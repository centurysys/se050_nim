# NXP OpenSSL Provider連携

## 目的

`se050_nim` / `se050ctl`で管理するSE050 TLS client identityを、OpenSSL 3および通常のOpenSSL-backed applicationから使用するための境界をまとめます。

現在は2つの参照方法を使い分けます。

1. `nxp:0x...` URI: Providerを明示的に扱うdiagnostic/CLI向け
2. NXP Reference Key PEM: 普通の`keyFile`/`-key` filenameとして扱うtransparent application向け

P-256とP-384の双方について、Reference Key -> NXP Provider -> SE050 ECDSA署名、およびNim `std/net` TLS 1.2 / TLS 1.3 mTLSを実機確認済みです。

## 採用Provider

NXP公式 `se05x-openssl-provider` を使用します。`se050_nim`自体はNXP Plug & Trust Middlewareに依存せず、ProviderはOpenSSL runtime連携の境界としてのみ使用します。

Providerのnative/cross buildでは対象architecture用の`libsssProvider.so`を生成してください。OpenSSL 3からProviderをdynamic loadする構成では、Provider自身が`libcrypto.so.3`を解決できる必要があります。確認には次を使えます。

```sh
readelf -d /usr/local/lib/libsssProvider.so | grep NEEDED
ldd /usr/local/lib/libsssProvider.so
```

対象buildで`libcrypto.so.3`への依存が欠ける場合は、Provider targetを`crypto`へ明示linkする必要があります。

## I2C接続

Linux I2C portは`EX_SSS_BOOT_SSS_PORT`で指定します。

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
```

本プロジェクトではHost OSをtrusted environmentとして扱い、direct-I2CのPlain sessionを使用します。主目的はprivate keyのnon-exportabilityであり、Host OS侵害後のSE050不正利用防止は現在のsecurity boundaryには含めません。

## 1. Provider-native Object URI

`tls-key-ref`はSE050へアクセスせず、managed TLS slotのObject IDからProvider URIを生成します。

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
# nxp:0x30000200
```

これはProviderを明示的に扱うcommandで便利です。

```sh
printf 'provider test\n' > input.txt

openssl pkeyutl \
  --provider /usr/local/lib/libsssProvider.so \
  --provider default \
  -inkey nxp:0x30000200 \
  -sign \
  -rawin \
  -in input.txt \
  -out signature.der \
  -digest sha256
```

URIにはcurveやorigin情報が含まれないため、managed TLS identityとして使用する前には`tls-key-info`等でlive objectを検証してください。

## 2. Reference Key PEM

通常のapplicationへ透過的に渡す経路はReference Key PEMです。

NXP ProviderのEC Reference KeyはSEC1 `EC PRIVATE KEY`構造を使いますが、privateKey OCTET STRINGには実private scalarではなく、SE050 Object IDとProvider markerが格納されます。公開鍵とnamed-curve情報は通常のEC key metadataです。

`se050_nim`は次を生成できます。

- P-256: 32-byte reference field + `prime256v1`
- P-384: 48-byte reference field + `secp384r1`

Reference Keyには実private key materialを含みません。

### 内部生成P-256

```sh
se050ctl tls-key-ref-file \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot A \
  --out device.key
```

### 外部import済みP-384

```sh
se050ctl tls-key-ref-file \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot B \
  --curve p384 \
  --imported \
  --out device.key
```

export前に対象Objectの存在、type、persistence、Policy、Attestation certificate/signature、origin、live/attested public key一致を検証します。出力fileは0600で作成し、既存pathを上書きしません。

## 3. Provider autoload

Application側からProvider指定を消すため、NXP Providerとdefault Providerを`openssl.cnf`からautoloadします。

```ini
config_diagnostics = 1
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
nxp_prov = nxp_sect
default = default_sect

[nxp_sect]
identity = nxp_prov
module = /usr/local/lib/libsssProvider.so
activate = 1

[default_sect]
activate = 1
```

試験時は次のように指定できます。

```sh
export OPENSSL_CONF=/path/to/openssl.cnf
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
```

この状態では、通常のOpenSSL commandへReference Key filenameだけを渡せます。

```sh
openssl pkeyutl \
  -inkey device.key \
  -sign \
  -rawin \
  -in input.txt \
  -out signature.der \
  -digest sha384
```

## 4. 外部private key import

外部P-256/P-384 private keyを既存PKIからSE050へ移す場合は`tls-key-import`を使用します。

```sh
se050ctl tls-key-import \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot B \
  --curve p384 \
  --key client.key \
  --cert client.crt
```

private keyはunencrypted PEMまたはDERを受け付けます。処理順は次のとおりです。

```text
OpenSSLでprivate key decode
-> supported curve / key-pair整合性検証
-> X.509 certificate public keyとの一致検証
-> P-384の場合はcurve instantiation確認
-> managed slotが空であることを確認
-> sensitive WriteECKey
-> imported-origin Attestation検証
-> source/live public key一致確認
```

既存slotを上書きしません。private key bufferと一時APDU bufferはzeroizeし、sensitive transportのraw frameはdebugでもredactします。

## 5. P-384 curve state

`ReadECCurveList`が返すのは現在instantiateされているWeierstrass curveの状態で、silicon capabilityそのものではありません。

```sh
se050ctl curve-list -b 0
```

P-384が`not-set`の場合は、standard secp384r1 parameterを明示的にprovisionできます。

```sh
se050ctl curve-provision-p384 -b 0 --yes
```

これはpersistent global SE05x curve stateを変更します。Create後のparameter設定またはfinal verificationが失敗した場合はbest-effort DeleteECCurveでrollbackします。既にinstantiate済みなら変更しません。

## 6. 通常のNim `std/net` application

`tools/std_net_mtls_client.nim`にはSE050 APIもProvider APIもありません。

概念的には通常のNim TLS clientです。

```nim
let ctx = newContext(
  verifyMode = CVerifyPeer,
  certFile = certFile,
  keyFile = keyFile,
  caFile = caFile
)

socket.connect(host, Port(port))
ctx.wrapConnectedSocket(socket, handshakeAsClient, hostname = serverName)
```

`keyFile`へReference Key PEMを渡し、Providerは`openssl.cnf`からautoloadします。この経路でP-256/P-384のTLS 1.3およびTLS 1.2 mutual TLSを確認済みです。

## 7. Integration test

主なscript:

```text
tools/se050_reference_key_provider_test.sh
tools/se050_reference_key_autoload_test.sh
tools/se050_external_key_import_test.sh
tools/se050_external_p384_key_import_test.sh
tools/se050_std_net_mtls_test.sh
tools/se050_external_key_std_net_mtls_test.sh
tools/std_net_mtls_client.nim
```

`se050_external_key_std_net_mtls_test.sh --curve p256|p384`は空のtest TLS slotだけを対象に、software key生成 -> import -> Reference Key -> ordinary Nim `std/net` TLS 1.3/1.2 -> cleanupまで実行します。開始時に既存Objectがあれば削除せず停止します。

詳細は[`local-mtls-test.ja.md`](local-mtls-test.ja.md)を参照してください。
