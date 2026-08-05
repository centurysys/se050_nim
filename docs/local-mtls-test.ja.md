# SE050 TLS identity ローカルmTLS試験

## 目的

Cloud固有要素を入れる前に、SE050内のTLS client private keyがNXP OpenSSL Provider経由で**普通のOpenSSL-backed application**から使用できることをローカル環境だけで確認します。

現在の最終確認対象は`tools/std_net_mtls_client.nim`です。このprogramにはSE050 APIもNXP Provider APIもなく、通常のNim `std/net` `certFile` / `keyFile` / `caFile`だけを使用します。

## 確認済みmatrix

| TLS identity | Provisioning | TLS 1.3 | TLS 1.2 |
|---|---|:---:|:---:|
| P-256 | SE050 internal generation | OK | OK |
| P-256 | external import | OK | OK |
| P-384 | external import | OK | OK |

P-384 internal generationは現在のmanaged TLS CLIでは提供しません。`tls-keygen`はP-256専用です。

## 前提

- OpenSSL 3.x
- target architecture向けNXP `libsssProvider.so`
- `se050ctl`
- `EX_SSS_BOOT_SSS_PORT`でSE050へ接続可能
- `nim c -d:ssl`でbuildした`std_net_mtls_client`

例:

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
```

## 通常applicationの意味

`std_net_mtls_client.nim`は概念的に次だけを行います。

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

`keyFile`へNXP Reference Key PEMを渡し、Providerは`OPENSSL_CONF`からautoloadします。Application自身はSE050 Object ID、Provider URI、I2C bus/addressを知りません。

## 既存TLS identityのtransparent test

`tools/se050_std_net_mtls_test.sh`はSE050 Objectを作成・削除しません。指定identityを検証してReference Keyを生成し、一時CA/server/client certificateを作成してTLS 1.3とTLS 1.2を実行します。

内部生成P-256例:

```sh
./tools/se050_std_net_mtls_test.sh \
  --se050ctl ./bin/se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --profile test \
  --identity 0 \
  --slot A \
  --curve p256 \
  --client ./tools/std_net_mtls_client
```

外部import済みP-384例:

```sh
./tools/se050_std_net_mtls_test.sh \
  --se050ctl ./bin/se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --profile test \
  --identity 0 \
  --slot B \
  --curve p384 \
  --imported \
  --client ./tools/std_net_mtls_client
```

主な確認内容:

1. internal/imported originを含むlive TLS identity検証
2. P-256/P-384 Reference Key PEM export（0600）
3. live SE050 public keyをSPKI DERでexport
4. `openssl.cnf`からNXP/default Providerをautoload
5. Reference Keyを使ってclient CSRを作成
6. client certificate public keyとlive SE050 SPKIのbyte-for-byte一致
7. Nim `std/net` clientでTLS 1.3 mTLS
8. Nim `std/net` clientでTLS 1.2 mTLS

TLS 1.2ではclient identity curveに合わせ、P-256はECDSA/SHA-256 + `prime256v1`、P-384はECDSA/SHA-384 + `secp384r1`をserver側test constraintとして使用します。

## disposable external-import test

`tools/se050_external_key_std_net_mtls_test.sh`は、空であることを確認したtest TLS slotだけを対象に外部key importからtransparent TLSまで通します。

P-384例:

```sh
./tools/se050_external_key_std_net_mtls_test.sh \
  --se050ctl ./bin/se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --curve p384 \
  --identity 0 \
  --slot B \
  --bus 0 \
  --address 0x48 \
  --client ./tools/std_net_mtls_client
```

P-384では事前に`curve-list`を確認し、instantiateされていなければ停止します。このscript自身はpersistent global curve stateを変更しません。

処理は次のとおりです。

```text
empty test slot確認
-> disposable software P-256/P-384 key + certificate生成
-> tls-key-import
-> imported-origin validation
-> common std/net transparent mTLS test
-> test object cleanup
```

開始時にObjectが存在する場合は削除・上書きせず停止します。cleanup対象は開始時に空だったtest slotにこのscript自身が作成したObjectだけです。

## Provider境界だけを確認するtest

より低いlayerの確認には次があります。

```text
tools/se050_reference_key_provider_test.sh
tools/se050_reference_key_autoload_test.sh
tools/se050_external_key_import_test.sh
tools/se050_external_p384_key_import_test.sh
tools/se050_local_mtls_test.sh
```

これらはProvider URI、Reference Key、explicit/autoload Provider、OpenSSL CLIによる署名/mTLSなどを個別に切り分けるためのdiagnosticです。製品applicationのtransparent性を確認する最終testは`se050_std_net_mtls_test.sh`です。

## セキュリティ境界

- SE050 private scalarはfilesystemへexportしない
- Reference Key PEMはObject ID/Provider marker/public key/curve metadataだけを保持する
- external import時のprivate key bufferは処理後にzeroizeする
- sensitive WriteECKey transport frameはdebugでもraw表示しない
- Host OSはtrusted environmentとして扱い、Plain I2C sessionを使用する
- SCP03、Host authentication、複数process排他、Cloud policyはこのtestの対象外
