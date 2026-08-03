# NXP OpenSSL Provider連携

## 目的

`se050_nim` / `se050ctl`で生成・検証したTLS client identity鍵を、OpenSSL 3からNXP公式 `se05x-openssl-provider` 経由で使用するための境界を定義する。

Cloud固有処理はここに含めない。まず既存SE050 ObjectをProviderから参照してECDSA署名できることを確認し、その後CSRとローカルmTLSへ進む。

## 採用Provider

NXP公式:

```text
https://github.com/NXPPlugNTrust/se05x-openssl-provider
```

2026-08時点の公式READMEではOpenSSL 3.x対応で、EC key generation、EC sign/verify、ECDH、CSR、TLS 1.2/1.3 client例が公開されている。

既存SE050鍵は次のURI形式で直接参照できる。

```text
nxp:0x12345678
```

そのため、`se050_nim`側でNXP reference-key PEM形式を独自生成しない。まずObject ID URI方式を標準経路とする。

## se050ctlとの対応

例:

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
```

出力:

```text
nxp:0x30000200
```

Object ID配置規則はTLS identity profileが一元管理するため、Cloud/application側でObject IDを再計算しない。

## Providerの取得とnative build

公式READMEの基本手順:

```sh
git clone --recurse-submodules https://github.com/NXPPlugNTrust/se05x-openssl-provider.git
cd se05x-openssl-provider
mkdir build
cd build
cmake ../
cmake -DPTMW_HostCrypto=OPENSSL .
cmake --build .
```

生成物はrepositoryの `bin/libsssProvider.so` にもcopyされる。`cmake --install .`を使用する場合は通常shared library directoryへinstallされる。

対象製品rootfs向けcross buildでは、上記にtoolchain file / sysrootを追加する。Provider本体に加えてsubmodule `simw_lib`も対象architecture向けにcompileされるため、host用binaryを流用しない。

## I2C接続

NXP Supportの現行案内ではLinux I2C portは環境変数 `EX_SSS_BOOT_SSS_PORT` で指定できる。

例:

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
```

この値は実機のbus/addressに合わせる。

本プロジェクトではHost OSをtrusted environmentとして扱い、TLS秘密鍵のnon-exportabilityを主なsecurity boundaryとする。そのためdirect-I2Cのplain sessionを採用する。Providerが表示する `Communication channel is Plain` / `Not recommended for production use` 警告はこの設計では想定内である。Host OS侵害後のSE050不正利用防止は対象外とし、SCP03 / Access Manager / Host authentication credentialは導入しない。

## Step 5実機確認

### 1. 既存TLS identityを確認

```sh
se050ctl tls-key-info -b 0 --profile test --identity 0 --slot A
```

Attestationまで成功している既存鍵を使う。Providerから新しい鍵を生成しない。

### 2. Provider URIを取得

```sh
KEY_URI=$(se050ctl tls-key-ref --profile test --identity 0 --slot A)
echo "$KEY_URI"
```

期待値:

```text
nxp:0x30000200
```

### 3. Provider load確認

Provider install先に応じてpathを変更する。

```sh
openssl list -providers \
  -provider /usr/local/lib/libsssProvider.so \
  -provider default
```

NXP Providerとdefault providerの双方がloadできることを確認する。

### 4. 既存SE050鍵でECDSA署名

```sh
printf 'se050 provider test\n' > provider-input.txt

openssl pkeyutl \
  --provider /usr/local/lib/libsssProvider.so \
  --provider default \
  -inkey "$KEY_URI" \
  -sign \
  -rawin \
  -in provider-input.txt \
  -out provider-signature.der \
  -digest sha256
```

ここで成功すれば、`se050_nim`が作った既存Object IDをNXP Providerが解決し、SE050でECDSA署名できたことになる。

default providerを先にloadする構成でNXP ECDSA implementationが選ばれない場合は、NXP公式READMEに従いproperty queryを追加する。

```text
?nxp_prov.signature.ecdsa=yes
```

## Step 5完了条件

- NXP Providerを対象architectureでbuildできる
- `libsssProvider.so`をOpenSSL 3がloadできる
- `EX_SSS_BOOT_SSS_PORT`で対象SE050へ接続できる
- `se050ctl tls-key-ref`の `nxp:0x...` URIをProviderが受け付ける
- Provider経由ECDSA signが既存TLS identity鍵で成功する
- Provider自身によるkey generationは行わず、Object lifecycleは引き続き`se050_nim`側が管理する

次Stepでは、この同じURIを `openssl req -new -key nxp:...` に渡してCSR生成・自己検証を行う。


## CSR生成と公開鍵一致確認

TLS identity鍵からCSRを生成するときも、reference-key PEMは不要です。
NXP ProviderのObject ID URIをそのまま`openssl req`へ渡します。

例としてtest / identity 0 / slot Aを使用します。

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
PROVIDER=/usr/local/lib/libsssProvider.so
KEY_URI=$(se050ctl tls-key-ref --profile test --identity 0 --slot A)

se050ctl tls-key-pubkey \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot A \
  --format spki-der \
  --out se050-public.der

openssl req -new \
  --provider "$PROVIDER" \
  --provider default \
  -key "$KEY_URI" \
  -subj "/CN=se050-local-test" \
  -out device.csr
```

CSR自身の署名を検証します。

```sh
openssl req -in device.csr -noout -verify
```

次にCSRのSubjectPublicKeyInfoをDERで取り出し、SE050からAttestation検証後に
exportした公開鍵とbyte-for-byteで比較します。

```sh
openssl req -in device.csr -pubkey -noout | \
  openssl pkey -pubin -outform DER -out csr-public.der

cmp se050-public.der csr-public.der
```

`cmp`が終了コード0なら、CSRへ格納された公開鍵は選択したSE050 TLS identity
Objectの公開鍵と一致しています。CSR生成時に秘密鍵ファイルは作成されません。

この確認はCloud非依存です。AWS IoT Core / Azure IoT HubへCSRや証明書を
登録する前に、SE050 + NXP Provider + OpenSSLの境界だけを独立して検証できます。
