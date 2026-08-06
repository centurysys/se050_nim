# se050_nim

NXP SE050 セキュアエレメントを T=1 over I2C で扱うための軽量な Nim ライブラリ、診断用CLI、およびAttestation付きキッティングCSV生成ツールです。

NXP Plug & Trust Middlewareには依存せず、組み込みLinux製品から必要なSE050操作を直接実行します。現在は、低レベルprimitiveに加えて、NXP Attestation証明書の検証、キッティングrecord/CSV、オフライン検証、実機照合、およびX.509/mTLS向けTLS client identity管理までを提供します。実際のOpenSSL/TLS連携にはNXP公式`se05x-openssl-provider`を使用します。Firmware envelopeの形式、HKDF/AES-GCM処理、ファームウェア更新処理は上位プロジェクトの責務です。

## 現在の状態

実機のSE050 Applet 7.2.x経路で確認済みの主な機能は以下です。

- Object `0x7FFF0206`からのUID読出し
- Applet version/config読出し
- GlobalPlatform IDENTIFYによるSE050 product/OEF/platform情報の読出し
- 乱数生成
- Secure Objectのexists/type/size/list/delete helper
- `list --long`によるtype/persistence/size一覧と、policy許可範囲のgeneric Object read
- 開発用EC鍵生成と公開鍵読出し
- P-256 ECDH shared secret導出
- NXP事前搭載Attestation鍵・個体証明書の利用
- ReadObject-with-Attestationの取得とECDSA署名検証
- NXP Root/IntermediateまでのX.509証明書チェーン検証
- test用firmware KEX鍵`0x30000100`の生成・再利用
- Attestation付き複数機器CSVの生成、追記、再実行
- CSVのオフライン暗号学的検証
- CSVとローカル基板serial、SE050 UID、公開鍵の実機照合
- P-256 ECDSA/SHA-256署名
- TLS client identityの`identity N + A/B slot`管理
- SE050内部生成P-256 TLS identityのstrict Attestation検証（`origin = internal`）
- 外部P-256/P-384 private keyのPEM/DER parse、X.509 certificateとの公開鍵一致検証、空slotへのimport
- imported TLS identityのstrict Attestation検証（`origin = external`）
- P-384 curve instantiation状態の読出しと、standard secp384r1 parameterのtransactional provisioning
- P-256/P-384 NXP Reference Key DER/PEM生成（private scalarは含まない）
- Attestation検証済みTLS identityから0600・非上書きでReference Key PEMをexport
- sensitive key-import/ECDH transportのraw T=1 log redactionと一時buffer zeroization
- NXP OpenSSL ProviderによるP-256/P-384 Reference KeyからのSE050 ECDSA署名
- `openssl.cnf`からNXP/default Providerをautoloadし、普通のkey file APIからReference Keyを使用
- SE050固有コードを含まないNim `std/net` clientでP-256/P-384 TLS 1.2 / TLS 1.3 mTLS client authentication
- `EX_SSS_BOOT_SSS_PORT`によるdirect-I2C endpoint共通指定と、`status`によるread-only一括診断

Production用`0x20000100`のfirmware KEX生成経路も実装済みですが、不可逆な実機試験はまだ完了していません。

Firmware envelope用の鍵共有本線は以下です。

```text
P-256 ECDH + HKDF-SHA256 + AES-256-GCM
```

X25519は、確認したApplet 7.2.0経路では鍵生成と公開鍵exportは成功しましたが、`ECDHGenerateSharedSecret`が一貫して`SW=0x6985`で失敗しました。そのため、現在の製品経路ではP-256を使用します。

## TLS client identity

TLS client identityはCloud固有名を持たない汎用X.509/mTLS client signing keyとして管理します。各identityはA/Bの2 slotを持ち、証明書・鍵rotationに使用できます。

```text
identity 0: slot A / slot B
identity 1: slot A / slot B
identity 2: slot A / slot B
...
```

Object IDはcurveに依存せず、次の規則で固定します。

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
slotOffset: A=0, B=1
```

TLS鍵Policyは`SIGN + READ + DELETE` (`0x10240000`)です。Object IDだけではP-256/P-384を区別できないため、P-384を扱うAPI/CLIではcurveを明示します。

現在のprovisioning経路は次の2種類です。

- `tls-keygen`: SE050内部でP-256鍵を生成し、`origin = internal`を要求して検証
- `tls-key-import`: 外部のunencrypted P-256/P-384 private keyを、対応するX.509 certificateと照合した後で空slotへimportし、`origin = external`を要求して検証

外部importは既存Objectを上書きしません。private key/certificateのalgorithm・curve・公開鍵一致をhost側で先に検証し、書込み後はlive public key、Object type、persistence、Policy、Attestation originを再検証します。private key fileのbufferとWriteECKey用一時bufferはzeroizeし、debug時もsensitive T=1 frameはredactします。

P-384 importにはstandard NIST P-384 curveがSE05xへinstantiate済みである必要があります。状態確認と明示的provisioningは次のとおりです。

```sh
se050ctl curve-list -b 0
se050ctl curve-provision-p384 -b 0 --yes
```

`curve-provision-p384`はkey objectではなくpersistent global curve stateを変更するため、`--yes`なしでは実行しません。

P-256内部生成例:

```sh
se050ctl tls-keygen \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot A
```

外部P-384 import例:

```sh
se050ctl tls-key-import \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot B \
  --curve p384 \
  --key client.key \
  --cert client.crt

se050ctl tls-key-info \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot B \
  --curve p384 \
  --imported
```

NXP Provider固有のObject URIが必要な場合は従来どおり`tls-key-ref`を使えます。

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
# nxp:0x30000200
```

一方、**通常のOpenSSL/Nim TLS applicationへ透過的に渡す標準経路**はReference Key fileです。ApplicationはSE050やProvider URIを知らず、普通のprivate-key filenameとして扱います。

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

NXP Providerとdefault Providerを`openssl.cnf`からautoloadすれば、Nim側は通常の`std/net` APIだけで動作します。

```nim
let ctx = newContext(
  verifyMode = CVerifyPeer,
  certFile = certFile,
  keyFile = keyFile,
  caFile = caFile
)
```

P-256/P-384の双方について、TLS 1.3とTLS 1.2のmutual TLSをAthena実機で確認済みです。

AWS IoT Core / Azure IoT Hubについては既存documentを参照してください。Cloud側で許容されるcurve/algorithmはservice仕様に依存するため、P-384を使用する場合は各serviceの現行仕様を別途確認します。

Host OSはtrusted environmentとして扱い、SE050とのdirect I2C通信にはPlain sessionを使用します。主目的はTLS private keyのnon-exportabilityであり、Host OS侵害後のSE050不正利用防止はこの設計のsecurity boundaryには含めません。

詳細:

- [`docs/openssl-provider.ja.md`](docs/openssl-provider.ja.md): Provider URI、Reference Key、autoload、transparent TLS
- [`docs/local-mtls-test.ja.md`](docs/local-mtls-test.ja.md): P-256/P-384のローカルmTLS統合試験
- [`docs/se050ctl-guide.ja.md`](docs/se050ctl-guide.ja.md): endpoint、診断、Object read、import/curve/reference-key CLI
- [`docs/factory-identities.ja.md`](docs/factory-identities.ja.md): NXP factory-provisioned Cloud identity
- [`docs/aws-iot.ja.md`](docs/aws-iot.ja.md): AWS IoT Core接続手順
- [`docs/azure-iot.ja.md`](docs/azure-iot.ja.md): Azure IoT Hub接続手順

## NXP factory-provisioned Cloud identity

SE050 variantに事前搭載されているNXP Cloud connection credentialをread-onlyで利用できます。対応catalogはECC P-256およびRSA-2048のidentity 0/1で、実機に存在するObjectは`factory-list`で確認します。

```sh
se050ctl factory-list -b 0

se050ctl factory-cert \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --out device.crt

KEY_URI=$(se050ctl factory-key-ref --kind ecc --identity 0)
```

この経路では新規key generation、CSR、private-key fileが不要です。factory certificateをCloud側へ登録し、private keyはNXP OpenSSL Providerから`nxp:0x...` URIで参照できます。

自社PKI、rotation、複数service identityが必要な場合は、上記のmanaged TLS client identityを使用します。factory credentialのcertificate validity/revocation/Cloud受入可否は利用時に確認してください。

詳細は[`docs/factory-identities.ja.md`](docs/factory-identities.ja.md)を参照してください。

## 生成されるコマンド

`nimble build`で以下の2バイナリを生成します。

```text
bin/se050ctl
bin/se050-kitting-export
```

- `se050ctl`: 開発・診断、およびCSVと実機の照合
- `se050-kitting-export`: 工場・開発環境でAttestation付きCSVを生成

Exporterは、削除可能な`test`プロファイルと、削除・上書きできない`production`プロファイルを実装します。Production経路は不可逆なため、出荷しない評価個体での実機確認が完了するまではexperimentalとして扱います。

## キッティング

Exporterは`/proc/device-tree/board/serialno`から基板serialを取得し、SE050内のtest鍵を作成または再利用して、Attestation付きCSV recordを追加します。

```sh
se050-kitting-export test \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

Production鍵を作成する場合は、固定Object ID `0x20000100`へPolicy `0x04200000`で不可逆生成します。

```sh
se050-kitting-export production \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

`production`は既存Objectを削除・上書きしません。異なるtypeやPolicyのObjectが存在する場合は停止します。

同じ基板・同じ鍵で再実行すると、CSV行を重複追加せず次の状態になります。

```text
CSV record: already valid
```

生成したCSVを同じ実機で検証します。

```sh
se050ctl kitting-verify \
  -b 0 \
  --input /tmp/se050-kitting.csv \
  --profile test
```

NXP Attestation Root/Intermediate証明書は`staticRead()`でバイナリへ組み込まれているため、キッティングコマンドでは外部CAファイルを指定しません。

詳細は[`docs/kitting-guide.ja.md`](docs/kitting-guide.ja.md)を参照してください。

## SE050接続先と`se050ctl`共通オプション

普段使いではNXP Providerと同じ`EX_SSS_BOOT_SSS_PORT`を設定すると、各commandの`-b`指定を省略できます。`se050ctl`と`se050-kitting-export`のdirect-I2C接続で共通に使用します。

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
se050ctl status
se050ctl product-info
se050ctl list --long
```

対応する環境変数形式は`/dev/i2c-N[:0xADDR]`です。AccessManagerの`host:port`形式はdirect-I2C endpointではないため受け付けません。

接続先の優先順位は次のとおりです。

- `-b/--bus`を明示した場合、そのbusを使用し、addressは`-a/--address`またはdefault `0x48`を使用する。環境変数のaddressは混在させない。
- `-b/--bus`を省略した場合、busは`EX_SSS_BOOT_SSS_PORT`から取得する。addressは`-a/--address`、環境変数内のaddress、default `0x48`の順で選択する。
- busがCLIにも環境変数にも無い場合はエラーとする。

```text
-b, --bus <n>          I2C bus番号。未指定時はEX_SSS_BOOT_SSS_PORT
-a, --address <hex>    SE050 I2C address。default: 0x48
-d, --debug            T=1 over I2C frameを表示
```

主なコマンド:

```text
uid                     UID読出し
random                  乱数生成
version                 Applet version/config確認
product-info            OEF ID / product / platform / patch / ROM情報
status                  接続先・product・curve・factory/TLS identity一括診断
curve-list              Weierstrass curve instantiation状態読出し
curve-provision-p384    standard NIST P-384 curveの明示的provisioning
exists/info/list        Secure Object確認（list --longで詳細一覧）
read                    policyで許可されたSecure Objectのhex表示/raw file出力
keygen/pubkey           開発用EC鍵生成・公開鍵読出し
tls-keygen              内部生成P-256 TLS identity作成・検証
tls-key-import          外部P-256/P-384 TLS private key import
tls-key-info            internal/imported TLS identityのAttestation検証
tls-key-ref             NXP Provider用`nxp:0x...` URI生成
tls-key-ref-file        P-256/P-384 Reference Key PEM生成
tls-key-pubkey          TLS identity公開鍵のraw/SPKI DER出力
derive                  P-256 ECDH
attestation-cert    NXP個体証明書のDER出力
attest-read         ReadObject-with-Attestationの診断取得
attest-verify       外部CA指定によるライブAttestation診断
kitting-verify      組み込みCAによるCSV＋実機照合
delete              dev range objectの削除
```

CLIの詳細は[`docs/se050ctl-guide.ja.md`](docs/se050ctl-guide.ja.md)を参照してください。

## 開発用P-256 key agreement

```sh
se050ctl delete -b 0 --area dev --index 0x110 || true
se050ctl delete -b 0 --area dev --index 0x111 || true

se050ctl keygen -b 0 --area dev --index 0x110
se050ctl keygen -b 0 --area dev --index 0x111

se050ctl pubkey -b 0 --area dev --index 0x110 --out p256_a.bin
se050ctl pubkey -b 0 --area dev --index 0x111 --out p256_b.bin

se050ctl derive -b 0 --area dev --index 0x110 \
  --peer-public p256_b.bin \
  --out p256_secret_ab.bin

se050ctl derive -b 0 --area dev --index 0x111 \
  --peer-public p256_a.bin \
  --out p256_secret_ba.bin

cmp p256_secret_ab.bin p256_secret_ba.bin
```

P-256公開鍵は65 bytesの非圧縮point、ECDH shared secretは32 bytesです。

## Object IDとPolicy

| 用途 | Object ID | Policy header | 状態 |
|---|---:|---:|---|
| 汎用development鍵 | dev range | `0x043C0000` | `se050ctl keygen`で作成可能 |
| TLS identity test | `0x30000200 + identity * 2 + slotOffset` | `0x10240000` | identity 0/1で実機確認済み |
| TLS identity production | `0x20000200 + identity * 2 + slotOffset` | `0x10240000` | CLI/Policy実装済み。実Cloud接続未実施 |
| test firmware KEX | `0x30000100` | `0x04240000` | Exporterで実装・実機確認済み |
| production firmware KEX | `0x20000100` | `0x04200000` | Exporter実装済み。不可逆実機試験待ち |
| NXP Attestation key | `0xF0000012` | NXP provisioned | 読出し・検証で使用 |
| NXP device certificate | `0xF0000013` | NXP provisioned | 読出し・検証で使用 |

汎用`se050ctl keygen`で`0x30000100`を作るとPolicyが異なるため、Exporterは安全のため拒否します。Test領域であることを確認したうえで明示的に削除し、Exporterに正しいPolicyで再生成させます。

詳細は[`docs/object-ranges.ja.md`](docs/object-ranges.ja.md)を参照してください。

## ライブラリの責務

`src/se050_nim.nim`は以下の機能群をre-exportします。

- direct-I2C endpoint解決、transport/APDU/TLV、UID、乱数、Secure Object、鍵管理
- GlobalPlatform IDENTIFY parseと既知SE050 OEF/product mapping
- Attestation証明書読出し、ReadObject-with-Attestation
- OpenSSL 3によるSHA-256、ECDSA、X.509検証
- 組み込みNXP Trust Store
- 基板serial、キッティングprofile/record/CSV
- オフラインキッティング検証
- ローカル実機照合
- TLS identity profile / A/B slot / identity番号 / P-256・P-384 curve管理
- internal/imported originを分離したTLS identity Attestation semantic検証
- external EC private key parse、certificate match、P-256/P-384 managed import
- P-384 curve state query / standard parameter provisioning
- P-256/P-384 SPKI DER変換とNXP Reference Key DER/PEM生成
- private-key-style Reference Key fileのatomic/non-overwrite出力
- sensitive transport redactionとsecure memory clearing
- NXP OpenSSL Provider用Object URI
- NXP factory Cloud identity catalog、certificate/public key readout
- Exporter用CSV merge helper

Firmware envelope format、HKDF、AES-GCM、release CEK、ファームウェア署名検証、A/B更新はこのライブラリの範囲外です。

## Build / Runtime要件

```sh
nimble build
nimble test
```

Nim依存関係:

```nim
requires "nim >= 2.2.10"
requires "results >= 0.5.1"
requires "argparse >= 4.0.2"
```

`results`は`>= 0.5.1`のままにしてください。

組み込みTrust Storeとして、以下のDERファイルがソースツリーに必要です。

```text
src/se050_nim/certs/nxp-attestation-ecc-root.der
src/se050_nim/certs/nxp-attestation-ecc-intermediate.der
```

Attestation検証を実行するtargetにはOpenSSL 3の`libcrypto.so.3`が必要です。C headerやdevelopment symlinkは不要で、実行時に動的loadします。

TLS client identityをOpenSSL/TLSから利用する場合は、別途NXP公式`se05x-openssl-provider`の`libsssProvider.so`が必要です。`se050_nim`自体はNXP Plug & Trust Middlewareへ依存せず、ProviderはTLS runtime連携の境界としてのみ使用します。

## Documentation

- [`docs/se050ctl-guide.ja.md`](docs/se050ctl-guide.ja.md): CLI
- [`docs/api-guide.ja.md`](docs/api-guide.ja.md): library API
- [`docs/kitting-guide.ja.md`](docs/kitting-guide.ja.md): Attestation付きキッティング
- [`docs/object-ranges.ja.md`](docs/object-ranges.ja.md): Object ID/Policy
- [`docs/p256-ecdh.ja.md`](docs/p256-ecdh.ja.md): Envelope向けP-256 ECDH
- [`docs/openssl-provider.ja.md`](docs/openssl-provider.ja.md): NXP OpenSSL Provider連携
- [`docs/factory-identities.ja.md`](docs/factory-identities.ja.md): NXP factory-provisioned Cloud identity
- [`docs/local-mtls-test.ja.md`](docs/local-mtls-test.ja.md): ローカルTLS 1.2/1.3 mTLS統合試験
- [`docs/aws-iot.ja.md`](docs/aws-iot.ja.md): AWS IoT Core provisioning / 接続
- [`docs/azure-iot.ja.md`](docs/azure-iot.ja.md): Azure IoT Hub provisioning / 接続

## License

MIT License
