# se050_nim

NXP SE050 セキュアエレメントを T=1 over I2C で扱うための軽量な Nim ライブラリ、診断用CLI、およびAttestation付きキッティングCSV生成ツールです。

NXP Plug & Trust Middlewareには依存せず、組み込みLinux製品から必要なSE050操作を直接実行します。現在は、低レベルprimitiveに加えて、NXP Attestation証明書の検証、キッティングrecord/CSV、オフライン検証、実機照合、およびX.509/mTLS向けTLS client identity管理までを提供します。実際のOpenSSL/TLS連携にはNXP公式`se05x-openssl-provider`を使用します。Firmware envelopeの形式、HKDF/AES-GCM処理、ファームウェア更新処理は上位プロジェクトの責務です。

## 現在の状態

実機のSE050 Applet 7.2.x経路で確認済みの主な機能は以下です。

- Object `0x7FFF0206`からのUID読出し
- Applet version/config読出し
- 乱数生成
- Secure Objectのexists/type/size/list/delete helper
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
- TLS identity鍵の`origin = internal`、Policy、公開鍵のAttestation検証
- NXP OpenSSL Provider 1.1.5から`nxp:0x...`で既存SE050鍵を直接参照
- SE050鍵によるPKCS#10 CSR生成とCSR自己署名検証
- CSR内公開鍵とSE050公開鍵のbyte-for-byte一致確認
- OpenSSL 3.5.6 + NXP Provider 1.1.5でTLS 1.2 / TLS 1.3 mTLS client authentication

Production用`0x20000100`の生成経路も実装済みですが、不可逆な実機試験はまだ完了していません。

Firmware envelope用の鍵共有本線は以下です。

```text
P-256 ECDH + HKDF-SHA256 + AES-256-GCM
```

X25519は、確認したApplet 7.2.0経路では鍵生成と公開鍵exportは成功しましたが、`ECDHGenerateSharedSecret`が一貫して`SW=0x6985`で失敗しました。そのため、現在の製品経路ではP-256を使用します。

## TLS client identity

TLS client identityはCloud固有名を持たず、汎用のP-256 client signing keyとして管理します。各identityはA/Bの2 slotを持ち、証明書・鍵rotationに使用できます。

```text
identity 0: slot A / slot B
identity 1: slot A / slot B
identity 2: slot A / slot B
...
```

Object IDは次の規則で固定します。

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
slotOffset: A=0, B=1
```

TLS鍵Policyは`SIGN + READ + DELETE` (`0x10240000`)です。秘密鍵はSE050内部で生成し、filesystemやCloudへexportしません。既存Objectのtype、origin、Policy、公開鍵はNXP Attestationで検証し、不整合時に自動削除・再生成は行いません。

主なCLI例:

```sh
se050ctl tls-keygen \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot A

se050ctl tls-key-info \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot A

se050ctl tls-key-ref \
  --profile test \
  --identity 0 \
  --slot A
```

`tls-key-ref`はNXP OpenSSL Providerから直接参照できる`nxp:0x30000200`形式のURIを返します。

実機では、SE050内部鍵をNXP OpenSSL Provider経由でOpenSSL 3から使用し、ECDSA署名、PKCS#10 CSR生成、CSR検証、TLS 1.2 / TLS 1.3の相互TLS client authenticationまで確認済みです。ローカルmTLS試験ではclient certificateなしの接続が拒否されることも確認しています。

AWS IoT Core / Azure IoT Hubについては、現行の公式X.509/mTLS仕様と今回のSE050構成を照合し、接続・provisioning手順を文書化済みです。実AWS/Azureアカウントを使用したCloud接続試験はこのrepositoryでは未実施です。

Host OSはtrusted environmentとして扱い、SE050とのdirect I2C通信にはPlain sessionを使用します。主目的はTLS private keyのnon-exportabilityであり、Host OS侵害後のSE050不正利用防止はこの設計のsecurity boundaryには含めません。

詳細:

- [`docs/openssl-provider.ja.md`](docs/openssl-provider.ja.md): NXP OpenSSL Provider連携
- [`docs/factory-identities.ja.md`](docs/factory-identities.ja.md): NXP factory-provisioned Cloud identity
- [`docs/local-mtls-test.ja.md`](docs/local-mtls-test.ja.md): ローカルmTLS統合試験
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

## `se050ctl`共通オプション

```text
-b, --bus <n>          I2C bus番号。例: 0は/dev/i2c-0
-a, --address <hex>    SE050 I2C address。default: 0x48
-d, --debug            T=1 over I2C frameを表示
```

主なコマンド:

```text
uid                 UID読出し
random              乱数生成
version             Applet version/config確認
exists/info/list    Secure Object確認
keygen/pubkey       開発用EC鍵生成・公開鍵読出し
tls-keygen           TLS client identity鍵生成・既存鍵検証
tls-key-info          TLS client identity鍵のAttestation付き情報表示
tls-key-ref           NXP OpenSSL Provider用`nxp:0x...` URI生成
tls-key-pubkey        TLS identity公開鍵のraw/SPKI DER出力
derive              P-256 ECDH
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

- transport/APDU/TLV、UID、乱数、Secure Object、鍵管理
- Attestation証明書読出し、ReadObject-with-Attestation
- OpenSSL 3によるSHA-256、ECDSA、X.509検証
- 組み込みNXP Trust Store
- 基板serial、キッティングprofile/record/CSV
- オフラインキッティング検証
- ローカル実機照合
- TLS identity profile / A/B slot / identity番号管理
- TLS identity Attestation semantic検証
- NXP OpenSSL Provider用Object URIとP-256 SPKI DER変換
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
