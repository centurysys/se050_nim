# se050ctlガイド

`se050ctl`は`se050_nim`の開発・診断CLIです。SE050 primitive、TLS client identity鍵、Attestation診断、キッティングCSVとローカル実機の照合を提供します。Firmware KEXのproduction鍵生成、firmware envelope、firmware updaterは扱いません。

## 対象範囲

扱うもの:

- UID、乱数、Applet version/config、product/OEF/platform情報
- Secure Objectのexists/info/list、詳細一覧、policy許可範囲のgeneric read
- dev rangeのEC鍵生成と削除
- identity番号 + A/B slotで管理するTLS client identity（内部生成P-256、外部import P-256/P-384）
- EC curve state確認/P-384 provisioning、TLS公開鍵/Reference Key export、P-256 ECDH derive
- NXP個体証明書のDER export
- ReadObject-with-Attestationのraw capture
- 外部CA指定によるライブAttestation診断
- 組み込みNXP CAによるキッティングCSV＋実機照合
- endpoint/product/curve/factory/TLS identityのread-only status表示

扱わないもの:

- firmware KEX用production one-time/no-delete鍵生成
- customer/vendor objectの一般write/delete
- PC専用CSV検証CLI
- HKDF/AES-GCM envelope処理
- firmware復号・A/B更新

## 接続先と共通オプション

通常はNXP Providerと同じ環境変数を設定しておくと、各commandで`-b 0`を繰り返す必要がありません。

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
se050ctl status
```

`se050ctl`と`se050-kitting-export`が受け付ける環境変数形式は`/dev/i2c-N[:0xADDR]`です。AccessManager用の`127.0.0.1:8040`のような`host:port`形式はdirect-I2C endpointではないためrejectします。

解決規則:

1. `-b/--bus`を明示した場合はそのbusを使用する。この場合、環境変数内のaddressは継承せず、`-a/--address`またはdefault `0x48`を使う。
2. `-b/--bus`を省略した場合、busを`EX_SSS_BOOT_SSS_PORT`から取得する。addressは`-a/--address`、環境変数内address、default `0x48`の順。
3. busがCLIにも環境変数にも無い場合はエラー。

```text
-b, --bus       I2C bus番号。未指定時はEX_SSS_BOOT_SSS_PORT
-a, --address   SE050 I2C address。default: 0x48
-d, --debug     T=1 over I2C frameを表示
```

## Object参照

Objectを対象とするコマンドでは、次のいずれか1つを使用します。

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

Areaは`vendor`、`customer`、`dev`、`nxp`、`internal`です。

## 基本・診断コマンド

### UID

```sh
se050ctl uid -b 0
se050ctl uid -b 0 --colon
```

### Random

```sh
se050ctl random -b 0 --len 32
se050ctl random -b 0 --len 32 --colon
```

長さは1..255 bytesです。

### Version

```sh
se050ctl version -b 0
```

Applet version/config、secure box version、feature bitmapを表示します。

### `product-info`

GlobalPlatform IDENTIFY dataとApplet情報を使い、実装されているSE050 variantを実機から識別します。

```sh
se050ctl product-info
```

主な表示項目はproduct名、OEF ID、Configuration ID、Applet version/config、Patch ID、JCOP Platform ID、Platform Build ID、FIPS mode、pre-perso state、ROM IDです。既知OEF IDはproduct名へmappingし、未知IDは推測せず`unknown`としてOEF IDをそのまま表示します。

AthenaのSE050E2実機例では`product: SE050E2`、`OEF ID: 0xA921`を確認済みです。

### `status`

接続中の個体について、普段の診断で必要な情報をread-onlyでまとめて表示します。

```sh
se050ctl status
```

表示対象はendpoint、product/OEF、Applet、UID、P-256/P-384/P-521 curve state、factory ECC/RSA identity、Attestation identity、現在存在するmanaged TLS identityです。variantで未対応のRSAは`unsupported by applet`のように区別します。

追加診断の一部がpolicy等で取得できない場合は`unavailable`として可能な範囲の診断を継続します。基本的なdevice identification自体が失敗した場合はcommandを失敗させます。

### Exists / Info / List

```sh
se050ctl exists -b 0 --area dev --index 0x100
se050ctl exists -b 0 --area dev --index 0x100 --quiet
se050ctl info -b 0 --area dev --index 0x100
se050ctl list -b 0 --area dev --annotate
se050ctl list -b 0 --filter 0x29
se050ctl list --long
```

通常の`list`はObject IDだけを軽量に列挙します。`-l/--long`を指定すると各Objectへ追加問い合わせを行い、type、persistent/transient、sizeも表示します。`ReadIDList`には現れるものの`ALLOW_READ` policy等で`ReadType`を拒否するObjectは、`unavailable(SW=...)`として一覧を継続します。I2C/T=1/protocol errorは隠しません。

P-256 key pairの`info`例:

```text
id: 0x30000100
type: 0x29 (EC_KEY_PAIR_NIST_P256)
transient: 0x01 (persistent)
size: 32
```

### `read`

policyで読出しを許可されたSecure Objectをgenericに取得します。端末へraw binaryを直接流さないため、`--out`なしでは16-byte単位のhex dumpを表示します。

```sh
se050ctl read --id 0xF0000013
se050ctl read --id 0xF0000013 --out /tmp/object.bin
```

`--out`指定時はraw bytesをfileへ保存します。`BINARY_FILE`は既存のchunked read pathを使用し、それ以外は通常のReadObject pathを使用します。対象Objectがpolicyでreadを拒否した場合、このcommandはそのObjectを明示指定しているためエラーになります。generic writeは提供しません。

## NXP factory-provisioned Cloud identity

SE050 variantにNXP factory Cloud credentialが存在する場合、read-onlyでcertificateとProvider key URIを取得できます。

まず搭載Objectを確認します。

```sh
se050ctl factory-list -b 0
```

ECC identity 0のcertificateをPEMで取得:

```sh
se050ctl factory-cert \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --format pem \
  --out device.crt
```

Provider URIだけをstdoutへ出力:

```sh
se050ctl factory-key-ref --kind ecc --identity 0
```

certificateのSubjectPublicKeyInfoを取得:

```sh
se050ctl factory-pubkey \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --format pem \
  --out device-public.pem
```

`--kind`は`ecc`または`rsa`、`--identity`は`0`または`1`です。factory Objectはvariantによって存在しない場合があります。このcommand群はfactory Objectを生成、上書き、削除しません。

詳細は[`factory-identities.ja.md`](factory-identities.ja.md)を参照してください。

## EC curve state

SE05xのWeierstrass curve instantiation状態をread-onlyで確認できます。

```sh
se050ctl curve-list -b 0
```

表示される`set` / `not-set`は現在のSE05x global curve stateであり、silicon capabilityそのものではありません。

P-384が`not-set`で、対象製品でP-384を使用する場合はstandard secp384r1 parameterを明示的にprovisionできます。

```sh
se050ctl curve-provision-p384 -b 0 --yes
```

`--yes`は必須です。このcommandはdisposable key objectではなくpersistent global curve stateを変更します。既にP-384がsetならno-opです。Create後のparameter設定またはfinal state確認に失敗した場合はbest-effort rollbackを行います。

## TLS client identity鍵

TLS client identityは任意Object IDを指定せず、固定`profile / identity / slot / curve`で操作します。Object IDはcurveをencodeしません。

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
slotOffset: A=0, B=1
```

Policyは全slot共通で`SIGN + READ + DELETE` (`0x10240000`)です。既存Objectは自動削除・上書きしません。

現在のmanaged curveはP-256/P-384です。ただし**内部生成の`tls-keygen`はP-256専用**で、P-384はexternal import経路で使用します。

### `tls-keygen`

SE050内部でP-256 key pairを生成、または既存P-256 identityをstrict validationします。

```sh
se050ctl tls-keygen -b 0 --profile test --identity 0 --slot A
```

検証条件にはP-256 key-pair type、persistent、NXP Attestation chain/signature、`origin = internal`、Policy `0x10240000`、live/attested public key一致が含まれます。既存Objectが不整合でも置換しません。

### `tls-key-import`

外部のunencrypted EC private keyを空のmanaged slotへimportします。

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

`--curve`は`p256`または`p384`、defaultは`p256`です。private keyはunencrypted PEM/DER、certificateはPEM/DERを受け付けます。

SE050書込み前にprivate keyのalgorithm/curve/key-pair整合性とcertificate public key一致をOpenSSL 3で検証します。P-384ではcurveがinstantiate済みであることも確認します。対象slotが既に存在する場合は拒否します。

書込み後は`origin = external`、Object type/size、persistent、Policy、Attestation、live/source public key一致を確認します。import用private materialはsensitive transportで送信し、一時bufferをzeroizeします。

### `tls-key-info`

内部生成P-256:

```sh
se050ctl tls-key-info -b 0 --profile test --identity 0 --slot A
```

import済みP-384:

```sh
se050ctl tls-key-info \
  -b 0 \
  --profile test --identity 0 --slot B \
  --curve p384 --imported
```

`--imported`なしでは`origin = internal`を要求し、`--imported`では`origin = external`を要求します。originを自動判定してvalidationを緩めることはしません。

### `tls-key-pubkey`

Attestation検証済みTLS identityの公開鍵をrawまたはSPKI DERで出力します。

```sh
se050ctl tls-key-pubkey \
  -b 0 \
  --profile test --identity 0 --slot B \
  --curve p384 --imported \
  --format spki-der \
  --out se050-public.der
```

raw pointはP-256が65 bytes、P-384が97 bytesです。SPKI DERはP-256/P-384双方に対応します。

### `tls-key-ref`

NXP Provider-native Object URIをstdoutへ出します。SE050へアクセスしないため`-b`は不要です。

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
# nxp:0x30000200
```

Providerを明示的に操作するdiagnosticには便利ですが、通常applicationへのtransparent key-file連携には次の`tls-key-ref-file`を使用します。

### `tls-key-ref-file`

Attestation検証済みTLS identityからNXP Reference Key PEMを作成します。

内部生成P-256:

```sh
se050ctl tls-key-ref-file \
  -b 0 --profile test --identity 0 --slot A \
  --out device.key
```

import済みP-384:

```sh
se050ctl tls-key-ref-file \
  -b 0 --profile test --identity 0 --slot B \
  --curve p384 --imported \
  --out device.key
```

Reference Keyには実private scalarを含みません。出力はprivate-key-styleの0600でatomicにinstallし、既存pathを上書きしません。

NXP/default Providerを`openssl.cnf`からautoloadすると、通常のOpenSSL/Nim applicationはこのfileを普通の`keyFile`として扱えます。

## 開発用EC鍵

### Keygen

```sh
se050ctl keygen -b 0 --area dev --index 0x120 --curve p256
se050ctl keygen -b 0 --area dev --index 0x121 --curve x25519
```

Default curveはP-256です。`se050ctl keygen`はdev rangeだけを許可し、汎用development Policy `0x043C0000`を使用します。このPolicyで作った`0x30000100`はキッティングtest Policyと異なるため、Exporterに拒否されます。

### Public key

```sh
se050ctl pubkey -b 0 --area dev --index 0x120 --out p256_pub.bin
se050ctl pubkey -b 0 --area dev --index 0x120 --colon
```

P-256は65-byte `0x04 || X || Y`、X25519は32 bytesです。

### P-256 derive

```sh
se050ctl derive -b 0 --area dev --index 0x120 \
  --peer-public peer_p256.bin \
  --out shared_secret.bin
```

Peer P-256公開鍵は65 bytes、shared secretは32 bytesです。X25519 deriveは確認したApplet 7.2.0経路で`SW=0x6985`となるため拒否します。

### Delete

```sh
se050ctl delete -b 0 --area dev --index 0x120
```

Dev range以外は拒否します。

## Attestationコマンド

### `attestation-cert`

NXP事前搭載の個体証明書`0xF0000013`をDERで保存します。

```sh
se050ctl attestation-cert \
  -b 0 \
  --out se050-attestation-cert.der
```

個体によってBinaryFileの末尾がゼロ埋めされる場合があります。コマンドはDER SEQUENCE本体だけを出力し、非ゼロの余剰データは拒否します。

### `attest-read`

ReadObject-with-Attestationのrawデータを診断用に保存します。署名検証は行いません。

```sh
se050ctl attest-read \
  -b 0 \
  --id 0x30000100 \
  --freshness 000102030405060708090A0B0C0D0E0F \
  --out-prefix /tmp/attest
```

生成物:

```text
/tmp/attest.command.bin
/tmp/attest.transmit-apdu.bin
/tmp/attest.response.bin
/tmp/attest.signature.bin
/tmp/attest.object.bin
```

### `attest-verify`

ライブAttestationを外部CAファイルで診断検証します。対象は設定済みキッティングObject IDだけです。

```sh
se050ctl attest-verify \
  -b 0 \
  --id 0x30000100 \
  --freshness 000102030405060708090A0B0C0D0E0F \
  --trust-anchors nxp-attestation-ecc-root.der \
  --intermediates nxp-attestation-ecc-intermediate.der
```

確認するもの:

- 個体証明書chain
- 証明書公開鍵と`0xF0000012`公開鍵の一致
- Attestation ECDSA署名
- Object ID/type/origin/size/Policy

外部CA指定を残しているのは診断・CA更新調査のためです。通常のキッティング検証では組み込みTrust Storeを使用します。

## `kitting-verify`

Multi-device CSVからこの基板のrecordを選び、オフライン検証後に実機と照合します。

```sh
se050ctl kitting-verify \
  -b 0 \
  --input /tmp/se050-kitting.csv \
  --profile test
```

検証内容:

- CSV構造とmetadata-bound freshness
- 組み込みNXP Root/Intermediateまでの証明書chain
- Attestation署名とsigned object semantics
- `/proc/device-tree/board/serialno`
- live SE050 UID
- live Object type/persistence
- live public key

`--profile`のdefaultは`production`です。現在の`se050-kitting-export test`で作ったCSVには`--profile test`を明示してください。

成功時の最後は次のようになります。

```text
certificate trust chain: valid
attestation signature: valid
local board serial: match
local SE050 UID: match
local public key: match
kitting record: valid
```

## 推奨test kitting smoke test

```sh
se050-kitting-export test -b 0 --append /tmp/se050-kitting.csv
se050-kitting-export test -b 0 --append /tmp/se050-kitting.csv
se050ctl kitting-verify -b 0 \
  --input /tmp/se050-kitting.csv \
  --profile test
```

1回目は`CSV record: added`、2回目は`CSV record: already valid`を期待します。

詳細は[`kitting-guide.ja.md`](kitting-guide.ja.md)を参照してください。
