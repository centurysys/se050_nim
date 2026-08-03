# se050ctlガイド

`se050ctl`は`se050_nim`の開発・診断CLIです。SE050 primitive、TLS client identity鍵、Attestation診断、キッティングCSVとローカル実機の照合を提供します。Firmware KEXのproduction鍵生成、firmware envelope、firmware updaterは扱いません。

## 対象範囲

扱うもの:

- UID、乱数、Applet version/config
- Secure Objectのexists/info/list
- dev rangeのEC鍵生成と削除
- identity番号 + A/B slotで管理するTLS client identity鍵生成・検証（test/production）
- 公開鍵export、P-256 ECDH derive
- NXP個体証明書のDER export
- ReadObject-with-Attestationのraw capture
- 外部CA指定によるライブAttestation診断
- 組み込みNXP CAによるキッティングCSV＋実機照合

扱わないもの:

- firmware KEX用production one-time/no-delete鍵生成
- customer/vendor objectの一般write/delete
- PC専用CSV検証CLI
- HKDF/AES-GCM envelope処理
- firmware復号・A/B更新

## 共通オプション

```text
-b, --bus       I2C bus番号。例: 0は/dev/i2c-0
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

## 基本コマンド

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

### Exists / Info / List

```sh
se050ctl exists -b 0 --area dev --index 0x100
se050ctl exists -b 0 --area dev --index 0x100 --quiet
se050ctl info -b 0 --area dev --index 0x100
se050ctl list -b 0 --area dev --annotate
se050ctl list -b 0 --filter 0x29
```

P-256 key pairの`info`例:

```text
id: 0x30000100
type: 0x29 (EC_KEY_PAIR_NIST_P256)
transient: 0x01 (persistent)
size: 32
```

## TLS client identity鍵

TLS client identityは任意Object IDを指定せず、固定profile / identity / slotだけを操作します。

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
slotOffset: A=0, B=1
```

例:

```text
identity 0 A  0x30000200
identity 0 B  0x30000201
identity 1 A  0x30000202
identity 1 B  0x30000203
```

Policyは全slot共通で`SIGN + READ + DELETE` (`0x10240000`)です。既存Objectは自動削除・上書きしません。

### `tls-key-ref`

NXP公式 `se05x-openssl-provider` が既存SE050鍵を参照するためのURIを表示します。SE050へアクセスしないため、`-b`は不要です。

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
# nxp:0x30000200

se050ctl tls-key-ref --profile production --identity 1 --slot B
# nxp:0x20000203
```

この出力はOpenSSL 3の `-key` / `-inkey` へそのまま渡せます。

```sh
KEY_URI=$(se050ctl tls-key-ref --profile test --identity 0 --slot A)
openssl pkeyutl --provider /usr/local/lib/libsssProvider.so --provider default \
  -inkey "$KEY_URI" -sign -rawin -in input.txt -out signature.der -digest sha256
```


### `tls-key-pubkey`

TLS identityをAttestation検証した後、公開鍵だけをファイルへ出力します。
CSR内公開鍵との比較には`spki-der`を使用します。

```sh
se050ctl tls-key-pubkey \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot A \
  --format spki-der \
  --out se050-public.der
```

`--format raw`ではSE050 ReadObjectの65-byte `0x04 || X || Y`をそのまま出力します。
`spki-der`ではOpenSSL CSRの公開鍵と直接比較できるX.509 SubjectPublicKeyInfo DERを出力します。

### `tls-keygen`

```sh
se050ctl tls-keygen -b 0 --profile test --identity 0 --slot A
se050ctl tls-keygen -b 0 --profile production --identity 0 --slot A
se050ctl tls-keygen -b 0 --profile production --identity 1 --slot B
```

対象slotが空ならSE050内部でP-256鍵を生成します。既存の場合は再生成せず、NXP Attestationを使って次を検証したうえで再利用します。

- live Object typeがP-256 key pair
- live ReadTypeでpersistent
- NXP個体証明書chain
- Attestation署名
- signed Object ID/type
- `origin = internal`
- signed Policy `0x10240000`
- live public keyとattested public keyの一致

生成直後の検証が失敗した場合も自動削除は行いません。既存Objectの検証に失敗した場合も置換しません。

### `tls-key-info`

```sh
se050ctl tls-key-info -b 0 --profile test --identity 0 --slot A
se050ctl tls-key-info -b 0 --profile production --identity 0 --slot A
se050ctl tls-key-info -b 0 --profile production --identity 1 --slot B
```

鍵を変更せず、`tls-keygen`と同じtrust/semantic検証を行ってprofile、identity、slot、Object ID、公開鍵、origin、Policyを表示します。`--identity`のdefaultは`0`です。

汎用`keygen`/`delete`は従来どおりcustomer rangeを拒否します。Production TLS slotへ書き込める経路はTLS専用commandに限定します。

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
