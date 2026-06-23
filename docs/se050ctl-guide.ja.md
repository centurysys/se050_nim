# se050ctl ガイド

`se050ctl` は、`se050_nim` の開発・診断用CLIです。

このツールは SE050 の低レベル primitive 操作に閉じます。production provisioning、firmware envelope、firmware updater の処理は、`se050_nim` に依存する上位ツール側で実装します。

## 対象範囲

`se050ctl` が扱うもの:

- SE050疎通確認
- UID取得
- 乱数生成
- applet version / feature確認
- Secure Object の list / info / exists
- 開発用EC鍵ペア生成
- 公開鍵export
- 診断用P-256 shared secret derive
- 開発用object削除

`se050ctl` が扱わないもの:

- production用 one-time/no-delete provisioning
- customer/vendor object policy管理
- firmware envelope parse
- firmware復号・適用処理
- updater の A/B切替

## 共通オプション

多くのコマンドは以下を受け付けます。

```text
-b, --bus       I2C bus番号。例: 0 は /dev/i2c-0
-a, --address   SE050 I2Cアドレス。デフォルト 0x48
-d, --debug     T=1 over I2C フレームを表示
```

例:

```sh
./se050ctl uid -b 0
```

## Object参照形式

SE050 Secure Object を対象にするコマンドでは、以下のいずれか1つで object を指定します。

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

これらは同時指定できません。

`--area` 名:

- `vendor`
- `customer`
- `dev`
- `nxp`
- `internal`

`--index` は area の先頭からの相対indexです。通常は10進数、`0x` prefix付きなら16進数として扱います。

例:

```sh
./se050ctl info -b 0 --area dev --index 0x100
```

これは object ID `0x30000100` として解決されます。

## UID

Unique ID object を読みます。

```sh
./se050ctl uid -b 0
```

コロン区切り表示:

```sh
./se050ctl uid -b 0 --colon
```

既知object名 `uid` は、object系コマンドでも使えます。

```sh
./se050ctl info -b 0 --name uid
```

## 乱数

乱数を生成します。

```sh
./se050ctl random -b 0 --len 32
```

コロン区切り表示:

```sh
./se050ctl random -b 0 --len 32 --colon
```

対応長は 1..255 bytes です。

## Version

Applet version と feature bitmap を読みます。

```sh
./se050ctl version -b 0
```

出力には applet version、applet config、secure box version、`ECDSA_ECDH_ECDHE`、`DH_MONT`、`AES`、`FIPS_MODE_DISABLED` などの feature が含まれます。

## Exists

Object が存在するか確認します。

```sh
./se050ctl exists -b 0 --area dev --index 0x100
```

表示せず exit code だけを使う場合:

```sh
./se050ctl exists -b 0 --area dev --index 0x100 --quiet
```

## Info

Object type、persistent/transient、size を確認します。

```sh
./se050ctl info -b 0 --area dev --index 0x100
```

P-256 key pair の出力例:

```text
id: 0x30000100
ref: area:dev[0x00000100]
area: dev
exists: yes
type: 0x29 (EC_KEY_PAIR_NIST_P256)
transient: 0x01 (persistent)
size: 32
```

## List

見えている object ID を列挙します。

```sh
./se050ctl list -b 0
```

開発用objectだけ表示:

```sh
./se050ctl list -b 0 --area dev
```

area/name 注釈付き:

```sh
./se050ctl list -b 0 --annotate
```

SecureObjectType byte でfilter:

```sh
./se050ctl list -b 0 --filter 0x29
```

`0xFF` は全object typeを意味します。

## 鍵生成

開発用P-256 key pair を作ります。

```sh
./se050ctl keygen -b 0 --area dev --index 0x100
```

デフォルトcurveは P-256 です。

明示的にP-256を指定:

```sh
./se050ctl keygen -b 0 --area dev --index 0x100 --curve p256
```

診断用にX25519鍵生成も可能です。

```sh
./se050ctl keygen -b 0 --area dev --index 0x120 --curve x25519
```

ただし、テストした applet 経路では X25519 derive は `ECDHGenerateSharedSecret` が各種encodingで `SW=0x6985` を返したため、製品本線にはしません。

`se050ctl keygen` は `dev` range のみ許可します。vendor/customer range の production鍵は、専用provisioning toolで作成します。

## 公開鍵export

公開鍵のraw bytesをファイルへ書き出します。

```sh
./se050ctl pubkey -b 0 --area dev --index 0x100 --out p256_pub.bin
```

hexとして表示:

```sh
./se050ctl pubkey -b 0 --area dev --index 0x100
```

P-256 public key は 65-byte の非圧縮pointです。

```text
0x04 || X(32) || Y(32)
```

X25519 public key は 32 bytes です。

## P-256 derive

P-256 key pair を2つ作ります。

```sh
./se050ctl keygen -b 0 --area dev --index 0x110 --curve p256
./se050ctl keygen -b 0 --area dev --index 0x111 --curve p256

./se050ctl pubkey -b 0 --area dev --index 0x110 --out p256_a_pub.bin
./se050ctl pubkey -b 0 --area dev --index 0x111 --out p256_b_pub.bin
```

A秘密鍵 × B公開鍵:

```sh
./se050ctl derive -b 0 --area dev --index 0x110 \
  --peer-public p256_b_pub.bin \
  --out p256_secret_ab.bin
```

B秘密鍵 × A公開鍵:

```sh
./se050ctl derive -b 0 --area dev --index 0x111 \
  --peer-public p256_a_pub.bin \
  --out p256_secret_ba.bin
```

一致確認:

```sh
sha256sum p256_secret_ab.bin p256_secret_ba.bin
cmp p256_secret_ab.bin p256_secret_ba.bin
```

shared secret は 32 bytes です。上位の firmware envelope 側では、この値をそのまま AES key にせず、HKDF に渡します。

## Delete

開発用objectを削除します。

```sh
./se050ctl delete -b 0 --area dev --index 0x100
```

dev range 以外の削除は拒否します。このガードは意図的なものです。production object削除やproduction policy管理は、診断CLIに入れません。

## 推奨 smoke test

```sh
./se050ctl version -b 0
./se050ctl random -b 0 --len 32
./se050ctl list -b 0 --area dev --annotate

./se050ctl delete -b 0 --area dev --index 0x110 || true
./se050ctl delete -b 0 --area dev --index 0x111 || true

./se050ctl keygen -b 0 --area dev --index 0x110 --curve p256
./se050ctl keygen -b 0 --area dev --index 0x111 --curve p256

./se050ctl pubkey -b 0 --area dev --index 0x110 --out p256_a_pub.bin
./se050ctl pubkey -b 0 --area dev --index 0x111 --out p256_b_pub.bin

./se050ctl derive -b 0 --area dev --index 0x110 \
  --peer-public p256_b_pub.bin \
  --out p256_secret_ab.bin

./se050ctl derive -b 0 --area dev --index 0x111 \
  --peer-public p256_a_pub.bin \
  --out p256_secret_ba.bin

ls -l p256_a_pub.bin p256_b_pub.bin p256_secret_ab.bin p256_secret_ba.bin
sha256sum p256_secret_ab.bin p256_secret_ba.bin
cmp p256_secret_ab.bin p256_secret_ba.bin
```

期待サイズ:

- `p256_a_pub.bin`: 65 bytes
- `p256_b_pub.bin`: 65 bytes
- `p256_secret_ab.bin`: 32 bytes
- `p256_secret_ba.bin`: 32 bytes
