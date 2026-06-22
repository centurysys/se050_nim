# se050_nim

NXP SE050 セキュアエレメントを T=1 over I2C で扱うための軽量な Nim ライブラリと診断用 CLI です。

NXP Plug & Trust Middleware には依存せず、組み込み Linux 製品、ファームウェア envelope 実験、その上に作る production provisioning ツール向けの小さな SE050 primitive を提供する方針です。

## 現在の状態

現在の実機 SE050 applet 経路で確認済みの機能は以下です。

- Object `0x7FFF0206` からの UID 読み出し
- SE050 applet version/config 読み出し
- 乱数生成
- Secure Object の exists/type/size/list/delete helper
- 開発用 EC key generation
- EC key object からの public key 読み出し
- P-256 ECDH shared secret 導出

ファームウェア envelope 用の本線は以下です。

```text
P-256 ECDH + HKDF-SHA256 + AES-256-GCM
```

X25519 は、今回試した SE050 applet 7.2.0 環境では keygen と public key export は動きましたが、`ECDHGenerateSharedSecret` が一貫して `SW=0x6985` で失敗しました。同じ ECDH 系 APDU で P-256 は成功しているため、CLI では X25519 derive を未対応扱いにし、P-256 を本線にしています。

## CLI

インストールされるコマンドは以下です。

```sh
se050ctl
```

共通オプション:

```sh
-b, --bus <n>          I2C bus 番号。例: 0 は /dev/i2c-0
-a, --address <hex>    SE050 I2C address。default: 0x48
-d, --debug            T=1 over I2C frame を表示
```

### UID

```sh
se050ctl uid -b 0
se050ctl uid -b 0 --colon
```

### Version / feature bitmap

```sh
se050ctl version -b 0
```

### Random

```sh
se050ctl random -b 0 --len 32
se050ctl random -b 0 --len 32 --colon
```

### Secure Object 確認

object reference は次のいずれかで指定できます。

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

例:

```sh
se050ctl exists -b 0 --name uid
se050ctl info -b 0 --name uid
se050ctl list -b 0 --annotate
se050ctl list -b 0 --area dev --annotate
```

### 開発用 P-256 key agreement

`se050ctl keygen` の default は P-256 です。

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

sha256sum p256_secret_ab.bin p256_secret_ba.bin
cmp p256_secret_ab.bin p256_secret_ba.bin
```

期待する形:

- P-256 public key は 65 bytes の uncompressed point: `0x04 || X(32) || Y(32)`
- ECDH shared secret は 32 bytes
- A→B と B→A の shared secret が一致する

## `se050ctl` の Object ID 方針

`se050ctl` は production provisioning ツールではなく、開発・診断用 CLI です。作成・削除は dev range のみに制限します。

| Area | Range | `se050ctl` create/delete |
|---|---:|---|
| vendor | `0x10000000..0x10000FFF` | no |
| customer | `0x20000000..0x2000FFFF` | no |
| dev | `0x30000000..0x3000FFFF` | yes |
| nxp | `0x7FFF0000..0x7FFFFFFF` | no |
| internal | `0xF0000000..0xFFFFFFFF` | no |

production 用途では、将来的に次のように分ける想定です。

- `se050-provision`: production object 作成、no-delete policy 管理
- `fwkeys` / `fw-envelope`: manifest/envelope 処理
- `fw-update`: A/B firmware update application

## ライブラリ構成

```text
src/se050_nim.nim
src/se050_nim/apdu.nim
src/se050_nim/errors.nim
src/se050_nim/i2c.nim
src/se050_nim/keys.nim
src/se050_nim/management.nim
src/se050_nim/objects.nim
src/se050_nim/random.nim
src/se050_nim/tlv.nim
src/se050_nim/transport.nim
src/se050_nim/uid.nim
src/se050ctl.nim
```

library layer は低レベル primitive に留めます。製品ポリシー、ファームウェア package parsing、envelope format、署名ポリシー、A/B update logic はこの上の層に置く方針です。

## Build

```sh
nimble build
```

依存関係は小さく保ちます。

```nim
requires "nim >= 2.2.10"
requires "results >= 0.5.1"
requires "argparse >= 4.0.2"
```

`results` dependency は `>= 0.5.1` のままにしてください。`> 0.5.1` にすると、利用可能な version が `0.5.1` の環境で build できなくなります。

## License

MIT License
