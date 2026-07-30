# SE050 Object Rangeとツール方針

この文書は、`se050ctl`とキッティングExporterが使用するObject ID、Policy、責務境界をまとめます。

## Object ID range

| Area | Range | `se050ctl` create/delete | 想定用途 |
|---|---|---:|---|
| `vendor` | `0x10000000..0x10000FFF` | 不可 | 管理されたvendor provisioning |
| `customer` | `0x20000000..0x2000FFFF` | 不可 | production製品object |
| `dev` | `0x30000000..0x3000FFFF` | 可 | 開発・診断・削除可能test |
| `nxp` | `0x7FFF0000..0x7FFFFFFF` | 不可 | NXP/pre-provisioned |
| `internal` | `0xF0000000..0xFFFFFFFF` | 不可 | NXP internal/platform object |

`se050ctl keygen`と`delete`はdev rangeだけを許可します。ライブラリのraw APIは上位provisioning toolからcustomer/vendor rangeを扱えるよう、同じ制限を内部では強制しません。

## 現在使用するObject

| Name / purpose | Object ID | Type/owner | 状態 |
|---|---:|---|---|
| `uid` | `0x7FFF0206` | NXP unique ID | 読出し確認済み |
| NXP Attestation key | `0xF0000012` | P-256 key pair / NXP | 事前搭載、署名検証に使用 |
| NXP device certificate | `0xF0000013` | BinaryFile / NXP | 事前搭載、X.509検証に使用 |
| test firmware KEX | `0x30000100` | P-256 key pair / dev | Exporter実装・実機確認済み |
| production firmware KEX | `0x20000100` | P-256 key pair / customer | Profile/API定義済み、生成CLI未実装 |

Testとproductionで下位16-bitのindexを`0x0100`に揃え、上位byteでprofileを見分けます。

## Object参照形式

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

例:

| Reference | Object ID |
|---|---:|
| `--area dev --index 0x100` | `0x30000100` |
| `--area customer --index 0x100` | `0x20000100` |
| `--name uid` | `0x7FFF0206` |

## EC key Policy

| API /用途 | Header | KA | READ | WRITE | GEN | DELETE |
|---|---:|:---:|:---:|:---:|:---:|:---:|
| `developmentEcKeyPolicy()` | `0x043C0000` | yes | yes | yes | yes | yes |
| `testDeviceKeyPolicy()` | `0x04240000` | yes | yes | no | no | yes |
| `deviceEcKeyPolicy()` | `0x04200000` | yes | yes | no | no | no |
| `oneTimeDeviceKeyPolicy()` | `0x04200000` | yes | yes | no | no | no |

`oneTimeDeviceKeyPolicy()`は現在`deviceEcKeyPolicy()`と同じ実効headerです。API名を分けることで、provisioning codeが不可逆な意図を明示し、将来Applet固有の属性を追加できるようにしています。

## Test kittingの安全性

`se050-kitting-export test`は`0x30000100`だけを対象にし、Policyを`0x04240000`へ固定します。

既存Objectがある場合は上書きしません。AttestationでObject ID、type、origin、size、Policy、公開鍵を検証し、正しいtest鍵なら再利用します。汎用development Policy `0x043C0000`の鍵が残っている場合は停止し、自動削除しません。

## Production kitting

Production profileは次の値を定義済みです。

```text
Object ID: 0x20000100
Curve: P-256
Policy: 0x04200000
```

ただし、現在の`se050-kitting-export`は`test`サブコマンドだけを実装しています。Production生成を追加する前に、出荷しない評価個体を使って次を確認する必要があります。

- 初回生成が成功する
- AttestationのPolicy/Origin/typeが一致する
- 電源再投入後も同じ鍵を再利用できる
- overwrite/regenerate/deleteが拒否される
- CSV生成失敗後でも既存鍵から再実行できる

不可逆Objectを診断CLIから作成・削除する経路は追加しません。

## NXP reserved objectの保護

`0x7FFF...`および`0xF000...`のNXP objectは、`se050ctl`のwrite/delete対象外です。Attestation鍵`0xF0000012`と証明書`0xF0000013`は読出し・検証だけに使用します。

## 将来の配置

| 用途 | Area | Object ID例 |
|---|---|---:|
| production firmware KEX private key | `customer` | `0x20000100` |
| 製品metadata/version | `customer` | `0x20000010` |
| vendor管理object | `vendor` | `0x10000000..` |
| disposable diagnostic object | `dev` | `0x30000000..` |

Production mapは不可逆キッティング開始前に固定し、version管理します。
