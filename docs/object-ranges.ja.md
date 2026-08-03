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
| production firmware KEX | `0x20000100` | P-256 key pair / customer | 生成CLI・汎用変更ガード実装済み、不可逆実機試験待ち |
| test TLS identity key0 A/B | `0x30000200..0x30000201` | P-256 key pair / dev | identity番号 + A/B slot、実機確認済み |
| test TLS identity key1 A/B | `0x30000202..0x30000203` | P-256 key pair / dev | 複数identity mapping実機確認済み |
| production TLS identity | `0x20000200..` | P-256 key pair / customer | identity番号 + A/B slot、生成はTLS専用CLIのみ |

Firmware KEXはtest/productionとも下位16-bit indexを`0x0100`に揃えます。TLS client identityは`0x0200`をbaseとし、`identity * 2 + slotOffset`でObject IDを割り当てます。test/productionでは同じ下位16-bit indexを使い、Object areaでライフサイクルを分離します。

## Production firmware KEX IDの予約ガード

`0x20000100`はproduction firmware KEX専用IDとして、アプリケーション側でも明示的に予約します。

`se050ctl`は一般的なrange判定より先に共通ガードを呼び出し、次の汎用変更操作を拒否します。

- create
- key generation
- write / overwrite
- delete

現在`se050ctl`に実装されている変更系コマンドでは、`keygen`と`delete`がこのガードを使用します。将来write/import系コマンドを追加する場合も同じガードを通します。

`info`、`exists`、`pubkey`、Attestationなどの読取り・検証操作は許可します。production Exporterは固定Object ID・固定Policyを検証したうえで、ライブラリのraw primitiveから専用経路で生成します。

このガードは誤操作防止であり、セキュリティ境界ではありません。独自APDUや別middlewareからの操作を防ぐものではなく、最終的な削除・上書き防止はSE050内に保存されるone-time Policyが担います。

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

| API /用途 | Header | SIGN | KA | READ | WRITE | GEN | DELETE |
|---|---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `developmentEcKeyPolicy()` | `0x043C0000` | no | yes | yes | yes | yes | yes |
| `developmentSigningEcKeyPolicy()` | `0x103C0000` | yes | no | yes | yes | yes | yes |
| TLS identity `keyPolicy()` | `0x10240000` | yes | no | yes | no | no | yes |
| `testDeviceKeyPolicy()` | `0x04240000` | no | yes | yes | no | no | yes |
| `deviceEcKeyPolicy()` | `0x04200000` | no | yes | yes | no | no | no |
| `oneTimeDeviceKeyPolicy()` | `0x04200000` | no | yes | yes | no | no | no |

`oneTimeDeviceKeyPolicy()`は現在`deviceEcKeyPolicy()`と同じ実効headerです。API名を分けることで、provisioning codeが不可逆な意図を明示し、将来Applet固有の属性を追加できるようにしています。

TLS identityはcertificate/key rotationを前提とするため、productionでもDELETEを許可します。一方、既存鍵のsilent overwrite/regenerateを防ぐためWRITE/GENは許可しません。testとproductionで同じPolicy semanticsを使い、Object ID area、identity番号、A/B slotでライフサイクルを分離します。

## TLS client identity profile

TLS client identityはCloud固有名を持たない汎用のX.509/mTLS client signing keyです。複数サービスで独立した鍵ペアを使えるよう、`identity`番号ごとにA/B slotを割り当てます。

Object IDは次式で決定します。

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
slotOffset: A=0, B=1
```

代表例:

| Profile | Identity | Slot | Object ID | Policy |
|---|---:|:---:|---:|---:|
| test | 0 | A | `0x30000200` | `0x10240000` |
| test | 0 | B | `0x30000201` | `0x10240000` |
| test | 1 | A | `0x30000202` | `0x10240000` |
| test | 1 | B | `0x30000203` | `0x10240000` |
| production | 0 | A | `0x20000200` | `0x10240000` |
| production | 0 | B | `0x20000201` | `0x10240000` |
| production | 1 | A | `0x20000202` | `0x10240000` |
| production | 1 | B | `0x20000203` | `0x10240000` |

`identity 0`は従来のA/B Object IDと互換です。`identity 1`以降は別サービスや別接続先向けの独立したTLS client identityとして利用できます。

Policyは全identity/slot共通で`SIGN + READ + DELETE`です。秘密鍵はSE050内部生成とし、READは公開鍵取得に使用します。各identityのA/B方式で新しいslotへ鍵・証明書を準備して接続確認後に切り替え、旧slotを削除・再利用できる設計です。

AWS IoT Core / Azure IoT Hub固有のendpoint、device/Thing ID、CSR登録、certificate登録、MQTT parameterはこのprofileには含めません。

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

```sh
se050-kitting-export production \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

`se050-kitting-export production`はこの固定ID・固定Policyだけを使用し、既存Objectを削除・上書きしません。不可逆な初回実機試験では、出荷しない評価個体を使って次を確認します。

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
| production TLS identity slot A/B | `customer` | `0x20000200..0x20000201` |
| test TLS identity slot A/B | `dev` | `0x30000200..0x30000201` |
| 製品metadata/version | `customer` | `0x20000010` |
| vendor管理object | `vendor` | `0x10000000..` |
| disposable diagnostic object | `dev` | `0x30000000..` |

Production mapは不可逆キッティング開始前に固定し、version管理します。
