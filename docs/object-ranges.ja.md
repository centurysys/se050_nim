# SE050 Object Range とツール方針

この文書は、`se050ctl` が使う object ID namespace 方針と、診断CLIとproduction provisioning toolの責務分担をまとめたものです。

## Object ID range

`se050ctl` は Secure Object ID を以下の範囲に分類します。

| Area | Range | `se050ctl` 作成 | `se050ctl` 削除 | 想定所有者 |
| --- | --- | ---: | ---: | --- |
| `vendor` | `0x10000000..0x10000FFF` | 不可 | 不可 | 将来のvendor/provisioning tool |
| `customer` | `0x20000000..0x2000FFFF` | 不可 | 不可 | 将来の製品provisioning tool |
| `dev` | `0x30000000..0x3000FFFF` | 可 | 可 | 開発・診断用 |
| `nxp` | `0x7FFF0000..0x7FFFFFFF` | 不可 | 不可 | NXP/pre-provisioned object |
| `internal` | `0xF0000000..0xFFFFFFFF` | 不可 | 不可 | internal/platform object |

既知object:

| Name | Object ID | 備考 |
| --- | ---: | --- |
| `uid` | `0x7FFF0206` | SE050 unique ID object |

## なぜ `se050ctl` は `dev` だけを書き込むのか

`se050ctl` は開発・診断CLIです。そのため、作成・削除できるのは development object だけに制限します。これにより、実験中にproduction鍵を誤って破壊するリスクを減らします。

Production provisioning では、まったく別の性質が必要です。

- development range 以外への書き込み
- 最終production policyの適用
- one-time provisioning 的な扱い
- 必要に応じた削除不可設定
- 工場登録用recordの出力
- 再実行や途中失敗からの復旧

これらは、`se050-provision` や `se050-kitting` のような別ツールの責務です。

## Object参照形式

`se050ctl` は以下のいずれか1つで object を参照します。

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

`--area` と `--index` は、area base に相対indexを足して解決します。

例:

| Reference | Object ID |
| --- | ---: |
| `--area dev --index 0x100` | `0x30000100` |
| `--area customer --index 0x100` | `0x20000100` |
| `--name uid` | `0x7FFF0206` |

## 開発用key policy

`se050ctl keygen` で作る開発用EC key pair は、意図的に扱いやすい開発用policyを使います。

現在のpolicyで許可するもの:

- key agreement
- public key read
- 開発中の write/generate
- delete

これは診断には便利ですが、production policyではありません。

## ライブラリの自由度とCLIの安全性

`se050_nim` はライブラリであり、すべての製品フローを安全側に包むラッパーではありません。raw primitive は、呼び出し側が指定した object ID をそのまま受け取ります。`customer` / `vendor` range も扱える必要があります。上位の kitting/provisioning tool が、production object を意図的に書き込むためです。

一方で `se050ctl` は別です。`se050ctl` は製品に同梱される可能性がある診断CLIなので、write/delete系コマンドは development range に制限したままにします。ライブラリがraw操作を実行できるからといって、`se050ctl` にproduction policy用の近道を追加しないほうが安全です。

## Production policy は provisioning tool で扱う

将来のprovisioning toolでは、production policyを明示的に設計・レビューできるようにします。例:

- `customer` area に P-256 device key を作る
- key agreementを許可する
- provisioning中に必要であればpublic key exportを許可する
- provisioning完了後はdelete不可にする
- finalization後のwrite/overwriteを避ける
- 必要であればauthenticated sessionやplatform policyを使う

このため、ライブラリは `EcKeyPolicy` builder を提供します。

- `developmentEcKeyPolicy()` は scratch/dev key 用
- `deviceEcKeyPolicy()` は provision済みdevice key 用
- `oneTimeDeviceKeyPolicy()` は final one-time device key作成の意図を表すため
- `customEcKeyPolicy(header)` は raw policy header が必要なadvanced caller用

production操作でどのobject rangeとpolicyを許可するかは、`se050ctl` ではなく provisioning tool 側で判断します。

## 将来のproduction配置案

production配置の一例です。

| 用途 | Area | 例 | 備考 |
| --- | --- | ---: | --- |
| device P-256 ECDH private key | `customer` | `0x20000100` | firmware envelope keyを開くために使う |
| device metadata/version object | `customer` | `0x20000010` | 製品フローで必要なら使用 |
| factory/vendor reserved objects | `vendor` | `0x10000000..` | 管理されたprovisioning用 |
| diagnostic scratch objects | `dev` | `0x30000000..` | 削除・再作成してよい領域 |

正確なproduction mapは、キッティング開始前に固定し、provisioning project側でversion管理します。
