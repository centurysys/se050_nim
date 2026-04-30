# se050_nim

NXP SE050 セキュアエレメントを T=1 over I2C で扱うための軽量な Nim ライブラリです。

## 概要

`se050_nim` は以下を目的としています：

- 小さくシンプル
- 依存関係なし
- NXP Plug & Trust Middleware に依存しない

## 現在の機能

- T=1 over I2C 通信
- ATR 処理
- APDU 送受信
- UID 取得（Object ID: `0x7FFF0206`）
- CLIツール（`se050_uid`）

## 使用例

```
import se050_nim

let se = openSe050(0)

discard se.requestAtr()

let uid = se.readUidHex()
echo uid.get()
```

## CLIツール

```
se050_uid -b 0
se050_uid -b 0 --colon
se050_uid -b 0 -d
```

## 設計

```
transport (T=1 over I2C)
  ↓
APDU
  ↓
上位モジュール（uid、将来: object, crypto）
```

I2C層は内部実装として隠蔽されています。

## 今後の拡張

近い将来：

- ReadObject / WriteObject
- 乱数生成
- ECC鍵生成
- 署名（ECDSA）
- 公開鍵取得
- セキュアストレージ操作

さらに：

- デバイス認証
- クラウド連携（Azure / AWS）
- セキュアブート / ファームウェア検証

## 方針

- シンプルに保つ
- 重いミドルウェアに依存しない
- 組み込みLinux用途に最適化
- 部品として使えるライブラリ

## ライセンス

MIT License
