# se050_nim APIガイド

この文書は、`se050_nim` のライブラリAPIを使う側向けのガイドです。

`se050_nim` は、SE050の低レベル primitive を扱うためのライブラリです。transport、APDU/TLV、UID、乱数、Secure Object、鍵生成、公開鍵読み出し、P-256 ECDH までを担当します。ファームウェア envelope、production provisioning policy、updater の処理は、このライブラリを `requires` / `import` する上位プロジェクト側に分離します。

## エントリポイント

通常はトップレベルモジュールだけを import します。

```nim
import se050_nim
```

トップレベルモジュールは、以下のサブモジュールを re-export します。

- `errors`
- `transport`
- `apdu`
- `tlv`
- `uid`
- `random`
- `objects`
- `keys`
- `management`

特定の機能だけを明示的に使いたい場合だけ、サブモジュールを直接 import します。

## Result形式

通常の SE050/APDU エラーでは例外を投げず、`SE[T]` を返します。

```nim
type SE[T] = object
  ok*: bool
  value*: T        # T が void でない場合
  error*: Se050Error
```

典型的な使い方は次の形です。

```nim
let r = se.readUidHex()
if not r.ok:
  echo r.error.errorMessage()
  quit 1

echo r.value
```

`Se050Error.sw` が 0 以外の場合は、`0x6985` のような APDU status word 由来のエラーです。

## デバイスを開く

```nim
let se = openSe050(bus = 0)
```

I2Cアドレスのデフォルトは `0x48` です。

```nim
let se = openSe050(bus = 0, address = 0x48'u8)
```

APDU/T=1 over I2C フレームを表示したい場合は `debug = true` を指定します。

```nim
let se = openSe050(bus = 0, debug = true)
```

多くの high-level helper は、デフォルトで `selectFirst = true` として SE050 applet を選択します。複数コマンドを連続実行する場合は、最初に `selectApplet()` して、以後は `selectFirst = false` にしても構いません。

```nim
let selected = se.selectApplet()
if not selected.ok:
  echo selected.error.errorMessage()
  quit 1

let uid = se.readUidHex(selectFirst = false)
```

## UID

```nim
let uid = se.readUidHex()
```

関連API:

- `readUidRaw(se, selectFirst = true): SE[array[Se050UidLength, uint8]]`
- `readUidHex(se, separator = "", selectFirst = true): SE[string]`
- `uidToHex(uid, separator = ""): string`

既知の UID Secure Object ID は以下です。

```nim
Se050UniqueIdObjectId = 0x7FFF0206'u32
```

## 乱数

```nim
let rnd = se.getRandomBytes(length = 32)
```

関連API:

- `getRandomBytes(se, length, selectFirst = true): SE[seq[uint8]]`
- `getRandomHex(se, length, separator = "", selectFirst = true): SE[string]`
- `Se050MaxRandomLength = 255`
- `bytesToHex(data, separator = ""): string`

現在の実装は1回のAPDUで乱数を取得するため、長さは 1..255 bytes です。

## version / applet feature

```nim
let info = se.getVersionInfo()
if info.ok:
  echo info.value.major, ".", info.value.minor, ".", info.value.patch
```

関連API:

- `getVersionInfo(se, selectFirst = true): SE[Se050VersionInfo]`
- `hasFeature(info, bit): bool`
- `featureName(bit): string`
- `knownFeatureBits(): seq[uint16]`

主な feature 定数:

- `ConfigEcdsaEcdhEcdhe`
- `ConfigEddsa`
- `ConfigDhMont`
- `ConfigAes`
- `ConfigFipsModeDisabled`

## Secure Object の確認

```nim
let exists = se.objectExists(0x30000100'u32)
```

関連API:

- `objectExists(se, objectId, selectFirst = true): SE[bool]`
- `readObjectType(se, objectId, selectFirst = true): SE[ObjectTypeInfo]`
- `readObjectSize(se, objectId, selectFirst = true): SE[uint32]`
- `readObjectIdListChunk(se, offset = 0, filter = SecureObjectTypeAll, selectFirst = true): SE[ObjectIdListChunk]`
- `listObjectIds(se, filter = SecureObjectTypeAll, selectFirst = true): SE[seq[uint32]]`
- `objectTypeName(objectType): string`
- `transientIndicatorName(value): string`

`deleteSecureObject` も export されていますが、これは生の primitive です。dev以外を消さない、といった安全ポリシーは CLI や provisioning tool 側で強制します。

## 鍵生成

```nim
let created = se.generateP256KeyPair(0x30000100'u32)
```

関連API:

- `generateEcKeyPair(se, objectId, curve, selectFirst = true): SE[void]`
- `generateP256KeyPair(se, objectId, selectFirst = true): SE[void]`
- `generateX25519KeyPair(se, objectId, selectFirst = true): SE[void]`
- `curveId(curve): uint8`
- `curveName(curve): string`
- `expectedKeyPairType(curve): uint8`

対応している curve enum:

- `ecCurveP256`
- `ecCurveX25519`

現在の鍵生成は開発用ポリシーを付与します。key agreement、公開鍵読み出し、開発中の上書き/再生成、削除を許可します。production向けの one-time/no-delete policy は、別の provisioning tool 側で扱います。

## 公開鍵読み出し

```nim
let pub = se.readPublicKey(0x30000100'u32)
```

関連API:

- `readPublicKey(se, objectId, selectFirst = true): SE[seq[uint8]]`

実機で確認した公開鍵サイズ:

- P-256: 65 bytes、非圧縮形式 `0x04 || X(32) || Y(32)`
- X25519: 32 bytes

## P-256 ECDH derive

```nim
let secret = se.deriveSharedSecret(
  objectId = 0x30000100'u32,
  peerPublicKey = peerPublicKeyBytes
)
```

関連API:

- `deriveSharedSecret(se, objectId, peerPublicKey, selectFirst = true): SE[seq[uint8]]`

ファームウェア envelope 用途では、SE050側の実用的な鍵共有方式として P-256 ECDH を使います。返ってくる 32-byte shared secret は、そのまま AES key にせず、上位の envelope ライブラリ側で HKDF に渡します。

X25519 は、鍵生成と公開鍵読み出しは動作確認できていますが、テストした applet 経路では derive が peer public key 形式を変えても `SW=0x6985` で失敗しました。別の applet/middleware 経路で成功が確認できるまでは、現在の製品経路では X25519 derive を非対応扱いにします。

## エラー表示

```nim
if r.isErr:
  echo r.error.errorMessage()
```

関連API:

- `isOk(r)`
- `isErr(r)`
- `errorMessage(e)`

## 推奨レイヤ構成

責務境界は次のように分けます。

```text
se050_nim:
  SE050 primitive 操作

se050ctl:
  開発・診断CLI

se050-provision / se050-kitting:
  production object作成とpolicy設定

fwkeys / fw-envelope:
  P-256 ECDH + HKDF + AES-GCM envelope処理

fw-update:
  ファームウェア検証、復号、適用、A/B切替
```
