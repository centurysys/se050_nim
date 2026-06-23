# se050_nim サンプルコード

この文書は、`se050_nim` をライブラリとして使うための短いサンプル集です。

サンプルは意図的に primitive layer に留めます。Production provisioning、firmware envelope、updater の処理は別プロジェクト側で扱います。

## UIDを読む

```nim
import se050_nim

proc main() =
  let se = openSe050(bus = 0)

  let uid = se.readUidHex()
  if not uid.ok:
    echo "readUidHex failed: ", uid.error.errorMessage()
    quit 1

  echo uid.value

when isMainModule:
  main()
```

## 乱数を生成する

```nim
import se050_nim

proc main() =
  let se = openSe050(bus = 0)

  let rnd = se.getRandomHex(length = 32)
  if not rnd.ok:
    echo "getRandomHex failed: ", rnd.error.errorMessage()
    quit 1

  echo rnd.value

when isMainModule:
  main()
```

## Version と feature を表示する

```nim
import std/strutils

import se050_nim

proc main() =
  let se = openSe050(bus = 0)

  let info = se.getVersionInfo()
  if not info.ok:
    echo "getVersionInfo failed: ", info.error.errorMessage()
    quit 1

  echo "applet version: ", info.value.major, ".", info.value.minor, ".", info.value.patch
  echo "applet config : 0x", info.value.appletConfig.toHex(4)
  echo "secure box    : ", info.value.secureBoxMajor, ".", info.value.secureBoxMinor

  for bit in knownFeatureBits():
    let yesNo = if info.value.hasFeature(bit): "yes" else: "no"
    echo featureName(bit), ": ", yesNo

when isMainModule:
  main()
```

## 開発用P-256鍵を作って公開鍵を読む

```nim
import std/strutils

import se050_nim

const DevKeyId = 0x30000100'u32

proc main() =
  let se = openSe050(bus = 0)

  let created = se.generateP256KeyPair(DevKeyId)
  if not created.ok:
    echo "generateP256KeyPair failed: ", created.error.errorMessage()
    quit 1

  let typ = se.readObjectType(DevKeyId)
  if not typ.ok:
    echo "readObjectType failed: ", typ.error.errorMessage()
    quit 1

  echo "type: 0x", typ.value.objectType.toHex(2), " (", objectTypeName(typ.value.objectType), ")"

  let pub = se.readPublicKey(DevKeyId)
  if not pub.ok:
    echo "readPublicKey failed: ", pub.error.errorMessage()
    quit 1

  echo "public key length: ", pub.value.len
  echo bytesToHex(pub.value)

when isMainModule:
  main()
```

## 開発用P-256鍵2組でderiveする

```nim
import se050_nim

const
  KeyA = 0x30000110'u32
  KeyB = 0x30000111'u32

proc requireOk[T](r: SE[T], label: string): T =
  if not r.ok:
    echo label, " failed: ", r.error.errorMessage()
    quit 1
  result = r.value

proc requireOk(r: SE[void], label: string) =
  if not r.ok:
    echo label, " failed: ", r.error.errorMessage()
    quit 1

proc main() =
  let se = openSe050(bus = 0)

  requireOk(se.generateP256KeyPair(KeyA), "generate key A")
  requireOk(se.generateP256KeyPair(KeyB), "generate key B")

  let pubA = requireOk(se.readPublicKey(KeyA), "read public key A")
  let pubB = requireOk(se.readPublicKey(KeyB), "read public key B")

  if pubA.len != 65 or pubA[0] != 0x04'u8:
    echo "unexpected P-256 public key A format"
    quit 1
  if pubB.len != 65 or pubB[0] != 0x04'u8:
    echo "unexpected P-256 public key B format"
    quit 1

  let secretAB = requireOk(se.deriveSharedSecret(KeyA, pubB), "derive A x B")
  let secretBA = requireOk(se.deriveSharedSecret(KeyB, pubA), "derive B x A")

  if secretAB != secretBA:
    echo "shared secrets do not match"
    quit 1

  echo "shared secret length: ", secretAB.len
  echo bytesToHex(secretAB)

when isMainModule:
  main()
```

## エラー処理パターン

CLIツールでは、APDU status word をログに残します。Applet が返してくれる唯一の手がかりになることがあります。

```nim
import std/strutils

let r = se.deriveSharedSecret(keyId, peerPublicKey)
if not r.ok:
  stderr.writeLine "derive failed: " & r.error.errorMessage()
  if r.error.sw != 0:
    stderr.writeLine "SW=0x" & r.error.sw.toHex(4)
  quit 1
```

## 今後の実ファイル例

実際の `examples/` に置くなら、次のような短いファイルがよいです。

```text
examples/read_uid.nim
examples/random_bytes.nim
examples/version_info.nim
examples/p256_keygen_pubkey.nim
examples/p256_derive_secret.nim
```

サンプルは短く、目的ごとに分けます。より複雑な firmware envelope flow は、`se050_nim` のexampleではなく、将来の envelope project 側に実装します。
