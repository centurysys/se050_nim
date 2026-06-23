# se050_nim Sample Code

This document contains small examples for using `se050_nim` as a library.

The examples intentionally stay at the primitive layer. Production provisioning, firmware envelope handling, and updater logic should live in separate projects.

## Read UID

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

## Generate random bytes

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

## Print version and features

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

## Create a development P-256 key and export its public key

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

## P-256 derive using two development keys

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

## Error handling pattern

For command-line tools, preserve the APDU status word in logs because it is often the only clue returned by the applet.

```nim
import std/strutils

let r = se.deriveSharedSecret(keyId, peerPublicKey)
if not r.ok:
  stderr.writeLine "derive failed: " & r.error.errorMessage()
  if r.error.sw != 0:
    stderr.writeLine "SW=0x" & r.error.sw.toHex(4)
  quit 1
```

## Notes for future examples

Recommended actual example files:

```text
examples/read_uid.nim
examples/random_bytes.nim
examples/version_info.nim
examples/p256_keygen_pubkey.nim
examples/p256_derive_secret.nim
```

Keep examples short and focused. More complex firmware envelope flows should be implemented in the future envelope project, not in `se050_nim` examples.
