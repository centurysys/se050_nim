# =============================================================================
# Verify P-256 ECDH using two SE050 development key pairs
# =============================================================================
#
# Build:
#   nim c examples/p256_derive_secret.nim
#
# Run:
#   ./examples/p256_derive_secret 0 0x110 0x111
#
# Behavior:
#   - uses only dev object IDs: 0x30000000..0x3000FFFF
#   - generates a missing P-256 key pair
#   - reuses an existing P-256 key pair
#   - refuses to use an existing object if it is not P-256
#   - derives A private x B public and B private x A public
#   - checks that the two shared secrets match

import std/[os, strformat, strutils]

import se050_nim

const DevObjectBase = 0x30000000'u32

proc usage(programName: string) =
  echo &"Usage: {programName} <bus> [dev-index-a] [dev-index-b]"
  echo ""
  echo "Arguments:"
  echo "  dev-index-a  0x0000..0xFFFF, default: 0x110"
  echo "  dev-index-b  0x0000..0xFFFF, default: 0x111"
  echo ""
  echo "Example:"
  echo &"  {programName} 0 0x110 0x111"

proc parseU32Text(s: string): uint32 =
  var t = s.strip()
  if t.len == 0:
    raise newException(ValueError, "empty integer")

  var base = 10'u32
  if t.startsWith("0x") or t.startsWith("0X"):
    t = t[2 .. ^1]
    base = 16'u32

  if t.len == 0:
    raise newException(ValueError, "empty integer")

  var acc: uint64 = 0
  for c in t:
    var digit: uint32
    if c >= '0' and c <= '9':
      digit = uint32(ord(c) - ord('0'))
    elif base == 16 and c >= 'a' and c <= 'f':
      digit = uint32(ord(c) - ord('a') + 10)
    elif base == 16 and c >= 'A' and c <= 'F':
      digit = uint32(ord(c) - ord('A') + 10)
    else:
      raise newException(ValueError, &"invalid integer: {s}")

    if digit >= base:
      raise newException(ValueError, &"invalid integer: {s}")

    acc = acc * uint64(base) + uint64(digit)
    if acc > uint64(uint32.high):
      raise newException(ValueError, &"integer out of uint32 range: {s}")

  result = uint32(acc)

proc devObjectId(index: uint32): uint32 =
  if index > 0xFFFF'u32:
    raise newException(ValueError, "dev-index must be 0x0000..0xFFFF")
  result = DevObjectBase or index

proc bytesToString(data: openArray[uint8]): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc requireOk[T](label: string, r: SE[T]): T =
  if not r.ok:
    echo label, " failed: ", r.error.kind, ": ", r.error.errorMessage()
    quit(1)
  result = r.value

proc requireVoidOk(label: string, r: SE[void]) =
  if not r.ok:
    echo label, " failed: ", r.error.kind, ": ", r.error.errorMessage()
    quit(1)

proc ensureP256Key(se: Se050Transport, objectId: uint32) =
  let exists = requireOk("objectExists", se.objectExists(objectId))
  if exists:
    let typeInfo = requireOk("readObjectType", se.readObjectType(objectId))
    if typeInfo.objectType != Se050TypeEcKeyPairNistP256:
      echo &"object 0x{objectId.toHex(8)} exists but is not P-256: " &
           &"0x{typeInfo.objectType.toHex(2)} ({objectTypeName(typeInfo.objectType)})"
      quit(2)
    echo &"reuse: 0x{objectId.toHex(8)} ({objectTypeName(typeInfo.objectType)})"
  else:
    requireVoidOk("generateP256KeyPair", se.generateP256KeyPair(objectId))
    echo &"created: 0x{objectId.toHex(8)}"

proc writeBytes(path: string, data: openArray[uint8]) =
  writeFile(path, bytesToString(data))

proc main(): int =
  let args = commandLineParams()
  if args.len > 3 or (args.len >= 1 and args[0] in ["-h", "--help"]):
    usage(getAppFilename().lastPathPart())
    if args.len >= 1 and args[0] in ["-h", "--help"]:
      return 0
    else:
      return 2
  if args.len < 1:
    usage(getAppFilename().lastPathPart())
    return 2

  let bus = parseInt(args[0])
  let indexA = if args.len >= 2: parseU32Text(args[1]) else: 0x110'u32
  let indexB = if args.len >= 3: parseU32Text(args[2]) else: 0x111'u32
  let objectA = devObjectId(indexA)
  let objectB = devObjectId(indexB)

  if bus < 0:
    echo "bus must be >= 0"
    return 2
  if objectA == objectB:
    echo "dev-index-a and dev-index-b must be different"
    return 2

  let se = openSe050(bus)
  discard requireOk("GET_ATR", se.requestAtr())

  ensureP256Key(se, objectA)
  ensureP256Key(se, objectB)

  let pubA = requireOk("readPublicKey A", se.readPublicKey(objectA))
  let pubB = requireOk("readPublicKey B", se.readPublicKey(objectB))

  writeBytes("p256_a_pub.bin", pubA)
  writeBytes("p256_b_pub.bin", pubB)
  echo &"public A length: {pubA.len}"
  echo &"public B length: {pubB.len}"

  let secretAB = requireOk("derive A x B", se.deriveSharedSecret(objectA, pubB))
  let secretBA = requireOk("derive B x A", se.deriveSharedSecret(objectB, pubA))

  writeBytes("p256_secret_ab.bin", secretAB)
  writeBytes("p256_secret_ba.bin", secretBA)
  echo &"secret AB length: {secretAB.len}"
  echo &"secret BA length: {secretBA.len}"

  if secretAB != secretBA:
    echo "P-256 ECDH mismatch"
    return 1

  echo "P-256 ECDH OK: shared secrets match"
  result = 0

when isMainModule:
  try:
    quit(main())
  except CatchableError as e:
    echo "error: ", e.msg
    quit(1)
