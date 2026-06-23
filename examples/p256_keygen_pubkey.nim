# =============================================================================
# Generate one P-256 key pair in the SE050 development object range
# =============================================================================
#
# Build:
#   nim c examples/p256_keygen_pubkey.nim
#
# Run:
#   ./examples/p256_keygen_pubkey 0 0x110 p256_110_pub.bin
#
# Safety:
#   This example writes only to dev object IDs:
#     0x30000000..0x3000FFFF
#   It refuses to overwrite an existing object.

import std/[os, strformat, strutils]

import se050_nim

const DevObjectBase = 0x30000000'u32

proc usage(programName: string) =
  echo &"Usage: {programName} <bus> [dev-index] [public-key-out]"
  echo ""
  echo "Arguments:"
  echo "  dev-index       0x0000..0xFFFF, default: 0x110"
  echo "  public-key-out  default: p256_pub.bin"
  echo ""
  echo "Example:"
  echo &"  {programName} 0 0x110 p256_110_pub.bin"

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
  let index = if args.len >= 2: parseU32Text(args[1]) else: 0x110'u32
  let outPath = if args.len >= 3: args[2] else: "p256_pub.bin"
  let objectId = devObjectId(index)

  if bus < 0:
    echo "bus must be >= 0"
    return 2

  let se = openSe050(bus)
  discard requireOk("GET_ATR", se.requestAtr())

  let exists = requireOk("objectExists", se.objectExists(objectId))
  if exists:
    echo &"object 0x{objectId.toHex(8)} already exists; refusing to overwrite"
    echo "delete it explicitly with se050ctl or choose another dev-index"
    return 2

  requireVoidOk("generateP256KeyPair", se.generateP256KeyPair(objectId))

  let typeInfo = requireOk("readObjectType", se.readObjectType(objectId))
  echo &"created: 0x{objectId.toHex(8)}"
  echo &"type: 0x{typeInfo.objectType.toHex(2)} ({objectTypeName(typeInfo.objectType)})"

  if typeInfo.objectType != Se050TypeEcKeyPairNistP256:
    echo "unexpected key type"
    return 1

  let pubkey = requireOk("readPublicKey", se.readPublicKey(objectId))
  writeFile(outPath, bytesToString(pubkey))
  echo &"public key written: {outPath}"
  echo &"length: {pubkey.len}"

  result = 0

when isMainModule:
  try:
    quit(main())
  except CatchableError as e:
    echo "error: ", e.msg
    quit(1)
