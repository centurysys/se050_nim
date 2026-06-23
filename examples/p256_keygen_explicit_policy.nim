# =============================================================================
# Generate one P-256 key pair with an explicit EC key policy
# =============================================================================
#
# Build:
#   nim c examples/p256_keygen_explicit_policy.nim
#
# Run, safe development policy:
#   ./examples/p256_keygen_explicit_policy 0 0x120 development p256_120_pub.bin
#
# Run, sticky device-style policy:
#   ./examples/p256_keygen_explicit_policy 0 0x121 device p256_121_pub.bin --allow-sticky
#
# Safety:
#   This example writes only to dev object IDs:
#     0x30000000..0x3000FFFF
#
#   The device and one-time policies intentionally do not allow WRITE, GEN, or
#   DELETE after object creation. Objects created with those policies may not be
#   removable by se050ctl. The example therefore requires --allow-sticky for
#   those policy modes.

import std/[os, strformat, strutils]

import se050_nim

const DevObjectBase = 0x30000000'u32

type ExamplePolicy = enum
  epDevelopment,
  epDevice,
  epOneTime

proc usage(programName: string) =
  echo &"Usage: {programName} <bus> [dev-index] [policy] [public-key-out] [--allow-sticky]"
  echo ""
  echo "Arguments:"
  echo "  dev-index       0x0000..0xFFFF, default: 0x120"
  echo "  policy          development | device | one-time, default: development"
  echo "  public-key-out  default: p256_policy_pub.bin"
  echo ""
  echo "Examples:"
  echo &"  {programName} 0 0x120 development p256_120_pub.bin"
  echo &"  {programName} 0 0x121 device p256_121_pub.bin --allow-sticky"
  echo ""
  echo "Safety:"
  echo "  This example refuses to use vendor/customer/NXP/internal object IDs."
  echo "  device and one-time policies may create objects that se050ctl cannot delete."
  echo "  Use --allow-sticky only with a disposable dev object index."

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

proc parsePolicy(s: string): ExamplePolicy =
  let name = s.toLowerAscii().replace("-", "").replace("_", "")
  case name
  of "development", "dev": epDevelopment
  of "device": epDevice
  of "onetime": epOneTime
  else:
    raise newException(ValueError, &"unknown policy: {s}")

proc policyName(policy: ExamplePolicy): string =
  case policy
  of epDevelopment: "development"
  of epDevice: "device"
  of epOneTime: "one-time"

proc toEcKeyPolicy(policy: ExamplePolicy): EcKeyPolicy =
  case policy
  of epDevelopment: developmentEcKeyPolicy()
  of epDevice: deviceEcKeyPolicy()
  of epOneTime: oneTimeDeviceKeyPolicy()

proc isSticky(policy: ExamplePolicy): bool =
  policy in {epDevice, epOneTime}

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
  var args = commandLineParams()
  var allowSticky = false

  if "--allow-sticky" in args:
    allowSticky = true
    args.delete(args.find("--allow-sticky"))

  if args.len > 4 or (args.len >= 1 and args[0] in ["-h", "--help"]):
    usage(getAppFilename().lastPathPart())
    if args.len >= 1 and args[0] in ["-h", "--help"]:
      return 0
    else:
      return 2
  if args.len < 1:
    usage(getAppFilename().lastPathPart())
    return 2

  let bus = parseInt(args[0])
  let index = if args.len >= 2: parseU32Text(args[1]) else: 0x120'u32
  let selectedPolicy = if args.len >= 3: parsePolicy(args[2]) else: epDevelopment
  let outPath = if args.len >= 4: args[3] else: "p256_policy_pub.bin"
  let objectId = devObjectId(index)

  if bus < 0:
    echo "bus must be >= 0"
    return 2

  if selectedPolicy.isSticky() and not allowSticky:
    echo &"policy '{selectedPolicy.policyName()}' may create an object that cannot be deleted by se050ctl"
    echo "re-run with --allow-sticky only if this dev index is disposable"
    return 2

  let se = openSe050(bus)
  discard requireOk("GET_ATR", se.requestAtr())

  let exists = requireOk("objectExists", se.objectExists(objectId))
  if exists:
    echo &"object 0x{objectId.toHex(8)} already exists; refusing to overwrite"
    echo "choose another dev-index or delete it explicitly before running this example"
    return 2

  let keyPolicy = selectedPolicy.toEcKeyPolicy()
  echo &"creating P-256 key pair: 0x{objectId.toHex(8)}"
  echo &"policy: {selectedPolicy.policyName()}"
  echo &"policy header: 0x{keyPolicy.policyHeader().toHex(8)}"

  requireVoidOk("generateP256KeyPair", se.generateP256KeyPair(objectId, keyPolicy))

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
