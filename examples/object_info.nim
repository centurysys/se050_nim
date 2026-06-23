# =============================================================================
# Inspect one SE050 Secure Object
# =============================================================================
#
# Build:
#   nim c examples/object_info.nim
#
# Run:
#   ./examples/object_info 0 0x7FFF0206
#   ./examples/object_info 0 0x30000110

import std/[options, os, strformat, strutils]

import se050_nim

proc usage(programName: string) =
  echo &"Usage: {programName} <bus> <object-id>"
  echo ""
  echo "Examples:"
  echo &"  {programName} 0 0x7FFF0206"
  echo &"  {programName} 0 0x30000110"

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

proc requireOk[T](label: string, r: SE[T]): T =
  if not r.ok:
    echo label, " failed: ", r.error.kind, ": ", r.error.errorMessage()
    quit(1)
  when T is void:
    discard
  else:
    result = r.value

proc main(): int =
  let args = commandLineParams()
  if args.len != 2 or args[0] in ["-h", "--help"]:
    usage(getAppFilename().lastPathPart())
    if args.len >= 1 and args[0] in ["-h", "--help"]:
      return 0
    else:
      return 2

  let bus = parseInt(args[0])
  let objectId = parseU32Text(args[1])

  if bus < 0:
    echo "bus must be >= 0"
    return 2

  let se = openSe050(bus)
  discard requireOk("GET_ATR", se.requestAtr())

  let exists = requireOk("objectExists", se.objectExists(objectId))
  echo &"id: 0x{objectId.toHex(8)}"
  echo &"exists: {exists}"

  if not exists:
    return 0

  let typeInfo = requireOk("readObjectType", se.readObjectType(objectId))
  echo &"type: 0x{typeInfo.objectType.toHex(2)} ({objectTypeName(typeInfo.objectType)})"
  if typeInfo.transientIndicator.isSome:
    let t = typeInfo.transientIndicator.get()
    echo &"transient: 0x{t.toHex(2)} ({transientIndicatorName(t)})"

  let size = se.readObjectSize(objectId)
  if size.ok:
    echo &"size: {size.value}"
  else:
    echo "size: unavailable: ", size.error.kind, ": ", size.error.errorMessage()

  result = 0

when isMainModule:
  try:
    quit(main())
  except CatchableError as e:
    echo "error: ", e.msg
    quit(1)
