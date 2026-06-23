# =============================================================================
# Read SE050 UID
# =============================================================================
#
# Build:
#   nim c examples/read_uid.nim
#
# Run:
#   ./examples/read_uid 0

import std/[os, strformat, strutils]

import se050_nim

proc usage(programName: string) =
  echo &"Usage: {programName} <bus>"
  echo ""
  echo "Example:"
  echo &"  {programName} 0"

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
  if args.len != 1 or args[0] in ["-h", "--help"]:
    usage(getAppFilename().lastPathPart())
    if args.len == 1:
      return 0
    else:
      return 2

  let bus = parseInt(args[0])
  if bus < 0:
    echo "bus must be >= 0"
    return 2

  let se = openSe050(bus)
  discard requireOk("GET_ATR", se.requestAtr())

  let uid = requireOk("readUidHex", se.readUidHex())
  echo &"uid: {uid}"
  result = 0

when isMainModule:
  try:
    quit(main())
  except CatchableError as e:
    echo "error: ", e.msg
    quit(1)
