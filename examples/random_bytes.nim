# =============================================================================
# Generate random bytes using SE050
# =============================================================================
#
# Build:
#   nim c examples/random_bytes.nim
#
# Run:
#   ./examples/random_bytes 0 32

import std/[os, strformat, strutils]

import se050_nim

proc usage(programName: string) =
  echo &"Usage: {programName} <bus> [length]"
  echo ""
  echo "Arguments:"
  echo "  length  1..255, default: 32"
  echo ""
  echo "Example:"
  echo &"  {programName} 0 32"

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
  if args.len < 1 or args.len > 2 or args[0] in ["-h", "--help"]:
    usage(getAppFilename().lastPathPart())
    if args.len >= 1 and args[0] in ["-h", "--help"]:
      return 0
    else:
      return 2

  let bus = parseInt(args[0])
  let length = if args.len >= 2: parseInt(args[1]) else: 32

  if bus < 0:
    echo "bus must be >= 0"
    return 2
  if length < 1 or length > Se050MaxRandomLength:
    echo &"length must be 1..{Se050MaxRandomLength}"
    return 2

  let se = openSe050(bus)
  discard requireOk("GET_ATR", se.requestAtr())

  let hex = requireOk("getRandomHex", se.getRandomHex(length))
  echo &"random[{length}]: {hex}"
  result = 0

when isMainModule:
  try:
    quit(main())
  except CatchableError as e:
    echo "error: ", e.msg
    quit(1)
