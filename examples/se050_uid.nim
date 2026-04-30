# =============================================================================
# SE050 UID reader example
# =============================================================================

import std/os
import std/parseopt
import std/strutils

import se050_nim

# --------------------------------------------------------------------------------
# Types:
# --------------------------------------------------------------------------------

type
  AppConfig = object
    bus: int
    address: uint8
    debug: bool
    separator: string

# --------------------------------------------------------------------------------
# Utility:
# --------------------------------------------------------------------------------

proc printUsage(programName: string) =
  echo "Usage:"
  echo "  ", programName, " -b <bus> [options]"
  echo ""
  echo "Options:"
  echo "  -b, --bus <n>        I2C bus number, e.g. 0 for /dev/i2c-0"
  echo "  -a, --address <hex>  I2C address, default: 0x48"
  echo "  -d, --debug          Print T=1 over I2C frames"
  echo "  --colon              Print UID as AA:BB:CC..."
  echo "  -h, --help           Show this help"
  echo ""
  echo "Example:"
  echo "  ", programName, " -b 0"
  echo "  ", programName, " -b 0 --colon"

# --------------------------------------------------------------------------------
# Utility:
# --------------------------------------------------------------------------------

proc getAppName(): string =
  result = getAppFilename().lastPathPart()

# --------------------------------------------------------------------------------
# Utility:
# --------------------------------------------------------------------------------

proc readOptionValue(parser: var OptParser, optionName: string): string =
  ## Supports both:
  ##
  ##   -b 0
  ##   --bus=0
  ##
  ## parseopt stores --bus=0 in parser.val. For -b 0, the next token appears
  ## as cmdArgument.
  if parser.val.len > 0:
    return parser.val

  parser.next()
  if parser.kind != cmdArgument:
    raise newException(ValueError, "missing value for --" & optionName)

  result = parser.key

# --------------------------------------------------------------------------------
# Utility:
# --------------------------------------------------------------------------------

proc parseHexByte(s: string): uint8 =
  var t = s.strip()
  if t.startsWith("0x") or t.startsWith("0X"):
    t = t[2 .. ^1]

  let v = parseHexInt(t)
  if v < 0 or v > 0x7F:
    raise newException(ValueError, "I2C address must be in 7-bit range")

  result = uint8(v)

# --------------------------------------------------------------------------------
# Utility:
# --------------------------------------------------------------------------------

proc parseCommandLine(): AppConfig =
  result.bus = -1
  result.address = DefaultSe050I2cAddress
  result.debug = false
  result.separator = ""

  var parser = initOptParser()

  while true:
    parser.next()

    case parser.kind
    of cmdEnd:
      break

    of cmdShortOption, cmdLongOption:
      case parser.key
      of "b", "bus":
        result.bus = parseInt(readOptionValue(parser, "bus"))

      of "a", "address":
        result.address = parseHexByte(readOptionValue(parser, "address"))

      of "d", "debug":
        result.debug = true

      of "colon":
        result.separator = ":"

      of "h", "help":
        printUsage(getAppName())
        quit(0)

      else:
        raise newException(ValueError, "unknown option: " & parser.key)

    of cmdArgument:
      raise newException(ValueError, "unexpected argument: " & parser.key)

  if result.bus < 0:
    raise newException(ValueError, "I2C bus number is required. Use -b <bus>.")

# --------------------------------------------------------------------------------
# API:
# --------------------------------------------------------------------------------

proc main(): int =
  var cfg: AppConfig

  try:
    cfg = parseCommandLine()
  except CatchableError as e:
    echo "error: ", e.msg
    echo ""
    printUsage(getAppName())
    return 2

  let se = openSe050(cfg.bus, address = cfg.address, debug = cfg.debug)

  let atr = se.requestAtr()
  if not atr.ok:
    echo "ATR failed: ", atr.error.kind, ": ", atr.error.message
    if atr.error.sw != 0:
      echo "SW=0x", atr.error.sw.toHex(4)
    return 1

  let uid = se.readUidHex(separator = cfg.separator, selectFirst = true)
  if not uid.ok:
    echo "UID read failed: ", uid.error.kind, ": ", uid.error.message
    if uid.error.sw != 0:
      echo "SW=0x", uid.error.sw.toHex(4)
    return 1

  echo uid.value
  result = 0

# --------------------------------------------------------------------------------
# Main:
# --------------------------------------------------------------------------------

when isMainModule:
  quit(main())
