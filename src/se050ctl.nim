# =============================================================================
# se050ctl
# =============================================================================
#
# Development/diagnostic CLI for se050_nim.
#
# This tool intentionally stays at the low-level SE050 primitive layer.
# Firmware package, manifest, and envelope handling should live in higher layers
# such as fwkeys / fw-envelope / fw-update.

import std/options
import std/strformat
import std/strutils

import argparse
import se050_nim

# =============================================================================
# Utility
# =============================================================================

proc parseBusNumber(s: string): int =
  let v = parseInt(s.strip())
  if v < 0:
    raise newException(ValueError, &"I2C bus number must be >= 0: {s}")
  result = v

proc parseI2cAddress(s: string): uint8 =
  ## Parses a 7-bit I2C address.
  ##
  ## The value is treated as hexadecimal to preserve the existing se050_uid
  ## behavior. Both "48" and "0x48" mean 0x48.
  var t = s.strip()
  if t.startsWith("0x") or t.startsWith("0X"):
    t = t[2 .. ^1]

  let v = parseHexInt(t)
  if v < 0 or v > 0x7F:
    raise newException(ValueError, &"I2C address must be in 7-bit range: {s}")

  result = uint8(v)

proc parseLength(s: string, minValue: int, maxValue: int): int =
  let v = parseInt(s.strip())
  if v < minValue or v > maxValue:
    raise newException(ValueError, &"length must be in range {minValue}..{maxValue}: {s}")
  result = v

proc printSe050Error(prefix: string, e: Se050Error) =
  stderr.writeLine &"{prefix}: {e.kind}: {e.message}"
  if e.sw != 0:
    stderr.writeLine &"SW=0x{e.sw.toHex(4)}"

# =============================================================================
# Commands
# =============================================================================

proc openAndRequestAtr(busText: string, addressText: string, debug: bool): Se050Transport =
  let bus = parseBusNumber(busText)
  let address = parseI2cAddress(addressText)

  result = openSe050(bus, address = address, debug = debug)

  let atr = result.requestAtr()
  if not atr.ok:
    printSe050Error("ATR failed", atr.error)
    quit(1)

proc runUid(busText: string, addressText: string, debug: bool, separator: string): int =
  let se = openAndRequestAtr(busText, addressText, debug)

  let uid = se.readUidHex(separator = separator, selectFirst = true)
  if not uid.ok:
    printSe050Error("UID read failed", uid.error)
    return 1

  echo uid.value
  result = 0

proc runRandom(
    busText: string,
    addressText: string,
    debug: bool,
    lengthText: string,
    separator: string
): int =
  let length = parseLength(lengthText, 1, Se050MaxRandomLength)
  let se = openAndRequestAtr(busText, addressText, debug)

  let randomHex = se.getRandomHex(
    length = length,
    separator = separator,
    selectFirst = true
  )
  if not randomHex.ok:
    printSe050Error("GetRandom failed", randomHex.error)
    return 1

  echo randomHex.value
  result = 0

# =============================================================================
# Main
# =============================================================================

proc main(): int =
  var parser = newParser("se050ctl"):
    help("Low-level SE050 diagnostic and provisioning helper.")

    command("uid"):
      help("Read the SE050 unique ID object.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      flag("--colon", help = "Print UID as AA:BB:CC...")
      run:
        let separator = if opts.colon: ":" else: ""
        quit(runUid(opts.bus, opts.address, opts.debug, separator))

    command("random"):
      help("Generate random bytes using SE050 GetRandom.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("-l", "--len", required = true, help = "Random byte length, 1..255")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      flag("--colon", help = "Print bytes as AA:BB:CC...")
      run:
        let separator = if opts.colon: ":" else: ""
        quit(runRandom(opts.bus, opts.address, opts.debug, opts.len, separator))

  try:
    parser.run()
    result = 0
  except UsageError:
    stderr.writeLine getCurrentExceptionMsg()
    result = 2
  except ValueError:
    stderr.writeLine &"error: {getCurrentExceptionMsg()}"
    result = 2

when isMainModule:
  quit(main())
