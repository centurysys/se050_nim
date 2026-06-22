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
# Safety policy for destructive CLI operations
# =============================================================================

const
  VendorReservedStart = 0x10000000'u32
  VendorReservedEnd = 0x10000FFF'u32

  # NXP-reserved applet objects such as 0x7FFF0206 unique ID live here.
  NxpReservedStart = 0x7FFF0000'u32
  NxpReservedEnd = 0x7FFFFFFF'u32

  # Objects observed in this range are treated as internal/platform objects.
  InternalReservedStart = 0xF0000000'u32
  InternalReservedEnd = 0xFFFFFFFF'u32

  # se050ctl intentionally keeps key creation/deletion in this shallow-water
  # development range. Vendor-reserved IDs are left to a dedicated provisioning
  # tool, not this user-facing diagnostic CLI.
  DevelopmentStart = 0x30000000'u32
  DevelopmentEnd = 0x3000FFFF'u32

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

proc parseObjectId(s: string): uint32 =
  ## Parses an SE050 Secure Object identifier.
  ##
  ## The value is treated as hexadecimal. Both "10000100" and "0x10000100"
  ## mean 0x10000100.
  var t = s.strip()
  if t.startsWith("0x") or t.startsWith("0X"):
    t = t[2 .. ^1]

  if t.len == 0:
    raise newException(ValueError, "object id is empty")

  let v = parseHexInt(t)
  if v < 0:
    raise newException(ValueError, &"object id must be >= 0: {s}")

  result = uint32(v)

proc parseHexByte(s: string): uint8 =
  ## Parses a hexadecimal byte value.
  var t = s.strip()
  if t.startsWith("0x") or t.startsWith("0X"):
    t = t[2 .. ^1]

  if t.len == 0:
    raise newException(ValueError, "hex byte is empty")

  let v = parseHexInt(t)
  if v < 0 or v > 0xFF:
    raise newException(ValueError, &"hex byte must be in range 0x00..0xFF: {s}")

  result = uint8(v)

proc printSe050Error(prefix: string, e: Se050Error) =
  stderr.writeLine &"{prefix}: {e.kind}: {e.message}"
  if e.sw != 0:
    stderr.writeLine &"SW=0x{e.sw.toHex(4)}"

proc objectIdHex(objectId: uint32): string =
  result = &"0x{objectId.toHex(8)}"

proc isInRange(value: uint32, first: uint32, last: uint32): bool =
  result = value >= first and value <= last

proc isVendorReservedObjectId(objectId: uint32): bool =
  result = objectId.isInRange(VendorReservedStart, VendorReservedEnd)

proc isProtectedReservedObjectId(objectId: uint32): bool =
  result =
    objectId.isInRange(NxpReservedStart, NxpReservedEnd) or
    objectId.isInRange(InternalReservedStart, InternalReservedEnd)

proc isDevelopmentObjectId(objectId: uint32): bool =
  result = objectId.isInRange(DevelopmentStart, DevelopmentEnd)

proc deleteTargetError(objectId: uint32): Option[string] =
  if objectId == 0'u32:
    return some("object id 0x00000000 is not a valid delete target")

  if objectId.isProtectedReservedObjectId():
    return some(
      &"delete refused: {objectIdHex(objectId)} is in a protected SE050 reserved range"
    )

  if objectId.isVendorReservedObjectId():
    return some(
      &"delete refused: {objectIdHex(objectId)} is in the vendor reserved range; " &
      "use a dedicated provisioning tool for vendor-reserved objects"
    )

  result = none(string)

proc keygenTargetError(objectId: uint32): Option[string] =
  if objectId == 0'u32:
    return some("object id 0x00000000 is not a valid key generation target")

  if objectId.isProtectedReservedObjectId():
    return some(
      &"keygen refused: {objectIdHex(objectId)} is in a protected SE050 reserved range"
    )

  if objectId.isVendorReservedObjectId():
    return some(
      &"keygen refused: {objectIdHex(objectId)} is in the vendor reserved range; use a dedicated provisioning tool for vendor-reserved objects"
    )

  if not objectId.isDevelopmentObjectId():
    return some(
      &"keygen refused: {objectIdHex(objectId)} is outside the se050ctl development range 0x{DevelopmentStart.toHex(8)}..0x{DevelopmentEnd.toHex(8)}"
    )

  result = none(string)

proc parseCurveKind(s: string): EcCurveKind =
  case s.strip().toLowerAscii()
  of "x25519", "mont-dh-25519", "mont25519", "ecc-mont-dh-25519":
    result = ecCurveX25519
  else:
    raise newException(ValueError, &"unsupported curve for se050ctl keygen: {s}")

proc typeText(objectType: uint8): string =
  result = &"0x{objectType.toHex(2)} ({objectTypeName(objectType)})"

proc transientText(indicator: Option[uint8]): string =
  if indicator.isSome:
    let v = indicator.get()
    result = &"0x{v.toHex(2)} ({transientIndicatorName(v)})"
  else:
    result = "n/a"

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

proc runExists(
    busText: string,
    addressText: string,
    debug: bool,
    objectIdText: string,
    quiet: bool
): int =
  let objectId = parseObjectId(objectIdText)
  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not quiet:
    let statusText = if exists.value: "exists" else: "missing"
    echo &"{objectIdHex(objectId)}: {statusText}"

  result = if exists.value: 0 else: 1

proc runInfo(
    busText: string,
    addressText: string,
    debug: bool,
    objectIdText: string
): int =
  let objectId = parseObjectId(objectIdText)
  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  echo &"id: {objectIdHex(objectId)}"
  let existsText = if exists.value: "yes" else: "no"
  echo &"exists: {existsText}"

  if not exists.value:
    return 1

  let typ = se.readObjectType(objectId = objectId, selectFirst = false)
  if not typ.ok:
    printSe050Error("ReadType failed", typ.error)
    return 1

  echo &"type: {typeText(typ.value.objectType)}"
  echo &"transient: {transientText(typ.value.transientIndicator)}"

  let size = se.readObjectSize(objectId = objectId, selectFirst = false)
  if size.ok:
    echo &"size: {size.value}"
  else:
    echo "size: unavailable"
    stderr.writeLine &"ReadSize failed: {size.error.kind}: {size.error.message}"
    if size.error.sw != 0:
      stderr.writeLine &"SW=0x{size.error.sw.toHex(4)}"

  result = 0

proc runList(
    busText: string,
    addressText: string,
    debug: bool,
    filterText: string
): int =
  let filter = parseHexByte(filterText)
  let se = openAndRequestAtr(busText, addressText, debug)

  let ids = se.listObjectIds(filter = filter, selectFirst = true)
  if not ids.ok:
    printSe050Error("ReadIDList failed", ids.error)
    return 1

  for objectId in ids.value:
    echo objectIdHex(objectId)

  result = 0

proc runKeygen(
    busText: string,
    addressText: string,
    debug: bool,
    objectIdText: string,
    curveText: string
): int =
  let objectId = parseObjectId(objectIdText)
  let curve = parseCurveKind(curveText)

  let guard = keygenTargetError(objectId = objectId)
  if guard.isSome:
    stderr.writeLine guard.get()
    return 2

  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if exists.value:
    stderr.writeLine &"keygen refused: {objectIdHex(objectId)} already exists"
    return 1

  let generated = se.generateEcKeyPair(
    objectId = objectId,
    curve = curve,
    selectFirst = false
  )
  if not generated.ok:
    printSe050Error("WriteECKey failed", generated.error)
    return 1

  let after = se.objectExists(objectId = objectId, selectFirst = false)
  if not after.ok:
    printSe050Error("Keygen verification failed", after.error)
    return 1

  if not after.value:
    stderr.writeLine &"WriteECKey returned success, but {objectIdHex(objectId)} does not exist"
    return 1

  let typ = se.readObjectType(objectId = objectId, selectFirst = false)
  if not typ.ok:
    printSe050Error("ReadType after keygen failed", typ.error)
    return 1

  let expectedType = expectedKeyPairType(curve)
  if typ.value.objectType != expectedType:
    stderr.writeLine &"keygen verification failed: expected type 0x{expectedType.toHex(2)}, got {typeText(typ.value.objectType)}"
    return 1

  echo &"{objectIdHex(objectId)}: created"
  echo &"curve: {curveName(curve)}"
  echo &"type: {typeText(typ.value.objectType)}"
  echo &"transient: {transientText(typ.value.transientIndicator)}"

  result = 0

proc runDelete(
    busText: string,
    addressText: string,
    debug: bool,
    objectIdText: string
): int =
  let objectId = parseObjectId(objectIdText)

  let guard = deleteTargetError(objectId = objectId)
  if guard.isSome:
    stderr.writeLine guard.get()
    return 2

  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not exists.value:
    echo &"{objectIdHex(objectId)}: missing"
    return 1

  let deleted = se.deleteSecureObject(objectId = objectId, selectFirst = false)
  if not deleted.ok:
    printSe050Error("DeleteSecureObject failed", deleted.error)
    return 1

  let after = se.objectExists(objectId = objectId, selectFirst = false)
  if not after.ok:
    printSe050Error("Delete verification failed", after.error)
    return 1

  if after.value:
    stderr.writeLine &"DeleteSecureObject returned success, but {objectIdHex(objectId)} still exists"
    return 1

  echo &"{objectIdHex(objectId)}: deleted"
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

    command("exists"):
      help("Check whether an SE050 Secure Object identifier exists.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", required = true, help = "Secure Object ID in hex, e.g. 0x10000100")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      flag("-q", "--quiet", help = "Do not print status; use exit code only")
      run:
        quit(runExists(opts.bus, opts.address, opts.debug, opts.id, opts.quiet))

    command("info"):
      help("Read type and size information for an SE050 Secure Object identifier.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", required = true, help = "Secure Object ID in hex, e.g. 0x10000100")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runInfo(opts.bus, opts.address, opts.debug, opts.id))

    command("list"):
      help("List visible SE050 Secure Object identifiers.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--filter", default = some("0xFF"), help = "SecureObjectType filter byte, default: 0xFF for all types")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runList(opts.bus, opts.address, opts.debug, opts.filter))

    command("keygen"):
      help("Generate a development SE050 key pair. Only 0x30000000..0x3000FFFF is allowed by this CLI.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", required = true, help = "Development Secure Object ID in hex, e.g. 0x30000100")
      option("--curve", default = some("x25519"), help = "Curve name, currently: x25519")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runKeygen(
          opts.bus,
          opts.address,
          opts.debug,
          opts.id,
          opts.curve
        ))

    command("delete"):
      help("Delete an SE050 Secure Object identifier. Destructive operation; reserved ranges are always guarded.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", required = true, help = "Secure Object ID in hex, e.g. 0x30000100")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runDelete(
          opts.bus,
          opts.address,
          opts.debug,
          opts.id
        ))

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
