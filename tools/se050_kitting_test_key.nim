# =============================================================================
# Disposable SE050 kitting test-key helper
# =============================================================================
#
# Development-only helper for creating and deleting the fixed disposable
# firmware KEX object with the production-like kitting test policy.
#
# This program is deliberately kept outside the normal se050ctl binary and is
# not listed in the Nimble package's `bin` setting. It can only operate on the
# fixed test object defined by testKittingProfile().

import std/options
import std/strformat
import std/strutils

import argparse
import se050_nim

proc parseBusNumber(value: string): int =
  result = parseInt(value.strip())
  if result < 0:
    raise newException(ValueError, &"I2C bus must be >= 0: {value}")

proc parseAddress(value: string): uint8 =
  var text = value.strip()
  if text.startsWith("0x") or text.startsWith("0X"):
    text = text[2 .. ^1]

  let parsed = parseHexInt(text)
  if parsed < 0 or parsed > 0x7F:
    raise newException(ValueError, &"I2C address must be 0x00..0x7F: {value}")
  result = uint8(parsed)

proc printError(prefix: string, error: Se050Error) =
  stderr.writeLine &"{prefix}: {error.kind}: {error.message}"
  if error.sw != 0:
    stderr.writeLine &"SW=0x{error.sw.toHex(4)}"

proc openAndRequestAtr(
    busText: string,
    addressText: string,
    debug: bool
): Se050Transport =
  result = openSe050(
    parseBusNumber(busText),
    parseAddress(addressText),
    debug
  )

  let atr = result.requestAtr()
  if not atr.ok:
    printError("GET_ATR failed", atr.error)
    quit(1)

proc deleteTestKey(se: Se050Transport, allowMissing: bool): bool =
  let profile = testKittingProfile()
  let exists = se.objectExists(profile.keyObjectId, selectFirst = true)
  if not exists.ok:
    printError("CheckObjectExists failed", exists.error)
    return false

  if not exists.value:
    if allowMissing:
      echo &"0x{profile.keyObjectId.toHex(8)}: already absent"
      return true
    stderr.writeLine &"0x{profile.keyObjectId.toHex(8)}: does not exist"
    return false

  let deleted = se.deleteSecureObject(profile.keyObjectId, selectFirst = false)
  if not deleted.ok:
    printError("DeleteSecureObject failed", deleted.error)
    return false

  let after = se.objectExists(profile.keyObjectId, selectFirst = false)
  if not after.ok:
    printError("Delete verification failed", after.error)
    return false
  if after.value:
    stderr.writeLine &"0x{profile.keyObjectId.toHex(8)} still exists after delete"
    return false

  echo &"0x{profile.keyObjectId.toHex(8)}: deleted"
  result = true

proc createTestKey(se: Se050Transport): bool =
  let profile = testKittingProfile()
  let exists = se.objectExists(profile.keyObjectId, selectFirst = true)
  if not exists.ok:
    printError("CheckObjectExists failed", exists.error)
    return false
  if exists.value:
    stderr.writeLine &"0x{profile.keyObjectId.toHex(8)} already exists; delete or recreate it first"
    return false

  let generated = se.generateEcKeyPair(
    objectId = profile.keyObjectId,
    curve = profile.curve,
    policy = profile.keyPolicy(),
    selectFirst = false
  )
  if not generated.ok:
    printError("WriteECKey failed", generated.error)
    return false

  let typ = se.readObjectType(profile.keyObjectId, selectFirst = false)
  if not typ.ok:
    printError("ReadType after key generation failed", typ.error)
    return false
  if typ.value.objectType != profile.expectedKeyType():
    stderr.writeLine &"unexpected object type 0x{typ.value.objectType.toHex(2)}"
    return false

  echo &"0x{profile.keyObjectId.toHex(8)}: created"
  echo &"profile: {profile.name}"
  echo &"curve: {curveName(profile.curve)}"
  echo &"type: 0x{typ.value.objectType.toHex(2)}"
  echo &"policy: 0x{policyHeader(profile.keyPolicy()).toHex(8)}"
  echo &"deletable: yes"
  result = true

proc runCreate(busText: string, addressText: string, debug: bool): int =
  let se = openAndRequestAtr(busText, addressText, debug)
  result = if createTestKey(se): 0 else: 1

proc runDelete(busText: string, addressText: string, debug: bool): int =
  let se = openAndRequestAtr(busText, addressText, debug)
  result = if deleteTestKey(se, allowMissing = false): 0 else: 1

proc runRecreate(busText: string, addressText: string, debug: bool): int =
  let se = openAndRequestAtr(busText, addressText, debug)
  if not deleteTestKey(se, allowMissing = true):
    return 1
  result = if createTestKey(se): 0 else: 1

proc main(): int =
  var parser = newParser("se050-kitting-test-key"):
    help("Create or delete the fixed disposable SE050 kitting test key.")

    command("create"):
      help("Create the fixed test key with the production-like deletable policy.")
      option("-b", "--bus", required = true, help = "I2C bus number")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runCreate(opts.bus, opts.address, opts.debug))

    command("delete"):
      help("Delete the fixed disposable test key.")
      option("-b", "--bus", required = true, help = "I2C bus number")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runDelete(opts.bus, opts.address, opts.debug))

    command("recreate"):
      help("Delete the fixed test key if present, then create it again.")
      option("-b", "--bus", required = true, help = "I2C bus number")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runRecreate(opts.bus, opts.address, opts.debug))

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
