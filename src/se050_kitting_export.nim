# =============================================================================
# se050-kitting-export
# =============================================================================
#
# Factory/development exporter for an Attestation-backed, multi-device CSV.
# The test profile creates a disposable key in the development range. The
# production profile creates or reuses the fixed one-time/no-delete key in the
# customer range. Deployment packaging decides whether this executable is
# included in a target image.

import std/options
import std/os
import std/strformat
import std/strutils
import std/times

import argparse
import se050_nim

# =============================================================================
# Utility
# =============================================================================

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

proc readOptionalCsv(path: string): SE[Option[string]] =
  if not fileExists(path):
    return ok(none(string))

  try:
    result = ok(some(readFile(path)))
  except CatchableError as error:
    result = fail[Option[string]](
      seInvalidArgument,
      &"cannot read kitting CSV {path}: {error.msg}"
    )

proc writeCsvAtomic(path: string, content: string): SE[void] =
  ## Replaces the CSV through a temporary file in the same directory.
  ##
  ## Same-directory rename prevents readers from observing a partially written
  ## CSV. The current exporter assumes one writer; file locking and explicit
  ## fsync durability are not implemented.
  let directory = parentDir(path)
  if directory.len > 0 and not dirExists(directory):
    return fail[void](
      seInvalidArgument,
      &"kitting CSV directory does not exist: {directory}"
    )

  let temporary = path & &".tmp.{getCurrentProcessId()}"
  if fileExists(temporary):
    return fail[void](
      seInvalidArgument,
      &"temporary kitting CSV already exists: {temporary}"
    )

  try:
    writeFile(temporary, content)
    moveFile(temporary, path)
    result = ok()
  except CatchableError as error:
    if fileExists(temporary):
      try:
        removeFile(temporary)
      except CatchableError:
        discard
    result = fail[void](
      seInvalidArgument,
      &"cannot replace kitting CSV {path}: {error.msg}"
    )

proc utcTimestamp(): string =
  result = getTime().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'")

proc openAndRequestAtr(
    busText: string,
    addressText: string,
    debug: bool
): SE[Se050Transport] =
  let se = openSe050(
    parseBusNumber(busText),
    parseAddress(addressText),
    debug
  )

  let atr = se.requestAtr()
  if not atr.ok:
    return fail[Se050Transport](
      atr.error.kind,
      atr.error.message,
      atr.error.sw
    )

  result = ok(se)

# =============================================================================
# Live kitting export
# =============================================================================

proc ensureKittingKey(
    se: Se050Transport,
    profile: KittingProfile,
    objectAlreadyExists: bool
): SE[bool] =
  ## Returns true when this invocation created the key.
  ##
  ## Existing objects are never overwritten or deleted. The full signed policy,
  ## origin, and object semantics are verified later through Attestation.
  if not profile.isValid():
    return fail[bool](
      seInvalidArgument,
      "kitting profile is invalid"
    )

  if not objectAlreadyExists:
    let generated = se.generateEcKeyPair(
      objectId = profile.keyObjectId,
      curve = profile.curve,
      policy = profile.keyPolicy(),
      selectFirst = false
    )
    if not generated.ok:
      return fail[bool](
        generated.error.kind,
        generated.error.message,
        generated.error.sw
      )
    result.value = true

  let objectType = se.readObjectType(profile.keyObjectId, selectFirst = false)
  if not objectType.ok:
    return fail[bool](
      objectType.error.kind,
      objectType.error.message,
      objectType.error.sw
    )

  if objectType.value.objectType != profile.expectedKeyType():
    return fail[bool](
      seKittingValidationFailed,
      &"{profile.name} object 0x{profile.keyObjectId.toHex(8)} has type 0x{objectType.value.objectType.toHex(2)}; expected 0x{profile.expectedKeyType().toHex(2)}"
    )

  if objectType.value.transientIndicator.isNone or
      objectType.value.transientIndicator.get() != 0x01'u8:
    return fail[bool](
      seKittingValidationFailed,
      &"{profile.name} object 0x{profile.keyObjectId.toHex(8)} is not persistent"
    )

  result.ok = true

proc verifyExistingRecords(
    records: openArray[KittingRecord],
    trustAnchors: openArray[seq[uint8]],
    intermediates: openArray[seq[uint8]]
): SE[seq[VerifiedKittingRecord]] =
  for index, record in records:
    let verified = verifyKittingRecord(record, trustAnchors, intermediates)
    if not verified.ok:
      return fail[seq[VerifiedKittingRecord]](
        verified.error.kind,
        &"existing kitting CSV row {index + 2}: {verified.error.message}",
        verified.error.sw
      )
    result.value.add(verified.value)
  result.ok = true

proc findExistingVerifiedRecord(
    records: openArray[VerifiedKittingRecord],
    serialNumber: string,
    profile: KittingProfile
): Option[VerifiedKittingRecord] =
  for verified in records:
    if verified.record.serialNumber == serialNumber and
        verified.record.profileKind == profile.kind and
        verified.record.keyRole == profile.keyRole:
      return some(verified)
  result = none(VerifiedKittingRecord)

proc runKittingExport(
    profile: KittingProfile,
    busText: string,
    addressText: string,
    csvPath: string,
    debug: bool
): int =
  if not profile.isValid():
    stderr.writeLine "invalid kitting profile"
    return 2

  let trustAnchors = nxpAttestationTrustAnchors()
  let intermediates = nxpAttestationIntermediates()

  let serial = readBoardSerialNumber()
  if not serial.ok:
    printError("Read board serial number failed", serial.error)
    return 2

  let opened = openAndRequestAtr(busText, addressText, debug)
  if not opened.ok:
    printError("Open SE050 failed", opened.error)
    return 6
  let se = opened.value

  let version = se.getVersionInfo(selectFirst = true)
  if not version.ok:
    printError("GetVersion failed", version.error)
    return 6
  if version.value.major != KittingAppletMajor or
      version.value.minor != KittingAppletMinor:
    stderr.writeLine &"unsupported SE050 applet version {version.value.major}.{version.value.minor}.{version.value.patch}; expected {KittingAppletMajor}.{KittingAppletMinor}.x"
    return 1

  # Complete all reversible trust/input checks before an absent production key
  # is created with a no-delete/no-overwrite policy.
  let certificate = se.readAttestationCertificate(selectFirst = false)
  if not certificate.ok:
    printError("Read attestation certificate failed", certificate.error)
    return 6

  let certificateChain = verifyCertificateChain(
    leafCertificateDer = certificate.value,
    trustAnchorsDer = trustAnchors,
    intermediatesDer = intermediates
  )
  if not certificateChain.ok:
    printError("Verify attestation certificate failed", certificateChain.error)
    return 1

  let liveUidArray = se.readUidRaw(selectFirst = false)
  if not liveUidArray.ok:
    printError("Read live SE050 UID failed", liveUidArray.error)
    return 6
  let liveUid = @(liveUidArray.value)

  let existingText = readOptionalCsv(csvPath)
  if not existingText.ok:
    printError("Read kitting CSV failed", existingText.error)
    return 2

  var existingRecords: seq[KittingRecord] = @[]
  var existingVerified: seq[VerifiedKittingRecord] = @[]
  if existingText.value.isSome:
    let decoded = decodeKittingCsv(existingText.value.get())
    if not decoded.ok:
      printError("Decode existing kitting CSV failed", decoded.error)
      return 1
    existingRecords = decoded.value

    let verified = verifyExistingRecords(
      existingRecords,
      trustAnchors,
      intermediates
    )
    if not verified.ok:
      printError("Verify existing kitting CSV failed", verified.error)
      return 1
    existingVerified = verified.value

  let alreadyRegistered = findExistingVerifiedRecord(
    existingVerified,
    serial.value,
    profile
  )

  let objectExists = se.objectExists(profile.keyObjectId, selectFirst = false)
  if not objectExists.ok:
    printError("Check kitting key failed", objectExists.error)
    return 6

  let presence = validateKittingObjectPresenceForExport(
    existingRecordPresent = alreadyRegistered.isSome,
    objectExists = objectExists.value,
    serialNumber = serial.value,
    profile = profile
  )
  if not presence.ok:
    printError("Existing CSV record does not match this device", presence.error)
    return 5

  let keyCreated = ensureKittingKey(se, profile, objectExists.value)
  if not keyCreated.ok:
    printError(&"Prepare {profile.name} kitting key failed", keyCreated.error)
    return 1

  let liveType = se.readObjectType(profile.keyObjectId, selectFirst = false)
  if not liveType.ok:
    printError("Read live key type failed", liveType.error)
    return 6

  let livePublicKey = se.readPublicKey(profile.keyObjectId, selectFirst = false)
  if not livePublicKey.ok:
    printError("Read live public key failed", livePublicKey.error)
    return 6

  if alreadyRegistered.isSome:
    let local = verifyLocalKittingIdentity(
      verified = alreadyRegistered.get(),
      boardSerialNumber = serial.value,
      liveSe050Uid = liveUid,
      liveObjectType = liveType.value.objectType,
      liveTransientIndicator = liveType.value.transientIndicator,
      livePublicKey = livePublicKey.value
    )
    if not local.ok:
      printError("Existing CSV record does not match this device", local.error)
      return 5

    echo &"serialno: {serial.value}"
    echo &"profile: {profile.name}"
    echo &"key object id: 0x{profile.keyObjectId.toHex(8)}"
    echo "key created: no"
    echo "CSV record: already valid"
    echo &"CSV path: {csvPath}"
    return 0

  let createdAt = utcTimestamp()
  let nonce = se.getRandomBytes(KittingNonceLength, selectFirst = false)
  if not nonce.ok:
    printError("Generate kitting nonce failed", nonce.error)
    return 6

  let freshness = deriveKittingFreshness(
    serialNumber = serial.value,
    createdAt = createdAt,
    profile = profile,
    nonce = nonce.value
  )
  if not freshness.ok:
    printError("Derive kitting freshness failed", freshness.error)
    return 1

  let attested = se.readObjectWithAttestation(
    objectId = profile.keyObjectId,
    freshness = freshness.value,
    selectFirst = false
  )
  if not attested.ok:
    printError("Read key with Attestation failed", attested.error)
    return 6

  let record = createKittingRecord(
    serialNumber = serial.value,
    createdAt = createdAt,
    profile = profile,
    nonce = nonce.value,
    attestationCertificate = certificate.value,
    attested = attested.value
  )
  if not record.ok:
    printError("Create kitting record failed", record.error)
    return 1

  let verified = verifyKittingRecord(
    record.value,
    trustAnchors,
    intermediates
  )
  if not verified.ok:
    printError("Self-verification of kitting record failed", verified.error)
    return 1

  let local = verifyLocalKittingIdentity(
    verified = verified.value,
    boardSerialNumber = serial.value,
    liveSe050Uid = liveUid,
    liveObjectType = liveType.value.objectType,
    liveTransientIndicator = liveType.value.transientIndicator,
    livePublicKey = livePublicKey.value
  )
  if not local.ok:
    printError("Live-device verification failed", local.error)
    return 5

  let merged = mergeKittingRecord(existingRecords, record.value)
  if not merged.ok:
    printError("Merge kitting CSV failed", merged.error)
    return 1

  let csvText = encodeKittingCsv(merged.value.records)
  let written = writeCsvAtomic(csvPath, csvText)
  if not written.ok:
    printError("Write kitting CSV failed", written.error)
    return 2

  let reread = readOptionalCsv(csvPath)
  if not reread.ok or reread.value.isNone:
    if not reread.ok:
      printError("Re-read kitting CSV failed", reread.error)
    else:
      stderr.writeLine "Re-read kitting CSV failed: file disappeared after replacement"
    return 2

  let verifiedReread = verifyKittingCsvRecord(
    csvText = reread.value.get(),
    serialNumber = serial.value,
    profileKind = profile.kind,
    trustAnchorsDer = trustAnchors,
    intermediatesDer = intermediates,
    keyRole = profile.keyRole
  )
  if not verifiedReread.ok:
    printError("Post-write kitting CSV verification failed", verifiedReread.error)
    return 1

  let localReread = verifyLocalKittingIdentity(
    verified = verifiedReread.value,
    boardSerialNumber = serial.value,
    liveSe050Uid = liveUid,
    liveObjectType = liveType.value.objectType,
    liveTransientIndicator = liveType.value.transientIndicator,
    livePublicKey = livePublicKey.value
  )
  if not localReread.ok:
    printError("Post-write local-device verification failed", localReread.error)
    return 5

  echo &"serialno: {serial.value}"
  echo &"profile: {profile.name}"
  echo &"key object id: 0x{profile.keyObjectId.toHex(8)}"
  let keyCreatedText = if keyCreated.value: "yes" else: "no"
  echo &"key created: {keyCreatedText}"
  echo &"SE050 UID: {uidToHex(liveUid)}"
  echo &"CSV record count: {merged.value.recordCount}"
  echo "CSV record: added"
  echo &"CSV path: {csvPath}"
  echo "self-verification: valid"
  result = 0

# =============================================================================
# CLI
# =============================================================================

proc main(): int =
  var parser = newParser("se050-kitting-export"):
    help("Create an Attestation-backed SE050 kitting CSV record.")

    command("test"):
      help("Create or reuse the fixed disposable test key and append its record.")
      option("-b", "--bus", required = true, help = "I2C bus number")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address")
      option("--append", required = true, help = "Multi-device kitting CSV path")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runKittingExport(
          testKittingProfile(),
          opts.bus,
          opts.address,
          opts.append,
          opts.debug
        ))

    command("production"):
      help("Irreversibly create or reuse the fixed production key and append its record.")
      option("-b", "--bus", required = true, help = "I2C bus number")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address")
      option("--append", required = true, help = "Multi-device kitting CSV path")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runKittingExport(
          productionKittingProfile(),
          opts.bus,
          opts.address,
          opts.append,
          opts.debug
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
  except CatchableError:
    stderr.writeLine &"unexpected error: {getCurrentExceptionMsg()}"
    result = 1

when isMainModule:
  quit(main())
