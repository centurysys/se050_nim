# =============================================================================
# SE050 kitting record and attestation container
# =============================================================================

import std/strformat

import ../errors
import ../uid
import ../crypto_verify
import ../attestation/cert
import ../attestation/read
import ./profile
import ./board_identity

const
  KittingFreshnessDomain = "SE050-KITTING-FRESHNESS-V1"
  KittingAttestationContainerVersion* = 1'u16
  KittingAttestationContainerHeaderLength = 12
  KittingAttestationContainerMagic = [
    0x53'u8, 0x35'u8, 0x41'u8, 0x54'u8 # "S5AT"
  ]

  P256PublicKeyLength = 65


type
  KittingRecord* = object
    serialNumber*: string
    formatVersion*: uint16
    profileKind*: KittingProfileKind
    createdAt*: string
    keyRole*: string
    se050Uid*: seq[uint8]
    keyObjectId*: uint32
    nonce*: seq[uint8]
    publicKey*: seq[uint8]
    attestationCertificate*: seq[uint8]
    attestationContainer*: seq[uint8]

proc appendU16Be(buf: var seq[uint8], value: uint16) =
  buf.add(uint8((value shr 8) and 0xFF))
  buf.add(uint8(value and 0xFF))

proc appendU32Be(buf: var seq[uint8], value: uint32) =
  buf.add(uint8((value shr 24) and 0xFF))
  buf.add(uint8((value shr 16) and 0xFF))
  buf.add(uint8((value shr 8) and 0xFF))
  buf.add(uint8(value and 0xFF))

proc readU16Be(data: openArray[uint8], index: int): uint16 =
  result = (uint16(data[index]) shl 8) or uint16(data[index + 1])

proc readU32Be(data: openArray[uint8], index: int): uint32 =
  result =
    (uint32(data[index]) shl 24) or
    (uint32(data[index + 1]) shl 16) or
    (uint32(data[index + 2]) shl 8) or
    uint32(data[index + 3])

proc appendStringField(buf: var seq[uint8], value: string): SE[void] =
  if value.len > int(uint16.high):
    return fail[void](
      seInvalidArgument,
      "kitting freshness string field is too long"
    )

  buf.appendU16Be(uint16(value.len))
  for c in value:
    buf.add(uint8(ord(c)))
  result = ok()

proc appendByteField(buf: var seq[uint8], value: openArray[uint8]): SE[void] =
  if value.len > int(uint16.high):
    return fail[void](
      seInvalidArgument,
      "kitting freshness byte field is too long"
    )

  buf.appendU16Be(uint16(value.len))
  buf.add(value)
  result = ok()

proc parseFixedDecimal(value: string, startIndex, length: int): int =
  result = 0
  for i in 0 ..< length:
    let c = value[startIndex + i]
    if c < '0' or c > '9':
      return -1
    result = result * 10 + ord(c) - ord('0')

proc isLeapYear(year: int): bool =
  result = (year mod 4 == 0) and ((year mod 100 != 0) or (year mod 400 == 0))

proc validateKittingTimestamp*(value: string): SE[void] =
  ## Requires the canonical UTC form YYYY-MM-DDTHH:MM:SSZ.
  if value.len != 20 or
      value[4] != '-' or value[7] != '-' or value[10] != 'T' or
      value[13] != ':' or value[16] != ':' or value[19] != 'Z':
    return fail[void](
      seInvalidArgument,
      "kitting timestamp must use YYYY-MM-DDTHH:MM:SSZ"
    )

  let year = parseFixedDecimal(value, 0, 4)
  let month = parseFixedDecimal(value, 5, 2)
  let day = parseFixedDecimal(value, 8, 2)
  let hour = parseFixedDecimal(value, 11, 2)
  let minute = parseFixedDecimal(value, 14, 2)
  let second = parseFixedDecimal(value, 17, 2)

  if year < 1 or month < 1 or month > 12 or hour < 0 or hour > 23 or
      minute < 0 or minute > 59 or second < 0 or second > 59:
    return fail[void](
      seInvalidArgument,
      "kitting timestamp contains an out-of-range component"
    )

  let daysPerMonth = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  var maxDay = daysPerMonth[month - 1]
  if month == 2 and isLeapYear(year):
    maxDay = 29

  if day < 1 or day > maxDay:
    return fail[void](
      seInvalidArgument,
      "kitting timestamp contains an invalid calendar date"
    )

  result = ok()

proc deriveKittingFreshness*(
    serialNumber: string,
    createdAt: string,
    profile: KittingProfile,
    nonce: openArray[uint8]
): SE[seq[uint8]] =
  ## Derives the 16-byte SE050 freshness value from canonical record metadata.
  let serial = parseBoardSerialNumber(serialNumber)
  if not serial.ok:
    return fail[seq[uint8]](
      serial.error.kind,
      serial.error.message,
      serial.error.sw
    )

  if serial.value != serialNumber:
    return fail[seq[uint8]](
      seInvalidArgument,
      "kitting serial number must already be in canonical digit-only form"
    )

  let timestamp = validateKittingTimestamp(createdAt)
  if not timestamp.ok:
    return fail[seq[uint8]](
      timestamp.error.kind,
      timestamp.error.message,
      timestamp.error.sw
    )

  if not profile.isValid():
    return fail[seq[uint8]](
      seInvalidArgument,
      "kitting profile is invalid"
    )

  if nonce.len != KittingNonceLength:
    return fail[seq[uint8]](
      seInvalidArgument,
      &"kitting nonce must be {KittingNonceLength} bytes"
    )

  var canonical: seq[uint8] = @[]
  for c in KittingFreshnessDomain:
    canonical.add(uint8(ord(c)))
  canonical.appendU16Be(KittingCsvFormatVersion)

  for value in [serial.value, profile.name, createdAt, profile.keyRole]:
    let added = canonical.appendStringField(value)
    if not added.ok:
      return fail[seq[uint8]](
        added.error.kind,
        added.error.message,
        added.error.sw
      )

  canonical.appendU32Be(profile.keyObjectId)
  let nonceAdded = canonical.appendByteField(nonce)
  if not nonceAdded.ok:
    return fail[seq[uint8]](
      nonceAdded.error.kind,
      nonceAdded.error.message,
      nonceAdded.error.sw
    )

  let digest = sha256(canonical)
  if not digest.ok:
    return fail[seq[uint8]](
      digest.error.kind,
      digest.error.message,
      digest.error.sw
    )

  result.value = newSeq[uint8](KittingFreshnessLength)
  for i in 0 ..< KittingFreshnessLength:
    result.value[i] = digest.value[i]
  result.ok = true

proc encodeAttestationContainer*(
    attested: AttestedObjectRead
): SE[seq[uint8]] =
  ## Stores the exact signed command and raw response TLVs.
  let commandLength = attested.request.signedCommandApdu.len
  let responseLength = attested.response.rawResponseData.len

  if commandLength == 0 or commandLength > int(uint16.high):
    return fail[seq[uint8]](
      seInvalidArgument,
      "attestation signed command length is invalid"
    )

  if responseLength == 0 or uint64(responseLength) > uint64(uint32.high):
    return fail[seq[uint8]](
      seInvalidArgument,
      "attestation response length is invalid"
    )

  result.value.add(KittingAttestationContainerMagic)
  result.value.appendU16Be(KittingAttestationContainerVersion)
  result.value.appendU16Be(uint16(commandLength))
  result.value.appendU32Be(uint32(responseLength))
  result.value.add(attested.request.signedCommandApdu)
  result.value.add(attested.response.rawResponseData)
  result.ok = true

proc decodeAttestationContainer*(
    container: openArray[uint8],
    objectId: uint32,
    freshness: openArray[uint8]
): SE[AttestedObjectRead] =
  ## Restores and structurally validates an attestation capture.
  if container.len < KittingAttestationContainerHeaderLength:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      "attestation container is truncated"
    )

  for i in 0 ..< KittingAttestationContainerMagic.len:
    if container[i] != KittingAttestationContainerMagic[i]:
      return fail[AttestedObjectRead](
        seInvalidResponse,
        "attestation container magic is invalid"
      )

  let version = readU16Be(container, 4)
  if version != KittingAttestationContainerVersion:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      &"unsupported attestation container version {version}"
    )

  let commandLength = int(readU16Be(container, 6))
  let responseLength = int(readU32Be(container, 8))
  let expectedLength = KittingAttestationContainerHeaderLength +
    commandLength + responseLength

  if commandLength == 0 or responseLength == 0 or expectedLength != container.len:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      "attestation container length fields are invalid"
    )

  let commandStart = KittingAttestationContainerHeaderLength
  let responseStart = commandStart + commandLength
  let storedCommand = @container[commandStart ..< responseStart]
  let storedResponse = @container[responseStart ..< container.len]

  let request = buildReadObjectWithAttestationRequest(
    objectId = objectId,
    freshness = freshness
  )
  if not request.ok:
    return fail[AttestedObjectRead](
      request.error.kind,
      request.error.message,
      request.error.sw
    )

  if storedCommand != request.value.signedCommandApdu:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      "attestation container command does not match record metadata"
    )

  var responseWithStatus = storedResponse
  responseWithStatus.add(0x90'u8)
  responseWithStatus.add(0x00'u8)
  let response = parseReadObjectWithAttestationResponse(responseWithStatus)
  if not response.ok:
    return fail[AttestedObjectRead](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = ok(AttestedObjectRead(
    request: request.value,
    response: response.value
  ))

proc profile*(record: KittingRecord): KittingProfile =
  result = kittingProfile(record.profileKind)

proc restoreKittingAttestation*(
    record: KittingRecord
): SE[AttestedObjectRead] =
  ## Recomputes freshness, restores the attestation, and cross-checks CSV fields.
  let profile = record.profile()

  if record.formatVersion != KittingCsvFormatVersion:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      &"unsupported kitting CSV format version {record.formatVersion}"
    )

  let serial = parseBoardSerialNumber(record.serialNumber)
  if not serial.ok:
    return fail[AttestedObjectRead](
      serial.error.kind,
      serial.error.message,
      serial.error.sw
    )

  let timestamp = validateKittingTimestamp(record.createdAt)
  if not timestamp.ok:
    return fail[AttestedObjectRead](
      timestamp.error.kind,
      timestamp.error.message,
      timestamp.error.sw
    )

  if record.keyRole != profile.keyRole:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      "kitting key role does not match the selected profile"
    )

  if record.keyObjectId != profile.keyObjectId:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      "kitting key object ID does not match the selected profile"
    )

  if record.nonce.len != KittingNonceLength:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      &"kitting nonce must be {KittingNonceLength} bytes"
    )

  if record.se050Uid.len != Se050UidLength:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      &"kitting SE050 UID must be {Se050UidLength} bytes"
    )

  if record.publicKey.len != P256PublicKeyLength or record.publicKey[0] != 0x04'u8:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      "kitting public key is not an uncompressed P-256 point"
    )

  let certificate = validateAttestationCertificateDer(record.attestationCertificate)
  if not certificate.ok:
    return fail[AttestedObjectRead](
      certificate.error.kind,
      certificate.error.message,
      certificate.error.sw
    )

  let freshness = deriveKittingFreshness(
    serialNumber = record.serialNumber,
    createdAt = record.createdAt,
    profile = profile,
    nonce = record.nonce
  )
  if not freshness.ok:
    return fail[AttestedObjectRead](
      freshness.error.kind,
      freshness.error.message,
      freshness.error.sw
    )

  let attested = decodeAttestationContainer(
    container = record.attestationContainer,
    objectId = record.keyObjectId,
    freshness = freshness.value
  )
  if not attested.ok:
    return attested

  if not attested.value.response.objectDataPresent or
      attested.value.response.objectData != record.publicKey:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      "CSV public key does not match the attested public key"
    )

  if attested.value.response.chipId != record.se050Uid:
    return fail[AttestedObjectRead](
      seInvalidResponse,
      "CSV SE050 UID does not match the attested chip UID"
    )

  result = attested

proc createKittingRecord*(
    serialNumber: string,
    createdAt: string,
    profile: KittingProfile,
    nonce: openArray[uint8],
    attestationCertificate: openArray[uint8],
    attested: AttestedObjectRead
): SE[KittingRecord] =
  ## Creates a structurally self-consistent record after live verification.
  ## The caller must perform certificate-chain, signature, and semantic checks
  ## before treating the returned record as trusted.
  let freshness = deriveKittingFreshness(
    serialNumber = serialNumber,
    createdAt = createdAt,
    profile = profile,
    nonce = nonce
  )
  if not freshness.ok:
    return fail[KittingRecord](
      freshness.error.kind,
      freshness.error.message,
      freshness.error.sw
    )

  if attested.request.objectId != profile.keyObjectId or
      attested.request.freshness != freshness.value:
    return fail[KittingRecord](
      seInvalidResponse,
      "attestation request does not match kitting record metadata"
    )

  if not attested.response.objectDataPresent:
    return fail[KittingRecord](
      seInvalidResponse,
      "attestation response does not contain the kitting public key"
    )

  let certificate = validateAttestationCertificateDer(attestationCertificate)
  if not certificate.ok:
    return fail[KittingRecord](
      certificate.error.kind,
      certificate.error.message,
      certificate.error.sw
    )

  let container = encodeAttestationContainer(attested)
  if not container.ok:
    return fail[KittingRecord](
      container.error.kind,
      container.error.message,
      container.error.sw
    )

  var nonceCopy: seq[uint8] = @[]
  nonceCopy.add(nonce)
  var certificateCopy: seq[uint8] = @[]
  certificateCopy.add(attestationCertificate)

  let record = KittingRecord(
    serialNumber: serialNumber,
    formatVersion: KittingCsvFormatVersion,
    profileKind: profile.kind,
    createdAt: createdAt,
    keyRole: profile.keyRole,
    se050Uid: attested.response.chipId,
    keyObjectId: profile.keyObjectId,
    nonce: nonceCopy,
    publicKey: attested.response.objectData,
    attestationCertificate: certificateCopy,
    attestationContainer: container.value
  )

  let restored = restoreKittingAttestation(record)
  if not restored.ok:
    return fail[KittingRecord](
      restored.error.kind,
      restored.error.message,
      restored.error.sw
    )

  result = ok(record)
