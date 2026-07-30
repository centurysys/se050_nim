# =============================================================================
# Multi-device SE050 kitting CSV
# =============================================================================

import std/options
import std/strformat
import std/strutils

import ./errors
import ./binary_encoding
import ./kitting_profile
import ./kitting_record

const
  KittingCsvHeader* = [
    "serialno",
    "format_version",
    "profile",
    "created_at",
    "key_role",
    "se050_uid",
    "key_object_id",
    "nonce",
    "public_key",
    "attestation_cert",
    "attestation"
  ]

proc encodeCsvField(value: string): string =
  var needsQuotes = false
  for c in value:
    if c in {',', '"', '\r', '\n'}:
      needsQuotes = true
      break

  if not needsQuotes:
    return value

  result.add('"')
  for c in value:
    if c == '"':
      result.add("\"\"")
    else:
      result.add(c)
  result.add('"')

proc encodeCsvRow(fields: openArray[string]): string =
  for i, field in fields:
    if i > 0:
      result.add(',')
    result.add(encodeCsvField(field))
  result.add('\n')

proc parseCsvRows(text: string): SE[seq[seq[string]]] =
  var row: seq[string] = @[]
  var field = ""
  var index = 0
  var inQuotes = false
  var afterQuote = false

  template finishField() =
    row.add(field)
    field.setLen(0)
    afterQuote = false

  template finishRow() =
    finishField()
    result.value.add(row)
    row = @[]

  while index < text.len:
    let c = text[index]

    if inQuotes:
      if c == '"':
        if index + 1 < text.len and text[index + 1] == '"':
          field.add('"')
          index += 2
          continue
        inQuotes = false
        afterQuote = true
      else:
        field.add(c)
      inc index
      continue

    if afterQuote:
      case c
      of ',':
        finishField()
      of '\r':
        finishRow()
        if index + 1 < text.len and text[index + 1] == '\n':
          inc index
      of '\n':
        finishRow()
      else:
        return fail[seq[seq[string]]](
          seInvalidResponse,
          "CSV contains data after a closing quote"
        )
      inc index
      continue

    case c
    of '"':
      if field.len != 0:
        return fail[seq[seq[string]]](
          seInvalidResponse,
          "CSV quote must start at the beginning of a field"
        )
      inQuotes = true
    of ',':
      finishField()
    of '\r':
      finishRow()
      if index + 1 < text.len and text[index + 1] == '\n':
        inc index
    of '\n':
      finishRow()
    else:
      field.add(c)
    inc index

  if inQuotes:
    return fail[seq[seq[string]]](
      seInvalidResponse,
      "CSV contains an unterminated quoted field"
    )

  if afterQuote or field.len > 0 or row.len > 0:
    finishRow()

  result.ok = true

proc parseDecimalU16(value: string): Option[uint16] =
  if value.len == 0:
    return none(uint16)

  var parsed: uint32 = 0
  for c in value:
    if c < '0' or c > '9':
      return none(uint16)
    parsed = parsed * 10'u32 + uint32(ord(c) - ord('0'))
    if parsed > uint32(uint16.high):
      return none(uint16)

  result = some(uint16(parsed))

proc parseHexObjectId(value: string): Option[uint32] =
  if value.len != 10 or value[0] != '0' or value[1] notin {'x', 'X'}:
    return none(uint32)

  var parsed: uint32 = 0
  for i in 2 ..< value.len:
    let c = value[i]
    var digit: int
    case c
    of '0' .. '9': digit = ord(c) - ord('0')
    of 'a' .. 'f': digit = ord(c) - ord('a') + 10
    of 'A' .. 'F': digit = ord(c) - ord('A') + 10
    else: return none(uint32)
    parsed = (parsed shl 4) or uint32(digit)

  result = some(parsed)

proc decodeBinaryField(value, fieldName: string): SE[seq[uint8]] =
  let decoded = decodeBase64(value)
  if not decoded.ok:
    return fail[seq[uint8]](
      decoded.error.kind,
      fieldName & ": " & decoded.error.message,
      decoded.error.sw
    )
  result = decoded

proc encodeKittingCsv*(records: openArray[KittingRecord]): string =
  ## Encodes one header and any number of device records.
  result.add(encodeCsvRow(KittingCsvHeader))
  for record in records:
    let profile = record.profile()
    result.add(encodeCsvRow([
      record.serialNumber,
      $record.formatVersion,
      profile.name,
      record.createdAt,
      record.keyRole,
      encodeBase64(record.se050Uid),
      "0x" & record.keyObjectId.toHex(8),
      encodeBase64(record.nonce),
      encodeBase64(record.publicKey),
      encodeBase64(record.attestationCertificate),
      encodeBase64(record.attestationContainer)
    ]))

proc decodeKittingCsv*(text: string): SE[seq[KittingRecord]] =
  ## Decodes and structurally validates all records in a kitting CSV.
  let rows = parseCsvRows(text)
  if not rows.ok:
    return fail[seq[KittingRecord]](
      rows.error.kind,
      rows.error.message,
      rows.error.sw
    )

  if rows.value.len == 0:
    return fail[seq[KittingRecord]](
      seInvalidResponse,
      "kitting CSV is empty"
    )

  if rows.value[0].len != KittingCsvHeader.len:
    return fail[seq[KittingRecord]](
      seInvalidResponse,
      "kitting CSV header column count is invalid"
    )

  for i in 0 ..< KittingCsvHeader.len:
    if rows.value[0][i] != KittingCsvHeader[i]:
      return fail[seq[KittingRecord]](
        seInvalidResponse,
        &"kitting CSV header column {i + 1} must be {KittingCsvHeader[i]}"
      )

  for rowIndex in 1 ..< rows.value.len:
    let row = rows.value[rowIndex]
    if row.len != KittingCsvHeader.len:
      return fail[seq[KittingRecord]](
        seInvalidResponse,
        &"kitting CSV row {rowIndex + 1} has {row.len} columns; expected {KittingCsvHeader.len}"
      )

    let formatVersion = parseDecimalU16(row[1])
    if formatVersion.isNone:
      return fail[seq[KittingRecord]](
        seInvalidResponse,
        &"kitting CSV row {rowIndex + 1} has an invalid format_version"
      )

    let profile = kittingProfileForName(row[2])
    if profile.isNone:
      return fail[seq[KittingRecord]](
        seInvalidResponse,
        &"kitting CSV row {rowIndex + 1} has an unknown profile"
      )

    let objectId = parseHexObjectId(row[6])
    if objectId.isNone:
      return fail[seq[KittingRecord]](
        seInvalidResponse,
        &"kitting CSV row {rowIndex + 1} has an invalid key_object_id"
      )

    let uid = decodeBinaryField(row[5], "se050_uid")
    if not uid.ok:
      return fail[seq[KittingRecord]](uid.error.kind, uid.error.message, uid.error.sw)

    let nonce = decodeBinaryField(row[7], "nonce")
    if not nonce.ok:
      return fail[seq[KittingRecord]](nonce.error.kind, nonce.error.message, nonce.error.sw)

    let publicKey = decodeBinaryField(row[8], "public_key")
    if not publicKey.ok:
      return fail[seq[KittingRecord]](
        publicKey.error.kind,
        publicKey.error.message,
        publicKey.error.sw
      )

    let certificate = decodeBinaryField(row[9], "attestation_cert")
    if not certificate.ok:
      return fail[seq[KittingRecord]](
        certificate.error.kind,
        certificate.error.message,
        certificate.error.sw
      )

    let attestation = decodeBinaryField(row[10], "attestation")
    if not attestation.ok:
      return fail[seq[KittingRecord]](
        attestation.error.kind,
        attestation.error.message,
        attestation.error.sw
      )

    let record = KittingRecord(
      serialNumber: row[0],
      formatVersion: formatVersion.get(),
      profileKind: profile.get().kind,
      createdAt: row[3],
      keyRole: row[4],
      se050Uid: uid.value,
      keyObjectId: objectId.get(),
      nonce: nonce.value,
      publicKey: publicKey.value,
      attestationCertificate: certificate.value,
      attestationContainer: attestation.value
    )

    let restored = restoreKittingAttestation(record)
    if not restored.ok:
      return fail[seq[KittingRecord]](
        restored.error.kind,
        &"kitting CSV row {rowIndex + 1}: {restored.error.message}",
        restored.error.sw
      )

    for existing in result.value:
      if existing.serialNumber == record.serialNumber and
          existing.profileKind == record.profileKind and
          existing.keyRole == record.keyRole:
        return fail[seq[KittingRecord]](
          seInvalidResponse,
          &"duplicate kitting CSV record for serial {record.serialNumber}, profile {profile.get().name}, role {record.keyRole}"
        )

    result.value.add(record)

  result.ok = true

proc findKittingRecord*(
    records: openArray[KittingRecord],
    serialNumber: string,
    profileKind: KittingProfileKind,
    keyRole: string = KittingKeyRoleFirmwareKex
): SE[KittingRecord] =
  ## Finds exactly one record for the local board and selected profile.
  var found = false
  for record in records:
    if record.serialNumber == serialNumber and
        record.profileKind == profileKind and
        record.keyRole == keyRole:
      if found:
        return fail[KittingRecord](
          seInvalidResponse,
          "multiple matching kitting CSV records were found"
        )
      result.value = record
      found = true

  if not found:
    return fail[KittingRecord](
      seInvalidResponse,
      "matching kitting CSV record was not found"
    )

  result.ok = true
