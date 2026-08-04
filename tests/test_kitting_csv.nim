import std/unittest
import std/strutils

import se050_nim/attestation
import se050_nim/kitting/profile
import se050_nim/kitting/record
import se050_nim/kitting/csv

proc addTlv(data: var seq[uint8], tag: uint8, value: openArray[uint8]) =
  doAssert value.len < 0x80
  data.add(tag)
  data.add(uint8(value.len))
  data.add(value)

proc makeRecord(serialNumber: string, seed: uint8): KittingRecord =
  let profile = testKittingProfile()
  var nonce = newSeq[uint8](16)
  for i in 0 ..< nonce.len:
    nonce[i] = seed + uint8(i)

  let freshness = deriveKittingFreshness(
    serialNumber,
    "2026-07-29T08:00:00Z",
    profile,
    nonce
  )
  doAssert freshness.ok

  let request = buildReadObjectWithAttestationRequest(
    profile.keyObjectId,
    freshness.value
  )
  doAssert request.ok

  var publicKey = newSeq[uint8](65)
  publicKey[0] = 0x04'u8
  for i in 1 ..< publicKey.len:
    publicKey[i] = seed + uint8(i)

  var uid = newSeq[uint8](18)
  for i in 0 ..< uid.len:
    uid[i] = seed + uint8(i)

  var responseData: seq[uint8] = @[]
  responseData.addTlv(0x41'u8, publicKey)
  responseData.addTlv(0x42'u8, uid)
  responseData.addTlv(0x43'u8, @[0x01'u8])
  responseData.addTlv(0x44'u8, @[0x00'u8, 0x20'u8])
  responseData.addTlv(0x4F'u8, newSeq[uint8](12))
  responseData.addTlv(0x52'u8, @[0x30'u8, 0x00'u8])

  var responseWithStatus = responseData
  responseWithStatus.add(0x90'u8)
  responseWithStatus.add(0x00'u8)
  let response = parseReadObjectWithAttestationResponse(responseWithStatus)
  doAssert response.ok

  let record = createKittingRecord(
    serialNumber,
    "2026-07-29T08:00:00Z",
    profile,
    nonce,
    @[0x30'u8, 0x03, 0x02, 0x01, 0x01],
    AttestedObjectRead(request: request.value, response: response.value)
  )
  doAssert record.ok
  result = record.value

suite "multi-device kitting CSV":
  test "places serialno first and round-trips multiple records":
    let first = makeRecord("11900000014", 0x10'u8)
    let second = makeRecord("11900000015", 0x40'u8)
    let csv = encodeKittingCsv([first, second])

    check csv.startsWith("serialno,format_version,profile,")

    let decoded = decodeKittingCsv(csv)
    check decoded.ok
    check decoded.value.len == 2
    check decoded.value[0].serialNumber == "11900000014"
    check decoded.value[1].serialNumber == "11900000015"
    check decoded.value[1].publicKey == second.publicKey

    let found = findKittingRecord(decoded.value, "11900000015", kpTest)
    check found.ok
    check found.value.se050Uid == second.se050Uid

  test "rejects serial-number substitution":
    let record = makeRecord("11900000014", 0x10'u8)
    var csv = encodeKittingCsv([record])
    csv = csv.replace("11900000014", "11900000099")
    check not decodeKittingCsv(csv).ok

  test "rejects duplicate serial/profile/role records":
    let record = makeRecord("11900000014", 0x10'u8)
    let csv = encodeKittingCsv([record, record])
    check not decodeKittingCsv(csv).ok

  test "rejects a modified header":
    let record = makeRecord("11900000014", 0x10'u8)
    var csv = encodeKittingCsv([record])
    csv = csv.replace("serialno", "serial")
    check not decodeKittingCsv(csv).ok
