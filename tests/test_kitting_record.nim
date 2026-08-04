import std/unittest

import se050_nim/attestation
import se050_nim/kitting/profile
import se050_nim/kitting/record

proc addTlv(data: var seq[uint8], tag: uint8, value: openArray[uint8]) =
  doAssert value.len < 0x80
  data.add(tag)
  data.add(uint8(value.len))
  data.add(value)

proc makeAttested(
    profile: KittingProfile,
    freshness: openArray[uint8]
): AttestedObjectRead =
  let request = buildReadObjectWithAttestationRequest(
    objectId = profile.keyObjectId,
    freshness = freshness
  )
  doAssert request.ok

  var publicKey = newSeq[uint8](65)
  publicKey[0] = 0x04'u8
  for i in 1 ..< publicKey.len:
    publicKey[i] = uint8(i)

  var uid = newSeq[uint8](18)
  for i in 0 ..< uid.len:
    uid[i] = uint8(0x20 + i)

  var timestamp = newSeq[uint8](12)
  for i in 0 ..< timestamp.len:
    timestamp[i] = uint8(i)

  var responseData: seq[uint8] = @[]
  responseData.addTlv(0x41'u8, publicKey)
  responseData.addTlv(0x42'u8, uid)
  responseData.addTlv(0x43'u8, @[0x01'u8])
  responseData.addTlv(0x44'u8, @[0x00'u8, 0x20'u8])
  responseData.addTlv(0x4F'u8, timestamp)
  responseData.addTlv(0x52'u8, @[0x30'u8, 0x00'u8])

  var responseWithStatus = responseData
  responseWithStatus.add(0x90'u8)
  responseWithStatus.add(0x00'u8)
  let response = parseReadObjectWithAttestationResponse(responseWithStatus)
  doAssert response.ok

  result = AttestedObjectRead(request: request.value, response: response.value)

suite "kitting record":
  test "derives deterministic metadata-bound freshness":
    let nonce = @[0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    let freshness = deriveKittingFreshness(
      serialNumber = "11900000014",
      createdAt = "2026-07-29T08:00:00Z",
      profile = testKittingProfile(),
      nonce = nonce
    )

    check freshness.ok
    check freshness.value == @[
      0x6D'u8, 0x11, 0x00, 0x1B, 0xF1, 0xA8, 0x79, 0x63,
      0x20, 0xA2, 0x5C, 0x15, 0x76, 0x77, 0x83, 0x6B
    ]

    let changed = deriveKittingFreshness(
      serialNumber = "11900000015",
      createdAt = "2026-07-29T08:00:00Z",
      profile = testKittingProfile(),
      nonce = nonce
    )
    check changed.ok
    check changed.value != freshness.value

  test "round-trips an attestation container":
    let nonce = newSeq[uint8](16)
    let freshness = deriveKittingFreshness(
      "11900000014",
      "2026-07-29T08:00:00Z",
      testKittingProfile(),
      nonce
    )
    check freshness.ok

    let original = makeAttested(testKittingProfile(), freshness.value)
    let encoded = encodeAttestationContainer(original)
    check encoded.ok

    let decoded = decodeAttestationContainer(
      encoded.value,
      testKittingProfile().keyObjectId,
      freshness.value
    )
    check decoded.ok
    check decoded.value.request.signedCommandApdu == original.request.signedCommandApdu
    check decoded.value.response.rawResponseData == original.response.rawResponseData

    var tampered = encoded.value
    tampered[12] = tampered[12] xor 0x01'u8
    check not decodeAttestationContainer(
      tampered,
      testKittingProfile().keyObjectId,
      freshness.value
    ).ok

  test "creates and restores a self-consistent record":
    let nonce = @[0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    let freshness = deriveKittingFreshness(
      "11900000014",
      "2026-07-29T08:00:00Z",
      testKittingProfile(),
      nonce
    )
    check freshness.ok

    let attested = makeAttested(testKittingProfile(), freshness.value)
    let certificate = @[0x30'u8, 0x03, 0x02, 0x01, 0x01]
    let record = createKittingRecord(
      serialNumber = "11900000014",
      createdAt = "2026-07-29T08:00:00Z",
      profile = testKittingProfile(),
      nonce = nonce,
      attestationCertificate = certificate,
      attested = attested
    )

    check record.ok
    let restored = restoreKittingAttestation(record.value)
    check restored.ok
    check restored.value.response.objectData == record.value.publicKey
    check restored.value.response.chipId == record.value.se050Uid

  test "validates canonical UTC timestamps":
    check validateKittingTimestamp("2024-02-29T23:59:59Z").ok
    check not validateKittingTimestamp("2025-02-29T23:59:59Z").ok
    check not validateKittingTimestamp("2026-07-29 08:00:00Z").ok
    check not validateKittingTimestamp("2026-07-29T08:00:60Z").ok
