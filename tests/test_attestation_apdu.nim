import std/unittest

import se050_nim

suite "SE050 ReadObject-with-Attestation APDU":
  test "builds the Applet 7.2 request in middleware order":
    var freshness: seq[uint8] = @[]
    for i in 0 ..< 16:
      freshness.add(uint8(i))

    let request = buildReadObjectWithAttestationRequest(
      objectId = 0x30000100'u32,
      freshness = freshness
    )

    let expectedSigned = @[
      0x80'u8, 0x22'u8, 0x00'u8, 0x00'u8,
      0x00'u8, 0x00'u8, 0x21'u8,

      0x41'u8, 0x04'u8,
      0x30'u8, 0x00'u8, 0x01'u8, 0x00'u8,

      0x45'u8, 0x04'u8,
      0xF0'u8, 0x00'u8, 0x00'u8, 0x12'u8,

      0x46'u8, 0x01'u8, 0x21'u8,

      0x47'u8, 0x10'u8,
      0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8,
      0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
      0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8,
      0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8
    ]

    check request.ok
    check request.value.objectId == 0x30000100'u32
    check request.value.attestationKeyId == Se050AttestationKeyObjectId
    check request.value.algorithm == Se050AttestationAlgorithmEcSha256
    check request.value.freshness == freshness
    check request.value.signedCommandApdu == expectedSigned
    check request.value.transmitApdu == expectedSigned & @[0x00'u8, 0x00'u8]

  test "encodes optional offset and length before attestation parameters":
    let freshness = @[0xA5'u8]

    let request = buildReadObjectWithAttestationRequest(
      objectId = 0x30000100'u32,
      freshness = freshness,
      offset = 0x1234'u16,
      length = 0x0041'u16
    )

    let expectedBody = @[
      0x41'u8, 0x04'u8,
      0x30'u8, 0x00'u8, 0x01'u8, 0x00'u8,
      0x42'u8, 0x02'u8, 0x12'u8, 0x34'u8,
      0x43'u8, 0x02'u8, 0x00'u8, 0x41'u8,
      0x45'u8, 0x04'u8,
      0xF0'u8, 0x00'u8, 0x00'u8, 0x12'u8,
      0x46'u8, 0x01'u8, 0x21'u8,
      0x47'u8, 0x01'u8, 0xA5'u8
    ]

    check request.ok
    check request.value.signedCommandApdu[0 .. 6] == @[
      0x80'u8, 0x22'u8, 0x00'u8, 0x00'u8,
      0x00'u8, 0x00'u8, uint8(expectedBody.len)
    ]
    check request.value.signedCommandApdu[7 .. ^1] == expectedBody

  test "rejects invalid request parameters":
    let oneByte = @[0x01'u8]
    let empty: seq[uint8] = @[]
    var tooLong = newSeq[uint8](17)

    check not buildReadObjectWithAttestationRequest(0'u32, oneByte).ok
    check not buildReadObjectWithAttestationRequest(
      0x30000100'u32,
      oneByte,
      attestationKeyId = 0'u32
    ).ok
    check not buildReadObjectWithAttestationRequest(
      0x30000100'u32,
      oneByte,
      algorithm = 0'u8
    ).ok
    check not buildReadObjectWithAttestationRequest(0x30000100'u32, empty).ok
    check not buildReadObjectWithAttestationRequest(0x30000100'u32, tooLong).ok
