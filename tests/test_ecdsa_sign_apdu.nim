import std/unittest

import se050_nim

suite "SE050 ECDSA/SHA-256 signing APDU":
  test "builds the ECDSASign request from a 32-byte digest":
    var digest: array[EcdsaSha256DigestLength, uint8]
    for i in 0 ..< digest.len:
      digest[i] = uint8(i)

    let request = buildEcdsaSignApdu(
      objectId = 0x30000130'u32,
      digest = digest
    )

    let expected = @[
      0x80'u8, 0x03'u8, 0x0C'u8, 0x09'u8, 0x2B'u8,
      0x41'u8, 0x04'u8,
      0x30'u8, 0x00'u8, 0x01'u8, 0x30'u8,
      0x42'u8, 0x01'u8, 0x21'u8,
      0x43'u8, 0x20'u8,
      0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8,
      0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
      0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8,
      0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
      0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8,
      0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8,
      0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8,
      0x1C'u8, 0x1D'u8, 0x1E'u8, 0x1F'u8,
      0x00'u8
    ]

    check request.ok
    check request.value == expected

  test "rejects a digest whose length does not match SHA-256":
    let tooShort = newSeq[uint8](EcdsaSha256DigestLength - 1)
    let tooLong = newSeq[uint8](EcdsaSha256DigestLength + 1)

    let shortRequest = buildEcdsaSignApdu(0x30000130'u32, tooShort)
    let longRequest = buildEcdsaSignApdu(0x30000130'u32, tooLong)

    check not shortRequest.ok
    check shortRequest.error.kind == seInvalidArgument
    check not longRequest.ok
    check longRequest.error.kind == seInvalidArgument

suite "SE050 development signing policy":
  test "adds signing without changing the existing ECDH development policy":
    check policyHeader(developmentEcKeyPolicy()) == 0x043C0000'u32
    check policyHeader(developmentSigningEcKeyPolicy()) == 0x103C0000'u32
