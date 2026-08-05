import std/unittest

import se050_nim

const
  P256GeneratorX = [
    0x6B'u8, 0x17'u8, 0xD1'u8, 0xF2'u8,
    0xE1'u8, 0x2C'u8, 0x42'u8, 0x47'u8,
    0xF8'u8, 0xBC'u8, 0xE6'u8, 0xE5'u8,
    0x63'u8, 0xA4'u8, 0x40'u8, 0xF2'u8,
    0x77'u8, 0x03'u8, 0x7D'u8, 0x81'u8,
    0x2D'u8, 0xEB'u8, 0x33'u8, 0xA0'u8,
    0xF4'u8, 0xA1'u8, 0x39'u8, 0x45'u8,
    0xD8'u8, 0x98'u8, 0xC2'u8, 0x96'u8
  ]

  P256GeneratorY = [
    0x4F'u8, 0xE3'u8, 0x42'u8, 0xE2'u8,
    0xFE'u8, 0x1A'u8, 0x7F'u8, 0x9B'u8,
    0x8E'u8, 0xE7'u8, 0xEB'u8, 0x4A'u8,
    0x7C'u8, 0x0F'u8, 0x9E'u8, 0x16'u8,
    0x2B'u8, 0xCE'u8, 0x33'u8, 0x57'u8,
    0x6B'u8, 0x31'u8, 0x5E'u8, 0xCE'u8,
    0xCB'u8, 0xB6'u8, 0x40'u8, 0x68'u8,
    0x37'u8, 0xBF'u8, 0x51'u8, 0xF5'u8
  ]

proc privateScalarOne(): array[Se050P256PrivateKeyLength, uint8] =
  result[^1] = 0x01'u8

proc generatorPublicKey(): array[Se050P256UncompressedPublicKeyLength, uint8] =
  result[0] = 0x04'u8
  for i in 0 ..< P256GeneratorX.len:
    result[1 + i] = P256GeneratorX[i]
    result[33 + i] = P256GeneratorY[i]

suite "SE050 P-256 external key import APDU":
  test "builds WriteECKey with both private and public key values":
    let privateKey = privateScalarOne()
    let publicKey = generatorPublicKey()

    let request = buildImportP256KeyPairApdu(
      objectId = TlsIdentityTestSlotAObjectId,
      privateKey = privateKey,
      publicKey = publicKey,
      policy = testTlsIdentityProfile(tisSlotA).keyPolicy()
    )

    var expected = @[
      0x80'u8, 0x01'u8, 0x61'u8, 0x00'u8, 0x79'u8,

      # TAG_POLICY: SIGN + READ + DELETE = 0x10240000
      0x11'u8, 0x09'u8,
      0x08'u8,
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
      0x10'u8, 0x24'u8, 0x00'u8, 0x00'u8,

      # TAG_1: object ID 0x30000200
      0x41'u8, 0x04'u8,
      0x30'u8, 0x00'u8, 0x02'u8, 0x00'u8,

      # TAG_2: NIST P-256
      0x42'u8, 0x01'u8, 0x03'u8,

      # TAG_3: private scalar = 1, padded to 32 bytes
      0x43'u8, 0x20'u8
    ]

    for b in privateKey:
      expected.add(b)

    expected.add(0x44'u8)
    expected.add(0x41'u8)
    for b in publicKey:
      expected.add(b)

    check request.ok
    check request.value == expected

  test "rejects private key values that are not exactly 32 bytes":
    let tooShort = newSeq[uint8](Se050P256PrivateKeyLength - 1)
    let publicKey = generatorPublicKey()

    let request = buildImportP256KeyPairApdu(
      objectId = TlsIdentityTestSlotAObjectId,
      privateKey = tooShort,
      publicKey = publicKey,
      policy = testTlsIdentityProfile(tisSlotA).keyPolicy()
    )

    check not request.ok
    check request.error.kind == seInvalidArgument

  test "rejects public key values that are not exactly 65 bytes":
    let privateKey = privateScalarOne()
    let tooShort = newSeq[uint8](Se050P256UncompressedPublicKeyLength - 1)

    let request = buildImportP256KeyPairApdu(
      objectId = TlsIdentityTestSlotAObjectId,
      privateKey = privateKey,
      publicKey = tooShort,
      policy = testTlsIdentityProfile(tisSlotA).keyPolicy()
    )

    check not request.ok
    check request.error.kind == seInvalidArgument

  test "rejects a compressed or otherwise non-uncompressed public key":
    let privateKey = privateScalarOne()
    var publicKey = generatorPublicKey()
    publicKey[0] = 0x02'u8

    let request = buildImportP256KeyPairApdu(
      objectId = TlsIdentityTestSlotAObjectId,
      privateKey = privateKey,
      publicKey = publicKey,
      policy = testTlsIdentityProfile(tisSlotA).keyPolicy()
    )

    check not request.ok
    check request.error.kind == seInvalidArgument
