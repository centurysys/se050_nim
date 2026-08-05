import std/unittest

import se050_nim

const
  P384GeneratorX = [
    0xAA'u8, 0x87'u8, 0xCA'u8, 0x22'u8, 0xBE'u8, 0x8B'u8, 0x05'u8, 0x37'u8,
    0x8E'u8, 0xB1'u8, 0xC7'u8, 0x1E'u8, 0xF3'u8, 0x20'u8, 0xAD'u8, 0x74'u8,
    0x6E'u8, 0x1D'u8, 0x3B'u8, 0x62'u8, 0x8B'u8, 0xA7'u8, 0x9B'u8, 0x98'u8,
    0x59'u8, 0xF7'u8, 0x41'u8, 0xE0'u8, 0x82'u8, 0x54'u8, 0x2A'u8, 0x38'u8,
    0x55'u8, 0x02'u8, 0xF2'u8, 0x5D'u8, 0xBF'u8, 0x55'u8, 0x29'u8, 0x6C'u8,
    0x3A'u8, 0x54'u8, 0x5E'u8, 0x38'u8, 0x72'u8, 0x76'u8, 0x0A'u8, 0xB7'u8
  ]

  P384GeneratorY = [
    0x36'u8, 0x17'u8, 0xDE'u8, 0x4A'u8, 0x96'u8, 0x26'u8, 0x2C'u8, 0x6F'u8,
    0x5D'u8, 0x9E'u8, 0x98'u8, 0xBF'u8, 0x92'u8, 0x92'u8, 0xDC'u8, 0x29'u8,
    0xF8'u8, 0xF4'u8, 0x1D'u8, 0xBD'u8, 0x28'u8, 0x9A'u8, 0x14'u8, 0x7C'u8,
    0xE9'u8, 0xDA'u8, 0x31'u8, 0x13'u8, 0xB5'u8, 0xF0'u8, 0xB8'u8, 0xC0'u8,
    0x0A'u8, 0x60'u8, 0xB1'u8, 0xCE'u8, 0x1D'u8, 0x7E'u8, 0x81'u8, 0x9D'u8,
    0x7A'u8, 0x43'u8, 0x1D'u8, 0x7C'u8, 0x90'u8, 0xEA'u8, 0x0E'u8, 0x5F'u8
  ]

proc privateScalarOne(): array[Se050P384PrivateKeyLength, uint8] =
  result[^1] = 0x01'u8

proc generatorPublicKey(): array[Se050P384UncompressedPublicKeyLength, uint8] =
  result[0] = 0x04'u8
  for i in 0 ..< P384GeneratorX.len:
    result[1 + i] = P384GeneratorX[i]
    result[49 + i] = P384GeneratorY[i]

suite "SE050 P-384 external key import APDU":
  test "builds WriteECKey with both private and public key values":
    let privateKey = privateScalarOne()
    let publicKey = generatorPublicKey()

    let request = buildImportP384KeyPairApdu(
      objectId = TlsIdentityTestSlotAObjectId,
      privateKey = privateKey,
      publicKey = publicKey,
      policy = testTlsIdentityProfile(tisSlotA).keyPolicy()
    )

    var expected = @[
      0x80'u8, 0x01'u8, 0x61'u8, 0x00'u8, 0xA9'u8,

      # TAG_POLICY: SIGN + READ + DELETE = 0x10240000
      0x11'u8, 0x09'u8,
      0x08'u8,
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
      0x10'u8, 0x24'u8, 0x00'u8, 0x00'u8,

      # TAG_1: object ID 0x30000200
      0x41'u8, 0x04'u8,
      0x30'u8, 0x00'u8, 0x02'u8, 0x00'u8,

      # TAG_2: NIST P-384
      0x42'u8, 0x01'u8, 0x04'u8,

      # TAG_3: private scalar = 1, padded to 48 bytes
      0x43'u8, 0x30'u8
    ]

    for b in privateKey:
      expected.add(b)

    # TAG_4: uncompressed public point, 97 bytes.
    expected.add(0x44'u8)
    expected.add(0x61'u8)
    for b in publicKey:
      expected.add(b)

    check request.ok
    check request.value == expected

  test "rejects private key values that are not exactly 48 bytes":
    let tooShort = newSeq[uint8](Se050P384PrivateKeyLength - 1)
    let publicKey = generatorPublicKey()

    let request = buildImportP384KeyPairApdu(
      objectId = TlsIdentityTestSlotAObjectId,
      privateKey = tooShort,
      publicKey = publicKey,
      policy = testTlsIdentityProfile(tisSlotA).keyPolicy()
    )

    check not request.ok
    check request.error.kind == seInvalidArgument

  test "rejects public key values that are not exactly 97 bytes":
    let privateKey = privateScalarOne()
    let tooShort = newSeq[uint8](Se050P384UncompressedPublicKeyLength - 1)

    let request = buildImportP384KeyPairApdu(
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
    publicKey[0] = 0x03'u8

    let request = buildImportP384KeyPairApdu(
      objectId = TlsIdentityTestSlotAObjectId,
      privateKey = privateKey,
      publicKey = publicKey,
      policy = testTlsIdentityProfile(tisSlotA).keyPolicy()
    )

    check not request.ok
    check request.error.kind == seInvalidArgument

  test "keeps the existing P-256 builder behavior":
    var privateKey: array[Se050P256PrivateKeyLength, uint8]
    privateKey[^1] = 0x01'u8
    var publicKey: array[Se050P256UncompressedPublicKeyLength, uint8]
    publicKey[0] = 0x04'u8

    let request = buildImportP256KeyPairApdu(
      objectId = TlsIdentityTestSlotAObjectId,
      privateKey = privateKey,
      publicKey = publicKey,
      policy = testTlsIdentityProfile(tisSlotA).keyPolicy()
    )

    check request.ok
    check request.value[4] == 0x79'u8
    check request.value[22 .. 24] == @[0x42'u8, 0x01'u8, 0x03'u8]
