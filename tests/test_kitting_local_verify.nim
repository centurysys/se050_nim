import std/options
import std/strutils
import std/unittest

import se050_nim

proc testUid(): seq[uint8] =
  result = @[
    0x04'u8, 0x00'u8, 0x50'u8, 0x01'u8, 0xB1'u8, 0x0D'u8,
    0x3D'u8, 0x3F'u8, 0xA7'u8, 0x58'u8, 0x85'u8, 0x04'u8,
    0x27'u8, 0x19'u8, 0xD2'u8, 0x3E'u8, 0x1F'u8, 0x90'u8
  ]

proc testPublicKey(): seq[uint8] =
  result = newSeq[uint8](P256UncompressedPublicKeyLength)
  result[0] = 0x04'u8
  for index in 1 ..< result.len:
    result[index] = uint8(index)

proc verifiedRecord(): VerifiedKittingRecord =
  let profile = testKittingProfile()
  let publicKey = testPublicKey()
  result = VerifiedKittingRecord(
    record: KittingRecord(
      serialNumber: "11900000014",
      formatVersion: KittingCsvFormatVersion,
      profileKind: kpTest,
      createdAt: "2026-07-29T09:00:00Z",
      keyRole: KittingKeyRoleFirmwareKex,
      se050Uid: testUid(),
      keyObjectId: profile.keyObjectId,
      nonce: newSeq[uint8](KittingNonceLength),
      publicKey: publicKey
    ),
    semantics: KittingAttestationSemantics(
      profile: profile,
      attributes: AttestedObjectAttributes(
        objectId: profile.keyObjectId,
        objectType: profile.expectedKeyType(),
        origin: Se050ObjectOriginInternal
      ),
      objectSize: P256PrivateKeySizeBytes
    )
  )

suite "local kitting identity verification":
  test "accepts the matching board and live SE050 object":
    let verified = verifiedRecord()
    let checked = verifyLocalKittingIdentity(
      verified = verified,
      boardSerialNumber = "11900000014",
      liveSe050Uid = testUid(),
      liveObjectType = Se050TypeEcKeyPairNistP256,
      liveTransientIndicator = some(0x01'u8),
      livePublicKey = testPublicKey()
    )

    require checked.ok
    check checked.value.boardSerialNumber == "11900000014"
    check checked.value.liveSe050Uid == testUid()
    check checked.value.livePublicKey == testPublicKey()

  test "rejects a different board serial number":
    let checked = verifyLocalKittingIdentity(
      verified = verifiedRecord(),
      boardSerialNumber = "11900000015",
      liveSe050Uid = testUid(),
      liveObjectType = Se050TypeEcKeyPairNistP256,
      liveTransientIndicator = some(0x01'u8),
      livePublicKey = testPublicKey()
    )

    check not checked.ok
    check checked.error.kind == seKittingValidationFailed
    check checked.error.message.contains("board serial number")

  test "rejects a different live SE050 UID":
    var uid = testUid()
    uid[^1] = uid[^1] xor 0x01'u8
    let checked = verifyLocalKittingIdentity(
      verified = verifiedRecord(),
      boardSerialNumber = "11900000014",
      liveSe050Uid = uid,
      liveObjectType = Se050TypeEcKeyPairNistP256,
      liveTransientIndicator = some(0x01'u8),
      livePublicKey = testPublicKey()
    )

    check not checked.ok
    check checked.error.message.contains("SE050 UID")

  test "rejects a non-key-pair live object type":
    let checked = verifyLocalKittingIdentity(
      verified = verifiedRecord(),
      boardSerialNumber = "11900000014",
      liveSe050Uid = testUid(),
      liveObjectType = Se050TypeEcPubKeyNistP256,
      liveTransientIndicator = some(0x01'u8),
      livePublicKey = testPublicKey()
    )

    check not checked.ok
    check checked.error.message.contains("object type")

  test "rejects a transient live object":
    let checked = verifyLocalKittingIdentity(
      verified = verifiedRecord(),
      boardSerialNumber = "11900000014",
      liveSe050Uid = testUid(),
      liveObjectType = Se050TypeEcKeyPairNistP256,
      liveTransientIndicator = some(0x02'u8),
      livePublicKey = testPublicKey()
    )

    check not checked.ok
    check checked.error.message.contains("not persistent")

  test "rejects a changed live public key":
    var publicKey = testPublicKey()
    publicKey[^1] = publicKey[^1] xor 0x01'u8
    let checked = verifyLocalKittingIdentity(
      verified = verifiedRecord(),
      boardSerialNumber = "11900000014",
      liveSe050Uid = testUid(),
      liveObjectType = Se050TypeEcKeyPairNistP256,
      liveTransientIndicator = some(0x01'u8),
      livePublicKey = publicKey
    )

    check not checked.ok
    check checked.error.message.contains("public key")
