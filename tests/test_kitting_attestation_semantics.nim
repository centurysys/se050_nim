import std/strutils
import std/unittest

import se050_nim

proc appendU16Be(data: var seq[uint8], value: uint16) =
  data.add(uint8((value shr 8) and 0xFF))
  data.add(uint8(value and 0xFF))

proc appendU32Be(data: var seq[uint8], value: uint32) =
  data.add(uint8((value shr 24) and 0xFF))
  data.add(uint8((value shr 16) and 0xFF))
  data.add(uint8((value shr 8) and 0xFF))
  data.add(uint8(value and 0xFF))

proc attributesFor(profile: KittingProfile): seq[uint8] =
  result.appendU32Be(profile.keyObjectId)
  result.add(profile.expectedKeyType())
  result.add(Se050SetIndicatorNotSet)
  result.appendU16Be(0'u16)
  result.appendU32Be(0'u32)
  result.appendU16Be(0'u16)
  result.add(0x08'u8)
  result.appendU32Be(0'u32)
  result.appendU32Be(policyHeader(profile.keyPolicy()))
  result.add(Se050ObjectOriginInternal)
  result.appendU32Be(1'u32)

proc validAttestedObject(profile: KittingProfile): AttestedObjectRead =
  var publicKey = @[0x04'u8]
  for i in 0 ..< 64:
    publicKey.add(uint8(i))

  var chipId: seq[uint8] = @[]
  for i in 0 ..< Se050UidLength:
    chipId.add(uint8(i))

  result = AttestedObjectRead(
    request: AttestationRequest(
      objectId: profile.keyObjectId,
      offset: 0'u16,
      length: 0'u16,
      attestationKeyId: Se050AttestationKeyObjectId,
      algorithm: Se050AttestationAlgorithmEcSha256,
      freshness: newSeq[uint8](KittingFreshnessLength)
    ),
    response: AttestationResponse(
      objectDataPresent: true,
      objectData: publicKey,
      chipId: chipId,
      attributes: attributesFor(profile),
      objectInfo: @[0x00'u8, 0x20'u8],
      timestamp: newSeq[uint8](Se050AttestationTimestampLength),
      signature: @[0x30'u8, 0x00'u8]
    )
  )

suite "SE050 kitting attestation semantics":
  test "accepts the disposable test profile":
    let profile = testKittingProfile()
    let verified = verifyKittingAttestationSemantics(
      validAttestedObject(profile),
      profile
    )

    check verified.ok
    check verified.value.profile.kind == kpTest
    check verified.value.objectSize == 32'u16
    check verified.value.attributes.origin == Se050ObjectOriginInternal

  test "accepts the one-time production profile":
    let profile = productionKittingProfile()
    let verified = verifyKittingAttestationSemantics(
      validAttestedObject(profile),
      profile
    )

    check verified.ok
    check verified.value.profile.kind == kpProduction

  test "rejects an externally generated key":
    let profile = testKittingProfile()
    var attested = validAttestedObject(profile)
    attested.response.attributes[^5] = Se050ObjectOriginExternal

    let verified = verifyKittingAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seKittingValidationFailed

  test "rejects a policy from the other profile":
    let profile = testKittingProfile()
    var attested = validAttestedObject(profile)
    let productionHeader = policyHeader(productionKittingProfile().keyPolicy())

    # Header starts after the 14-byte fixed prefix, one length byte, and the
    # four-byte policy authentication object ID.
    let headerIndex = Se050AttestedAttributePolicyOffset + 5
    attested.response.attributes[headerIndex] =
      uint8((productionHeader shr 24) and 0xFF)
    attested.response.attributes[headerIndex + 1] =
      uint8((productionHeader shr 16) and 0xFF)
    attested.response.attributes[headerIndex + 2] =
      uint8((productionHeader shr 8) and 0xFF)
    attested.response.attributes[headerIndex + 3] =
      uint8(productionHeader and 0xFF)

    let verified = verifyKittingAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seKittingValidationFailed


  test "rejects the generic development key policy":
    let profile = testKittingProfile()
    var attested = validAttestedObject(profile)
    let developmentHeader = policyHeader(developmentEcKeyPolicy())
    let headerIndex = Se050AttestedAttributePolicyOffset + 5

    attested.response.attributes[headerIndex] =
      uint8((developmentHeader shr 24) and 0xFF)
    attested.response.attributes[headerIndex + 1] =
      uint8((developmentHeader shr 16) and 0xFF)
    attested.response.attributes[headerIndex + 2] =
      uint8((developmentHeader shr 8) and 0xFF)
    attested.response.attributes[headerIndex + 3] =
      uint8(developmentHeader and 0xFF)

    let verified = verifyKittingAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seKittingValidationFailed
    check verified.error.message.contains("generic development policy")

  test "rejects a mismatched signed object ID":
    let profile = testKittingProfile()
    var attested = validAttestedObject(profile)
    attested.response.attributes[3] = 0x01'u8

    let verified = verifyKittingAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seKittingValidationFailed

  test "rejects a compressed or truncated public key":
    let profile = testKittingProfile()
    var attested = validAttestedObject(profile)
    attested.response.objectData.setLen(33)
    attested.response.objectData[0] = 0x02'u8

    let verified = verifyKittingAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seKittingValidationFailed

  test "rejects a non-P256 object size":
    let profile = testKittingProfile()
    var attested = validAttestedObject(profile)
    attested.response.objectInfo = @[0x00'u8, 0x40'u8]

    let verified = verifyKittingAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seKittingValidationFailed
