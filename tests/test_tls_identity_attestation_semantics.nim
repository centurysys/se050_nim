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

proc attributesFor(profile: TlsIdentityProfile): seq[uint8] =
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

proc validAttestedObject(profile: TlsIdentityProfile): AttestedObjectRead =
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
      freshness: newSeq[uint8](TlsIdentityAttestationFreshnessLength)
    ),
    response: AttestationResponse(
      objectDataPresent: true,
      objectData: publicKey,
      chipId: chipId,
      attributes: attributesFor(profile),
      objectInfo: @[0x00'u8, 0x20'u8],
      timestamp: newSeq[uint8](12),
      signature: @[0x30'u8, 0x00'u8]
    )
  )

proc replacePolicyHeader(attested: var AttestedObjectRead, header: uint32) =
  let headerIndex = Se050AttestedAttributePolicyOffset + 5
  attested.response.attributes[headerIndex] =
    uint8((header shr 24) and 0xFF)
  attested.response.attributes[headerIndex + 1] =
    uint8((header shr 16) and 0xFF)
  attested.response.attributes[headerIndex + 2] =
    uint8((header shr 8) and 0xFF)
  attested.response.attributes[headerIndex + 3] =
    uint8(header and 0xFF)

suite "SE050 TLS identity attestation semantics":
  test "accepts test slot A":
    let profile = testTlsIdentityProfile(tisSlotA)
    let verified = verifyTlsIdentityAttestationSemantics(
      validAttestedObject(profile),
      profile
    )

    check verified.ok
    check verified.value.profile.kind == tipTest
    check verified.value.profile.slot == tisSlotA
    check verified.value.objectSize == 32'u16
    check verified.value.attributes.origin == Se050ObjectOriginInternal
    check verified.value.publicKey.len == EcP256UncompressedPublicKeyLength

  test "accepts production slot B":
    let profile = productionTlsIdentityProfile(tisSlotB)
    let verified = verifyTlsIdentityAttestationSemantics(
      validAttestedObject(profile),
      profile
    )

    check verified.ok
    check verified.value.profile.kind == tipProduction
    check verified.value.profile.slot == tisSlotB

  test "rejects an externally generated key":
    let profile = testTlsIdentityProfile(tisSlotA)
    var attested = validAttestedObject(profile)
    attested.response.attributes[^5] = Se050ObjectOriginExternal

    let verified = verifyTlsIdentityAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seTlsIdentityValidationFailed
    check verified.error.message.contains("origin must be internal")

  test "rejects generic development signing policy":
    let profile = testTlsIdentityProfile(tisSlotA)
    var attested = validAttestedObject(profile)
    attested.replacePolicyHeader(
      policyHeader(developmentSigningEcKeyPolicy())
    )

    let verified = verifyTlsIdentityAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seTlsIdentityValidationFailed
    check verified.error.message.contains("generic development signing policy")

  test "rejects a policy header outside the TLS identity profile":
    let profile = testTlsIdentityProfile(tisSlotA)
    var attested = validAttestedObject(profile)
    attested.replacePolicyHeader(policyHeader(developmentEcKeyPolicy()))

    let verified = verifyTlsIdentityAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seTlsIdentityValidationFailed
    check verified.error.message.contains("does not match")

  test "rejects a mismatched signed object ID":
    let profile = testTlsIdentityProfile(tisSlotA)
    var attested = validAttestedObject(profile)
    attested.response.attributes[3] = 0x01'u8

    let verified = verifyTlsIdentityAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seTlsIdentityValidationFailed

  test "rejects a non-key-pair object type":
    let profile = testTlsIdentityProfile(tisSlotA)
    var attested = validAttestedObject(profile)
    attested.response.attributes[4] = Se050TypeEcPubKeyNistP256

    let verified = verifyTlsIdentityAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seTlsIdentityValidationFailed
    check verified.error.message.contains("key-pair type")

  test "rejects a compressed or truncated public key":
    let profile = testTlsIdentityProfile(tisSlotA)
    var attested = validAttestedObject(profile)
    attested.response.objectData.setLen(33)
    attested.response.objectData[0] = 0x02'u8

    let verified = verifyTlsIdentityAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seTlsIdentityValidationFailed

  test "rejects a non-P256 object size":
    let profile = testTlsIdentityProfile(tisSlotA)
    var attested = validAttestedObject(profile)
    attested.response.objectInfo = @[0x00'u8, 0x40'u8]

    let verified = verifyTlsIdentityAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seTlsIdentityValidationFailed

  test "rejects an access-rule extension":
    let profile = testTlsIdentityProfile(tisSlotA)
    var attested = validAttestedObject(profile)

    # Increase the policy entry length from 8 to 9 and insert one extension
    # byte before the signed origin value.
    let policyStart = Se050AttestedAttributePolicyOffset
    attested.response.attributes[policyStart] = 0x09'u8
    attested.response.attributes.insert(0xAA'u8, policyStart + 9)

    let verified = verifyTlsIdentityAttestationSemantics(attested, profile)
    check not verified.ok
    check verified.error.kind == seTlsIdentityValidationFailed
    check verified.error.message.contains("access-rule extension")
