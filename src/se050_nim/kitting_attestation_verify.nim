# =============================================================================
# SE050 kitting attestation semantic validation
# =============================================================================
#
# Cryptographic signature and certificate-chain validation prove that the
# response came from a trusted SE050. This layer additionally proves that the
# signed object is the exact firmware key-agreement object required by the
# selected test or production kitting profile.

import std/strformat
import std/strutils

import ./errors
import ./uid
import ./keys
import ./kitting_profile
import ./attestation
import ./attestation_attributes

# =============================================================================
# Constants
# =============================================================================

const
  P256UncompressedPublicKeyLength* = 65
  P256PrivateKeySizeBytes* = 32'u16
  Se050AttestationTimestampLength* = 12
  DefaultAuthObjectId = 0'u32

# =============================================================================
# Types
# =============================================================================

type
  KittingAttestationSemantics* = object
    profile*: KittingProfile
    attributes*: AttestedObjectAttributes
    objectSize*: uint16

# =============================================================================
# Internal helpers
# =============================================================================

proc semanticFailure(
    message: string
): SE[KittingAttestationSemantics] =
  result = fail[KittingAttestationSemantics](
    seKittingValidationFailed,
    message
  )

# =============================================================================
# Public API
# =============================================================================

proc verifyKittingAttestationSemantics*(
    attested: AttestedObjectRead,
    profile: KittingProfile
): SE[KittingAttestationSemantics] =
  ## Validates all signed fields needed to accept a firmware KEX public key.
  ## Certificate-chain and ECDSA checks must be completed separately before the
  ## caller treats this result as trusted.
  if not profile.isValid():
    return semanticFailure("kitting profile is invalid")

  if attested.request.objectId != profile.keyObjectId:
    return semanticFailure(
      &"attested request object ID 0x{attested.request.objectId.toHex(8)} does not match {profile.name} profile ID 0x{profile.keyObjectId.toHex(8)}"
    )

  if attested.request.attestationKeyId != Se050AttestationKeyObjectId:
    return semanticFailure(
      &"attestation key ID must be 0x{Se050AttestationKeyObjectId.toHex(8)}"
    )

  if attested.request.algorithm != Se050AttestationAlgorithmEcSha256:
    return semanticFailure("attestation algorithm is not ECDSA with SHA-256")

  if attested.request.offset != 0'u16 or attested.request.length != 0'u16:
    return semanticFailure("kitting public key must be attested as a complete object")

  if attested.request.freshness.len != KittingFreshnessLength:
    return semanticFailure(
      &"attestation freshness must be {KittingFreshnessLength} bytes"
    )

  if not attested.response.objectDataPresent:
    return semanticFailure("attestation response does not contain a public key")

  if attested.response.objectData.len != P256UncompressedPublicKeyLength or
      attested.response.objectData[0] != 0x04'u8:
    return semanticFailure(
      "attested public key is not a 65-byte uncompressed P-256 point"
    )

  if attested.response.chipId.len != Se050UidLength:
    return semanticFailure(
      &"attested chip UID must be {Se050UidLength} bytes"
    )

  if attested.response.timestamp.len != Se050AttestationTimestampLength:
    return semanticFailure(
      &"attestation timestamp must be {Se050AttestationTimestampLength} bytes"
    )

  let objectSize = parseAttestedObjectSize(attested.response.objectInfo)
  if not objectSize.ok:
    return fail[KittingAttestationSemantics](
      objectSize.error.kind,
      objectSize.error.message,
      objectSize.error.sw
    )

  if objectSize.value != P256PrivateKeySizeBytes:
    return semanticFailure(
      &"attested object size must be {P256PrivateKeySizeBytes} bytes; got {objectSize.value}"
    )

  let attributes = parseAttestedObjectAttributes(attested.response.attributes)
  if not attributes.ok:
    return fail[KittingAttestationSemantics](
      attributes.error.kind,
      attributes.error.message,
      attributes.error.sw
    )

  if attributes.value.objectId != profile.keyObjectId:
    return semanticFailure(
      &"signed attribute object ID 0x{attributes.value.objectId.toHex(8)} does not match profile ID 0x{profile.keyObjectId.toHex(8)}"
    )

  if attributes.value.objectType != profile.expectedKeyType():
    return semanticFailure(
      &"signed object type 0x{attributes.value.objectType.toHex(2)} does not match expected P-256 key-pair type 0x{profile.expectedKeyType().toHex(2)}"
    )

  if attributes.value.authAttribute != Se050SetIndicatorNotSet:
    return semanticFailure("firmware KEX object must not be an authentication object")

  if attributes.value.ownerAuthObjectId != DefaultAuthObjectId:
    return semanticFailure(
      &"firmware KEX object owner auth ID must be 0x{DefaultAuthObjectId.toHex(8)}"
    )

  if attributes.value.origin != Se050ObjectOriginInternal:
    return semanticFailure(
      &"firmware KEX key origin must be internal; got {objectOriginName(attributes.value.origin)}"
    )

  if not attributes.value.objectVersionPresent:
    return semanticFailure("Applet 7.2 object attributes do not contain an object version")

  if attributes.value.policies.len != 1:
    return semanticFailure(
      &"firmware KEX object must contain exactly one policy entry; got {attributes.value.policies.len}"
    )

  let policy = attributes.value.policies[0]
  if policy.authObjectId != DefaultAuthObjectId:
    return semanticFailure(
      &"firmware KEX policy auth object must be 0x{DefaultAuthObjectId.toHex(8)}"
    )

  let expectedPolicyHeader = policyHeader(profile.keyPolicy())
  if policy.header != expectedPolicyHeader:
    let developmentPolicyHeader = policyHeader(developmentEcKeyPolicy())
    if profile.kind == kpTest and policy.header == developmentPolicyHeader:
      return semanticFailure(
        &"signed policy header 0x{policy.header.toHex(8)} is the generic development policy; recreate 0x{profile.keyObjectId.toHex(8)} with the kitting test policy 0x{expectedPolicyHeader.toHex(8)}"
      )

    return semanticFailure(
      &"signed policy header 0x{policy.header.toHex(8)} does not match {profile.name} profile policy 0x{expectedPolicyHeader.toHex(8)}"
    )

  if policy.extension.len != 0:
    return semanticFailure("firmware KEX policy must not contain an access-rule extension")

  result = ok(KittingAttestationSemantics(
    profile: profile,
    attributes: attributes.value,
    objectSize: objectSize.value
  ))
