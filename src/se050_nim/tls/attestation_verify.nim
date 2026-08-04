# =============================================================================
# SE050 TLS client identity attestation semantic validation
# =============================================================================
#
# Cryptographic signature and certificate-chain validation prove that a
# ReadObject-with-Attestation response came from a trusted SE050. This layer
# additionally proves that the signed Secure Object is the exact P-256 TLS
# client identity key required by the selected A/B profile.
#
# Persistence is intentionally not claimed here: Applet 7.2 attested attributes
# do not include the ReadType TransientIndicator. Callers that require a
# persistent object must check ReadType separately on the live SE050.

import std/strformat
import std/strutils

import ../errors
import ../uid
import ../keys
import ../attestation/constants
import ../attestation/read
import ../attestation/attributes
import ./profile

# =============================================================================
# Constants
# =============================================================================

const
  TlsIdentityAttestationFreshnessLength* = 16
  TlsIdentityP256PublicKeyLength* = 65
  TlsIdentityP256PrivateKeySizeBytes* = 32'u16
  Se050AttestationTimestampLength = 12
  DefaultAuthObjectId = 0'u32

# =============================================================================
# Types
# =============================================================================

type
  TlsIdentityAttestationSemantics* = object
    profile*: TlsIdentityProfile
    attributes*: AttestedObjectAttributes
    objectSize*: uint16
    publicKey*: seq[uint8]

# =============================================================================
# Internal helpers
# =============================================================================

proc semanticFailure(
    message: string
): SE[TlsIdentityAttestationSemantics] =
  result = fail[TlsIdentityAttestationSemantics](
    seTlsIdentityValidationFailed,
    message
  )

# =============================================================================
# Public API
# =============================================================================

proc verifyTlsIdentityAttestationSemantics*(
    attested: AttestedObjectRead,
    profile: TlsIdentityProfile
): SE[TlsIdentityAttestationSemantics] =
  ## Validates the signed fields needed to accept one TLS client identity key.
  ##
  ## Certificate-chain and ECDSA attestation-signature checks must be completed
  ## separately before the caller treats these semantics as trusted.
  ## Persistence must also be checked separately through ReadType because the
  ## TransientIndicator is not part of the signed Applet 7.2 attributes.
  if not profile.isValid():
    return semanticFailure("TLS identity profile is invalid")

  if attested.request.objectId != profile.keyObjectId:
    return semanticFailure(
      &"attested request object ID 0x{attested.request.objectId.toHex(8)} does not match {profile.name} slot {profile.slot.slotName()} ID 0x{profile.keyObjectId.toHex(8)}"
    )

  if attested.request.attestationKeyId != Se050AttestationKeyObjectId:
    return semanticFailure(
      &"attestation key ID must be 0x{Se050AttestationKeyObjectId.toHex(8)}"
    )

  if attested.request.algorithm != Se050AttestationAlgorithmEcSha256:
    return semanticFailure("attestation algorithm is not ECDSA with SHA-256")

  if attested.request.offset != 0'u16 or attested.request.length != 0'u16:
    return semanticFailure("TLS identity public key must be attested as a complete object")

  if attested.request.freshness.len != TlsIdentityAttestationFreshnessLength:
    return semanticFailure(
      &"attestation freshness must be {TlsIdentityAttestationFreshnessLength} bytes"
    )

  if not attested.response.objectDataPresent:
    return semanticFailure("attestation response does not contain a public key")

  if attested.response.objectData.len != TlsIdentityP256PublicKeyLength or
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
    return fail[TlsIdentityAttestationSemantics](
      objectSize.error.kind,
      objectSize.error.message,
      objectSize.error.sw
    )

  if objectSize.value != TlsIdentityP256PrivateKeySizeBytes:
    return semanticFailure(
      &"attested object size must be {TlsIdentityP256PrivateKeySizeBytes} bytes; got {objectSize.value}"
    )

  let attributes = parseAttestedObjectAttributes(attested.response.attributes)
  if not attributes.ok:
    return fail[TlsIdentityAttestationSemantics](
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
    return semanticFailure("TLS identity object must not be an authentication object")

  if attributes.value.ownerAuthObjectId != DefaultAuthObjectId:
    return semanticFailure(
      &"TLS identity object owner auth ID must be 0x{DefaultAuthObjectId.toHex(8)}"
    )

  if attributes.value.origin != Se050ObjectOriginInternal:
    return semanticFailure(
      &"TLS identity key origin must be internal; got {objectOriginName(attributes.value.origin)}"
    )

  if not attributes.value.objectVersionPresent:
    return semanticFailure("Applet 7.2 object attributes do not contain an object version")

  if attributes.value.policies.len != 1:
    return semanticFailure(
      &"TLS identity object must contain exactly one policy entry; got {attributes.value.policies.len}"
    )

  let policy = attributes.value.policies[0]
  if policy.authObjectId != DefaultAuthObjectId:
    return semanticFailure(
      &"TLS identity policy auth object must be 0x{DefaultAuthObjectId.toHex(8)}"
    )

  let expectedPolicyHeader = policyHeader(profile.keyPolicy())
  if policy.header != expectedPolicyHeader:
    let developmentSigningHeader = policyHeader(developmentSigningEcKeyPolicy())
    if profile.kind == tipTest and policy.header == developmentSigningHeader:
      return semanticFailure(
        &"signed policy header 0x{policy.header.toHex(8)} is the generic development signing policy; recreate 0x{profile.keyObjectId.toHex(8)} with the TLS identity policy 0x{expectedPolicyHeader.toHex(8)}"
      )

    return semanticFailure(
      &"signed policy header 0x{policy.header.toHex(8)} does not match {profile.name} slot {profile.slot.slotName()} policy 0x{expectedPolicyHeader.toHex(8)}"
    )

  if policy.extension.len != 0:
    return semanticFailure("TLS identity policy must not contain an access-rule extension")

  result = ok(TlsIdentityAttestationSemantics(
    profile: profile,
    attributes: attributes.value,
    objectSize: objectSize.value,
    publicKey: attested.response.objectData
  ))
