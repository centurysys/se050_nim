# =============================================================================
# SE050 TLS client identity live validation
# =============================================================================
#
# This module validates an existing SE050 TLS client identity before callers
# accept it for signing or public-key export. The checks deliberately combine
# live ReadType/ReadPublicKey results with NXP attestation so persistence,
# object type, policy, origin, and public-key binding are all verified.
#
# The current TLS identity profile is intentionally limited to internally
# generated P-256 key pairs. Imported-key support will add an explicit origin
# expectation later rather than weakening these checks.

import std/options
import std/strformat
import std/strutils

import ../errors
import ../transport
import ../random
import ../objects
import ../keys
import ../x509_verify
import ../attestation/cert
import ../attestation/read
import ../attestation/signature_verify
import ../attestation/trust_store
import ./profile
import ./attestation_verify

# =============================================================================
# Types
# =============================================================================

type
  TlsIdentityLiveInfo* = object
    profile*: TlsIdentityProfile
    objectType*: uint8
    publicKey*: seq[uint8]
    semantics*: TlsIdentityAttestationSemantics

# =============================================================================
# Public API
# =============================================================================

proc inspectTlsIdentity*(
    se: Se050Transport,
    profile: TlsIdentityProfile
): SE[TlsIdentityLiveInfo] =
  ## Performs the trust checks required before accepting an existing TLS key.
  ##
  ## The object type and persistence come from the live ReadType response.
  ## Object ID, key type, internal origin, policy, and public key are then
  ## independently bound by NXP ReadObject-with-Attestation.
  if not profile.isValid():
    return fail[TlsIdentityLiveInfo](
      seInvalidArgument,
      "TLS identity profile is invalid"
    )

  let typ = se.readObjectType(
    objectId = profile.keyObjectId,
    selectFirst = false
  )
  if not typ.ok:
    return fail[TlsIdentityLiveInfo](
      typ.error.kind,
      typ.error.message,
      typ.error.sw
    )

  if typ.value.objectType != profile.expectedKeyType():
    return fail[TlsIdentityLiveInfo](
      seTlsIdentityValidationFailed,
      &"live object type 0x{typ.value.objectType.toHex(2)} does not match expected P-256 key-pair type 0x{profile.expectedKeyType().toHex(2)}"
    )

  if typ.value.transientIndicator.isNone or
      typ.value.transientIndicator.get() != 0x01'u8:
    return fail[TlsIdentityLiveInfo](
      seTlsIdentityValidationFailed,
      "TLS identity object is not persistent"
    )

  let livePublicKey = se.readPublicKey(
    objectId = profile.keyObjectId,
    selectFirst = false
  )
  if not livePublicKey.ok:
    return fail[TlsIdentityLiveInfo](
      livePublicKey.error.kind,
      livePublicKey.error.message,
      livePublicKey.error.sw
    )

  let certificate = se.readAttestationCertificate(selectFirst = false)
  if not certificate.ok:
    return fail[TlsIdentityLiveInfo](
      certificate.error.kind,
      certificate.error.message,
      certificate.error.sw
    )

  let chain = verifyCertificateChain(
    leafCertificateDer = certificate.value,
    trustAnchorsDer = nxpAttestationTrustAnchors(),
    intermediatesDer = nxpAttestationIntermediates()
  )
  if not chain.ok:
    return fail[TlsIdentityLiveInfo](
      chain.error.kind,
      chain.error.message,
      chain.error.sw
    )

  let freshness = se.getRandomBytes(
    TlsIdentityAttestationFreshnessLength,
    selectFirst = false
  )
  if not freshness.ok:
    return fail[TlsIdentityLiveInfo](
      freshness.error.kind,
      freshness.error.message,
      freshness.error.sw
    )

  let attested = se.readObjectWithAttestation(
    objectId = profile.keyObjectId,
    freshness = freshness.value,
    selectFirst = false
  )
  if not attested.ok:
    return fail[TlsIdentityLiveInfo](
      attested.error.kind,
      attested.error.message,
      attested.error.sw
    )

  let signature = verifyAttestationSignature(
    attested = attested.value,
    certificateDer = certificate.value
  )
  if not signature.ok:
    return fail[TlsIdentityLiveInfo](
      signature.error.kind,
      signature.error.message,
      signature.error.sw
    )

  let semantics = verifyTlsIdentityAttestationSemantics(
    attested = attested.value,
    profile = profile
  )
  if not semantics.ok:
    return fail[TlsIdentityLiveInfo](
      semantics.error.kind,
      semantics.error.message,
      semantics.error.sw
    )

  if livePublicKey.value != semantics.value.publicKey:
    return fail[TlsIdentityLiveInfo](
      seTlsIdentityValidationFailed,
      "live public key does not match the attested public key"
    )

  result = ok(TlsIdentityLiveInfo(
    profile: profile,
    objectType: typ.value.objectType,
    publicKey: livePublicKey.value,
    semantics: semantics.value
  ))
