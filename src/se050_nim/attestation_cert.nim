# =============================================================================
# SE050 attestation certificate helper
# =============================================================================
#
# Reads and performs structural validation of the NXP-provisioned device
# attestation certificate stored in Secure Object 0xF0000013.
#
# Trust-chain and certificate-signature verification intentionally belong to a
# later host-crypto layer. This module only confirms that the object is a binary
# file, that its reported size matches the returned bytes, and that those bytes
# form one complete DER SEQUENCE.

import ./errors
import ./transport
import ./apdu
import ./objects
import ./tlv
import ./kitting_profile

# =============================================================================
# Constants
# =============================================================================

const
  DerSequenceTag = 0x30'u8

# =============================================================================
# DER validation
# =============================================================================

proc validateAttestationCertificateDer*(certificate: openArray[uint8]): SE[void] =
  ## Checks that certificate contains exactly one complete DER SEQUENCE.
  ##
  ## This is deliberately structural validation only. It does not parse X.509
  ## fields and does not establish trust in the certificate issuer.
  if certificate.len < 2:
    return fail[void](
      seInvalidResponse,
      "attestation certificate is too short for a DER SEQUENCE"
    )

  if certificate[0] != DerSequenceTag:
    return fail[void](
      seInvalidResponse,
      "attestation certificate does not start with a DER SEQUENCE"
    )

  let derLen = readTlvLength(certificate, 1)
  if not derLen.ok:
    return fail[void](
      derLen.error.kind,
      "invalid attestation certificate DER length: " & derLen.error.message,
      derLen.error.sw
    )

  let encodedLength = derLen.value.nextIndex + derLen.value.length
  if encodedLength != certificate.len:
    return fail[void](
      seInvalidResponse,
      "attestation certificate DER length does not match the object length"
    )

  result = ok()

# =============================================================================
# SE050 access
# =============================================================================

proc readAttestationCertificate*(
    se: Se050Transport,
    selectFirst: bool = true
): SE[seq[uint8]] =
  ## Reads the NXP-provisioned device attestation certificate from 0xF0000013.
  ##
  ## The applet is selected once, then type, reported object size, object value,
  ## and DER container length are checked before returning the bytes.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[seq[uint8]](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let objectType = se.readObjectType(
    objectId = Se050AttestationCertificateObjectId,
    selectFirst = false
  )
  if not objectType.ok:
    return fail[seq[uint8]](
      objectType.error.kind,
      objectType.error.message,
      objectType.error.sw
    )

  if objectType.value.objectType != Se050TypeBinaryFile:
    return fail[seq[uint8]](
      seInvalidResponse,
      "SE050 attestation certificate object is not a BINARY_FILE"
    )

  let objectSize = se.readObjectSize(
    objectId = Se050AttestationCertificateObjectId,
    selectFirst = false
  )
  if not objectSize.ok:
    return fail[seq[uint8]](
      objectSize.error.kind,
      objectSize.error.message,
      objectSize.error.sw
    )

  let certificate = se.readSecureObject(
    objectId = Se050AttestationCertificateObjectId,
    selectFirst = false
  )
  if not certificate.ok:
    return fail[seq[uint8]](
      certificate.error.kind,
      certificate.error.message,
      certificate.error.sw
    )

  if uint32(certificate.value.len) != objectSize.value:
    return fail[seq[uint8]](
      seInvalidResponse,
      "SE050 attestation certificate length does not match ReadSize"
    )

  let der = validateAttestationCertificateDer(certificate.value)
  if not der.ok:
    return fail[seq[uint8]](
      der.error.kind,
      der.error.message,
      der.error.sw
    )

  result = certificate
