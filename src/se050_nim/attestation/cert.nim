# =============================================================================
# SE050 attestation certificate helper
# =============================================================================
#
# Reads and performs structural validation of the NXP-provisioned device
# attestation certificate stored in Secure Object 0xF0000013.
#
# Some SE050 variants allocate a BinaryFile object larger than the encoded X.509
# certificate and leave the unused tail zero-filled. The DER SEQUENCE length is
# therefore authoritative for the certificate itself, while ReadSize remains
# authoritative for reading the complete Secure Object value.
#
# Trust-chain and certificate-signature verification intentionally belong to a
# later host-crypto layer. This module only confirms that the object is a binary
# file and that its leading bytes form one complete DER SEQUENCE followed by
# optional zero padding.

import ../errors
import ../transport
import ../apdu
import ../objects
import ../tlv
import ./constants

# =============================================================================
# Constants
# =============================================================================

const
  DerSequenceTag = 0x30'u8

# =============================================================================
# DER validation
# =============================================================================

proc extractAttestationCertificateDer*(
    objectData: openArray[uint8]
): SE[seq[uint8]] =
  ## Extracts one complete DER SEQUENCE from a BinaryFile object value.
  ##
  ## SE050 configurations may provision 0xF0000013 with a fixed BinaryFile size
  ## larger than the actual X.509 DER encoding. In that case, only zero-filled
  ## bytes are accepted after the DER SEQUENCE and they are not returned.
  if objectData.len < 2:
    return fail[seq[uint8]](
      seInvalidResponse,
      "attestation certificate is too short for a DER SEQUENCE"
    )

  if objectData[0] != DerSequenceTag:
    return fail[seq[uint8]](
      seInvalidResponse,
      "attestation certificate does not start with a DER SEQUENCE"
    )

  let derLen = readTlvLength(objectData, 1)
  if not derLen.ok:
    return fail[seq[uint8]](
      derLen.error.kind,
      "invalid attestation certificate DER length: " & derLen.error.message,
      derLen.error.sw
    )

  let encodedLength = derLen.value.nextIndex + derLen.value.length
  if encodedLength > objectData.len:
    return fail[seq[uint8]](
      seInvalidResponse,
      "attestation certificate DER length exceeds the object length"
    )

  for i in encodedLength ..< objectData.len:
    if objectData[i] != 0x00'u8:
      return fail[seq[uint8]](
        seInvalidResponse,
        "attestation certificate has non-zero data after the DER SEQUENCE"
      )

  var certificate = newSeq[uint8](encodedLength)
  for i in 0 ..< encodedLength:
    certificate[i] = objectData[i]

  result = ok(certificate)

proc validateAttestationCertificateDer*(
    certificate: openArray[uint8]
): SE[void] =
  ## Checks that certificate contains one complete DER SEQUENCE followed by
  ## optional zero padding.
  ##
  ## This is deliberately structural validation only. It does not parse X.509
  ## fields and does not establish trust in the certificate issuer.
  let extracted = extractAttestationCertificateDer(certificate)
  if not extracted.ok:
    return fail[void](
      extracted.error.kind,
      extracted.error.message,
      extracted.error.sw
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
  ## and DER container length are checked. Any zero-filled BinaryFile tail is
  ## removed before returning the certificate DER bytes.
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

  let objectData = se.readBinaryObject(
    objectId = Se050AttestationCertificateObjectId,
    objectSize = objectSize.value,
    selectFirst = false
  )
  if not objectData.ok:
    return fail[seq[uint8]](
      objectData.error.kind,
      objectData.error.message,
      objectData.error.sw
    )

  if uint32(objectData.value.len) != objectSize.value:
    return fail[seq[uint8]](
      seInvalidResponse,
      "SE050 attestation certificate length does not match ReadSize"
    )

  let certificate = extractAttestationCertificateDer(objectData.value)
  if not certificate.ok:
    return fail[seq[uint8]](
      certificate.error.kind,
      certificate.error.message,
      certificate.error.sw
    )

  result = certificate
