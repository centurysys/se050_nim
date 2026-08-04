# =============================================================================
# SE050 attestation signature verification
# =============================================================================
#
# Verifies the Applet 7.2 ReadObject-with-Attestation ECDSA signature using the
# public key contained in the NXP-provisioned device certificate.
#
# Certificate-chain trust and semantic validation of object attributes belong
# to later layers. This module verifies the cryptographic binding between the
# captured request, response TLVs, and signature.

import ../errors
import ../crypto_verify
import ./constants
import ./read

# =============================================================================
# Types
# =============================================================================

type
  AttestationSignatureVerification* = object
    certificateSha256*: array[Sha256DigestLength, uint8]
    certificatePublicKey*: seq[uint8]
    commandSha256*: array[Sha256DigestLength, uint8]

# =============================================================================
# Public API
# =============================================================================

proc buildAttestationVerificationData*(
    attested: AttestedObjectRead
): SE[seq[uint8]] =
  ## Reconstructs the bytes hashed by the SE050 before ECDSA signing:
  ##
  ##   SHA256(plain request command without Le) || encoded response TLVs
  ##
  ## The caller then applies SHA-256 once more as part of ECDSA/SHA-256
  ## verification.
  if attested.request.algorithm != Se050AttestationAlgorithmEcSha256:
    return fail[seq[uint8]](
      seInvalidArgument,
      "unsupported attestation algorithm for host verification"
    )

  if attested.request.signedCommandApdu.len == 0:
    return fail[seq[uint8]](
      seInvalidArgument,
      "attestation request command is empty"
    )

  if attested.response.signedResponseData.len == 0:
    return fail[seq[uint8]](
      seInvalidArgument,
      "attestation signed response data is empty"
    )

  let commandDigest = sha256(attested.request.signedCommandApdu)
  if not commandDigest.ok:
    return fail[seq[uint8]](
      commandDigest.error.kind,
      commandDigest.error.message,
      commandDigest.error.sw
    )

  var verificationData = newSeqOfCap[uint8](
    Sha256DigestLength + attested.response.signedResponseData.len
  )
  verificationData.add(commandDigest.value)
  verificationData.add(attested.response.signedResponseData)

  result = ok(verificationData)

proc verifyAttestationSignature*(
    attested: AttestedObjectRead,
    certificateDer: openArray[uint8]
): SE[AttestationSignatureVerification] =
  ## Verifies the ECDSA/SHA-256 attestation signature using the EC P-256 public
  ## key in the supplied device certificate.
  ##
  ## A successful result does not yet prove that the certificate is issued by
  ## an accepted NXP CA. Certificate-chain verification is intentionally a
  ## separate step.
  if attested.response.signature.len == 0:
    return fail[AttestationSignatureVerification](
      seInvalidArgument,
      "attestation response signature is empty"
    )

  let verificationData = buildAttestationVerificationData(attested)
  if not verificationData.ok:
    return fail[AttestationSignatureVerification](
      verificationData.error.kind,
      verificationData.error.message,
      verificationData.error.sw
    )

  let signature = verifyEcdsaSha256WithCertificate(
    certificateDer,
    verificationData.value,
    attested.response.signature
  )
  if not signature.ok:
    return fail[AttestationSignatureVerification](
      signature.error.kind,
      signature.error.message,
      signature.error.sw
    )

  let publicKey = extractCertificateEcPublicKey(certificateDer)
  if not publicKey.ok:
    return fail[AttestationSignatureVerification](
      publicKey.error.kind,
      publicKey.error.message,
      publicKey.error.sw
    )

  let certificateDigest = certificateSha256(certificateDer)
  if not certificateDigest.ok:
    return fail[AttestationSignatureVerification](
      certificateDigest.error.kind,
      certificateDigest.error.message,
      certificateDigest.error.sw
    )

  let commandDigest = sha256(attested.request.signedCommandApdu)
  if not commandDigest.ok:
    return fail[AttestationSignatureVerification](
      commandDigest.error.kind,
      commandDigest.error.message,
      commandDigest.error.sw
    )

  result = ok(AttestationSignatureVerification(
    certificateSha256: certificateDigest.value,
    certificatePublicKey: publicKey.value,
    commandSha256: commandDigest.value
  ))
