# =============================================================================
# OpenSSL-backed host cryptographic verification
# =============================================================================
#
# Uses the shared minimal OpenSSL 3 FFI for SE050 attestation verification.
# The host binding remains isolated in openssl_ffi.nim so verification logic
# does not duplicate libcrypto declarations.

import ./errors
import ./openssl_ffi

# =============================================================================
# Constants
# =============================================================================

const
  Sha256DigestLength* = 32
  EcP256UncompressedPublicKeyLength* = 65

  OpenSslParamGroupName = "group"
  OpenSslParamPublicKey = "pub"

# =============================================================================
# Internal helpers
# =============================================================================

proc loadEcP256PublicKey(certificateDer: openArray[uint8]): SE[pointer] =
  let certificate = loadX509Certificate(certificateDer)
  if not certificate.ok:
    return fail[pointer](
      certificate.error.kind,
      certificate.error.message,
      certificate.error.sw
    )

  defer:
    x509Free(certificate.value)

  try:
    let publicKey = x509GetPublicKey(certificate.value)
    if publicKey == nil:
      return fail[pointer](
        seCryptoError,
        opensslErrorMessage("X.509 certificate does not contain a public key")
      )

    if evpPublicKeyIsA(publicKey, "EC") != 1:
      evpPublicKeyFree(publicKey)
      return fail[pointer](
        seInvalidResponse,
        "X.509 certificate public key is not an EC key"
      )

    if evpPublicKeyGetBits(publicKey) != 256:
      evpPublicKeyFree(publicKey)
      return fail[pointer](
        seInvalidResponse,
        "X.509 certificate EC public key is not 256 bits"
      )

    var groupBuffer: array[80, char]
    var groupLength: csize_t
    if evpPublicKeyGetUtf8StringParam(
        publicKey,
        OpenSslParamGroupName,
        cast[cstring](addr groupBuffer[0]),
        csize_t(groupBuffer.len),
        addr groupLength
    ) != 1:
      evpPublicKeyFree(publicKey)
      return fail[pointer](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to read the EC group name")
      )

    let groupName = $cast[cstring](addr groupBuffer[0])
    if groupName != "prime256v1" and
        groupName != "secp256r1" and
        groupName != "P-256":
      evpPublicKeyFree(publicKey)
      return fail[pointer](
        seInvalidResponse,
        "X.509 certificate EC public key uses unexpected group: " & groupName
      )

    result = ok(publicKey)
  except CatchableError as e:
    result = fail[pointer](
      seCryptoError,
      "OpenSSL public-key handling failed: " & e.msg
    )

# =============================================================================
# Public API
# =============================================================================

proc sha256*(data: openArray[uint8]): SE[array[Sha256DigestLength, uint8]] =
  ## Computes SHA-256 using the system OpenSSL 3 libcrypto.
  var digest: array[Sha256DigestLength, uint8]

  try:
    if opensslSha256(
        data.bytePointer(),
        csize_t(data.len),
        addr digest[0]
    ) == nil:
      return fail[array[Sha256DigestLength, uint8]](
        seCryptoError,
        opensslErrorMessage("OpenSSL SHA-256 failed")
      )

    result = ok(digest)
  except CatchableError as e:
    result = fail[array[Sha256DigestLength, uint8]](
      seCryptoError,
      "OpenSSL libcrypto is unavailable: " & e.msg
    )

proc certificateSha256*(
    certificateDer: openArray[uint8]
): SE[array[Sha256DigestLength, uint8]] =
  ## Returns the SHA-256 fingerprint of the exact DER certificate bytes.
  result = sha256(certificateDer)

proc extractCertificateEcPublicKey*(
    certificateDer: openArray[uint8]
): SE[seq[uint8]] =
  ## Extracts the uncompressed 0x04 || X || Y P-256 point from a DER X.509
  ## certificate. The certificate signature and trust chain are not verified.
  let publicKey = loadEcP256PublicKey(certificateDer)
  if not publicKey.ok:
    return fail[seq[uint8]](
      publicKey.error.kind,
      publicKey.error.message,
      publicKey.error.sw
    )

  defer:
    evpPublicKeyFree(publicKey.value)

  try:
    var encoded = newSeq[uint8](EcP256UncompressedPublicKeyLength)
    var encodedLength: csize_t

    if evpPublicKeyGetOctetStringParam(
        publicKey.value,
        OpenSslParamPublicKey,
        addr encoded[0],
        csize_t(encoded.len),
        addr encodedLength
    ) != 1:
      return fail[seq[uint8]](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to extract the EC public point")
      )

    if encodedLength != csize_t(EcP256UncompressedPublicKeyLength):
      return fail[seq[uint8]](
        seInvalidResponse,
        "X.509 certificate EC public point has unexpected length: " &
          $encodedLength
      )

    if encoded[0] != 0x04'u8:
      return fail[seq[uint8]](
        seInvalidResponse,
        "X.509 certificate EC public point is not uncompressed"
      )

    result = ok(encoded)
  except CatchableError as e:
    result = fail[seq[uint8]](
      seCryptoError,
      "OpenSSL public-key extraction failed: " & e.msg
    )

proc verifyEcdsaSha256WithCertificate*(
    certificateDer: openArray[uint8],
    data: openArray[uint8],
    signatureDer: openArray[uint8]
): SE[void] =
  ## Verifies a DER-encoded ECDSA/SHA-256 signature using the P-256 public key
  ## contained in a DER X.509 certificate.
  ##
  ## This verifies only the supplied signature. It does not establish trust in
  ## the certificate issuer or validate a certificate chain.
  if signatureDer.len == 0:
    return fail[void](
      seInvalidArgument,
      "ECDSA signature DER must not be empty"
    )

  let publicKey = loadEcP256PublicKey(certificateDer)
  if not publicKey.ok:
    return fail[void](
      publicKey.error.kind,
      publicKey.error.message,
      publicKey.error.sw
    )

  defer:
    evpPublicKeyFree(publicKey.value)

  try:
    let context = evpMdContextNew()
    if context == nil:
      return fail[void](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to allocate a digest context")
      )

    defer:
      evpMdContextFree(context)

    var publicKeyContext: pointer
    if evpDigestVerifyInit(
        context,
        addr publicKeyContext,
        evpSha256(),
        nil,
        publicKey.value
    ) != 1:
      return fail[void](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to initialize ECDSA verification")
      )

    let verified = evpDigestVerify(
      context,
      signatureDer.bytePointer(),
      csize_t(signatureDer.len),
      data.bytePointer(),
      csize_t(data.len)
    )

    case verified
    of 1:
      result = ok()
    of 0:
      result = fail[void](
        seSignatureInvalid,
        "ECDSA/SHA-256 signature verification failed"
      )
    else:
      result = fail[void](
        seCryptoError,
        opensslErrorMessage("OpenSSL ECDSA verification failed")
      )
  except CatchableError as e:
    result = fail[void](
      seCryptoError,
      "OpenSSL signature verification failed: " & e.msg
    )
