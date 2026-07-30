# =============================================================================
# OpenSSL-backed host cryptographic verification
# =============================================================================
#
# Minimal OpenSSL 3 binding used by the SE050 attestation verification path.
# The binding intentionally uses opaque pointers and runtime symbol loading so
# building se050_nim does not require OpenSSL C headers or a libcrypto.so
# development symlink. The target system must provide libcrypto.so.3.

import std/strutils

import ./errors

# =============================================================================
# Constants and OpenSSL imports
# =============================================================================

const
  LibCrypto = "libcrypto.so.3"
  Sha256DigestLength* = 32
  EcP256UncompressedPublicKeyLength* = 65

  OpenSslParamGroupName = "group"
  OpenSslParamPublicKey = "pub"

proc opensslSha256(
    data: ptr uint8,
    length: csize_t,
    digest: ptr uint8
): ptr uint8 {.cdecl, importc: "SHA256", dynlib: LibCrypto.}

proc d2iX509(
    certificate: ptr pointer,
    input: ptr ptr uint8,
    length: clong
): pointer {.cdecl, importc: "d2i_X509", dynlib: LibCrypto.}

proc x509Free(certificate: pointer) {.
  cdecl,
  importc: "X509_free",
  dynlib: LibCrypto
.}

proc x509GetPublicKey(certificate: pointer): pointer {.
  cdecl,
  importc: "X509_get_pubkey",
  dynlib: LibCrypto
.}

proc evpPublicKeyFree(publicKey: pointer) {.
  cdecl,
  importc: "EVP_PKEY_free",
  dynlib: LibCrypto
.}

proc evpPublicKeyIsA(publicKey: pointer, name: cstring): cint {.
  cdecl,
  importc: "EVP_PKEY_is_a",
  dynlib: LibCrypto
.}

proc evpPublicKeyGetBits(publicKey: pointer): cint {.
  cdecl,
  importc: "EVP_PKEY_get_bits",
  dynlib: LibCrypto
.}

proc evpPublicKeyGetUtf8StringParam(
    publicKey: pointer,
    key: cstring,
    buffer: cstring,
    bufferSize: csize_t,
    outputLength: ptr csize_t
): cint {.
  cdecl,
  importc: "EVP_PKEY_get_utf8_string_param",
  dynlib: LibCrypto
.}

proc evpPublicKeyGetOctetStringParam(
    publicKey: pointer,
    key: cstring,
    buffer: ptr uint8,
    bufferSize: csize_t,
    outputLength: ptr csize_t
): cint {.
  cdecl,
  importc: "EVP_PKEY_get_octet_string_param",
  dynlib: LibCrypto
.}

proc evpMdContextNew(): pointer {.
  cdecl,
  importc: "EVP_MD_CTX_new",
  dynlib: LibCrypto
.}

proc evpMdContextFree(context: pointer) {.
  cdecl,
  importc: "EVP_MD_CTX_free",
  dynlib: LibCrypto
.}

proc evpSha256(): pointer {.
  cdecl,
  importc: "EVP_sha256",
  dynlib: LibCrypto
.}

proc evpDigestVerifyInit(
    context: pointer,
    publicKeyContext: ptr pointer,
    digest: pointer,
    engine: pointer,
    publicKey: pointer
): cint {.
  cdecl,
  importc: "EVP_DigestVerifyInit",
  dynlib: LibCrypto
.}

proc evpDigestVerify(
    context: pointer,
    signature: ptr uint8,
    signatureLength: csize_t,
    data: ptr uint8,
    dataLength: csize_t
): cint {.
  cdecl,
  importc: "EVP_DigestVerify",
  dynlib: LibCrypto
.}

proc opensslErrorGet(): culong {.
  cdecl,
  importc: "ERR_get_error",
  dynlib: LibCrypto
.}

proc opensslErrorString(
    errorCode: culong,
    buffer: cstring,
    bufferLength: csize_t
) {.
  cdecl,
  importc: "ERR_error_string_n",
  dynlib: LibCrypto
.}

# =============================================================================
# Internal helpers
# =============================================================================

proc bytePointer(data: openArray[uint8]): ptr uint8 =
  if data.len == 0:
    result = nil
  else:
    result = cast[ptr uint8](unsafeAddr data[0])

proc opensslErrorMessage(fallback: string): string =
  var messages: seq[string] = @[]
  var errorCode = opensslErrorGet()

  while errorCode != 0 and messages.len < 4:
    var buffer: array[256, char]
    opensslErrorString(errorCode, cast[cstring](addr buffer[0]), csize_t(buffer.len))
    messages.add($cast[cstring](addr buffer[0]))
    errorCode = opensslErrorGet()

  if messages.len == 0:
    result = fallback
  else:
    result = fallback & ": " & messages.join("; ")

proc loadX509Certificate(certificateDer: openArray[uint8]): SE[pointer] =
  if certificateDer.len == 0:
    return fail[pointer](
      seInvalidArgument,
      "X.509 certificate DER must not be empty"
    )

  try:
    let start = certificateDer.bytePointer()
    var cursor = start
    let certificate = d2iX509(nil, addr cursor, clong(certificateDer.len))

    if certificate == nil:
      return fail[pointer](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to parse the X.509 certificate")
      )

    let consumed = cast[uint](cursor) - cast[uint](start)
    if consumed != uint(certificateDer.len):
      x509Free(certificate)
      return fail[pointer](
        seInvalidResponse,
        "X.509 certificate DER contains trailing or unparsed bytes"
      )

    result = ok(certificate)
  except CatchableError as e:
    result = fail[pointer](
      seCryptoError,
      "OpenSSL libcrypto is unavailable: " & e.msg
    )

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
