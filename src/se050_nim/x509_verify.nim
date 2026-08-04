# =============================================================================
# OpenSSL-backed X.509 certificate-chain verification
# =============================================================================
#
# Validates a DER-encoded leaf certificate against explicitly supplied trust
# anchors and optional intermediate certificates. The implementation uses an
# isolated X509_STORE and never falls back to the host system CA store.
#
# Certificate files may contain one DER certificate or multiple DER
# certificates concatenated back-to-back. PEM parsing intentionally remains
# outside this minimal library; use `openssl x509 -outform DER` when needed.

import std/strutils

import ./errors
import ./tlv

# =============================================================================
# Types
# =============================================================================

type
  CertificateChainVerification* = object
    trustAnchorCount*: int
    intermediateCount*: int

# =============================================================================
# Constants and OpenSSL imports
# =============================================================================

const
  LibCrypto = "libcrypto.so.3"
  DerSequenceTag = 0x30'u8

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

proc x509GetPubkey(certificate: pointer): pointer {.
  cdecl,
  importc: "X509_get_pubkey",
  dynlib: LibCrypto
.}

proc evpPkeyFree(publicKey: pointer) {.
  cdecl,
  importc: "EVP_PKEY_free",
  dynlib: LibCrypto
.}

proc i2dPubkey(publicKey: pointer, output: ptr ptr uint8): cint {.
  cdecl,
  importc: "i2d_PUBKEY",
  dynlib: LibCrypto
.}

proc x509StoreNew(): pointer {.
  cdecl,
  importc: "X509_STORE_new",
  dynlib: LibCrypto
.}

proc x509StoreFree(store: pointer) {.
  cdecl,
  importc: "X509_STORE_free",
  dynlib: LibCrypto
.}

proc x509StoreAddCertificate(store: pointer, certificate: pointer): cint {.
  cdecl,
  importc: "X509_STORE_add_cert",
  dynlib: LibCrypto
.}

proc x509StoreContextNew(): pointer {.
  cdecl,
  importc: "X509_STORE_CTX_new",
  dynlib: LibCrypto
.}

proc x509StoreContextFree(context: pointer) {.
  cdecl,
  importc: "X509_STORE_CTX_free",
  dynlib: LibCrypto
.}

proc x509StoreContextInit(
    context: pointer,
    store: pointer,
    certificate: pointer,
    untrusted: pointer
): cint {.
  cdecl,
  importc: "X509_STORE_CTX_init",
  dynlib: LibCrypto
.}

proc x509VerifyCertificate(context: pointer): cint {.
  cdecl,
  importc: "X509_verify_cert",
  dynlib: LibCrypto
.}

proc x509StoreContextGetError(context: pointer): cint {.
  cdecl,
  importc: "X509_STORE_CTX_get_error",
  dynlib: LibCrypto
.}

proc x509StoreContextGetErrorDepth(context: pointer): cint {.
  cdecl,
  importc: "X509_STORE_CTX_get_error_depth",
  dynlib: LibCrypto
.}

proc x509VerifyErrorString(errorCode: clong): cstring {.
  cdecl,
  importc: "X509_verify_cert_error_string",
  dynlib: LibCrypto
.}

proc opensslStackNewNull(): pointer {.
  cdecl,
  importc: "OPENSSL_sk_new_null",
  dynlib: LibCrypto
.}

proc opensslStackPush(stack: pointer, value: pointer): cint {.
  cdecl,
  importc: "OPENSSL_sk_push",
  dynlib: LibCrypto
.}

proc opensslStackFree(stack: pointer) {.
  cdecl,
  importc: "OPENSSL_sk_free",
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

proc opensslErrorClear() {.
  cdecl,
  importc: "ERR_clear_error",
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

proc freeCertificates(certificates: var seq[pointer]) =
  for certificate in certificates:
    if certificate != nil:
      x509Free(certificate)
  certificates.setLen(0)

# =============================================================================
# Public-key extraction
# =============================================================================

proc extractCertificatePublicKeySpkiDer*(
    certificateDer: openArray[uint8]
): SE[seq[uint8]] =
  ## Extracts the certificate SubjectPublicKeyInfo in DER form.
  ##
  ## This works for both ECC and RSA certificates and is intentionally generic;
  ## callers can compare or export the public key without any private-key
  ## operation or Provider dependency.
  let certificate = loadX509Certificate(certificateDer)
  if not certificate.ok:
    return fail[seq[uint8]](
      certificate.error.kind,
      certificate.error.message,
      certificate.error.sw
    )

  defer:
    x509Free(certificate.value)

  try:
    let publicKey = x509GetPubkey(certificate.value)
    if publicKey == nil:
      return fail[seq[uint8]](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to extract the certificate public key")
      )

    defer:
      evpPkeyFree(publicKey)

    let encodedLength = i2dPubkey(publicKey, nil)
    if encodedLength <= 0:
      return fail[seq[uint8]](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to measure SubjectPublicKeyInfo DER")
      )

    var encoded = newSeq[uint8](int(encodedLength))
    var cursor = encoded.bytePointer()
    let written = i2dPubkey(publicKey, addr cursor)
    if written != encodedLength:
      return fail[seq[uint8]](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to encode SubjectPublicKeyInfo DER")
      )

    result = ok(encoded)
  except CatchableError as e:
    result = fail[seq[uint8]](
      seCryptoError,
      "OpenSSL libcrypto is unavailable: " & e.msg
    )

# =============================================================================
# DER bundle handling
# =============================================================================

proc parseDerCertificateBundle*(
    bundle: openArray[uint8]
): SE[seq[seq[uint8]]] =
  ## Splits one or more concatenated DER X.509 certificates.
  ##
  ## Every element must be a complete DER SEQUENCE and must be accepted by
  ## OpenSSL's X.509 decoder. No whitespace or PEM framing is permitted.
  if bundle.len == 0:
    return fail[seq[seq[uint8]]](
      seInvalidArgument,
      "DER certificate bundle must not be empty"
    )

  var offset = 0
  var certificates: seq[seq[uint8]] = @[]

  while offset < bundle.len:
    if bundle[offset] != DerSequenceTag:
      return fail[seq[seq[uint8]]](
        seInvalidResponse,
        "DER certificate bundle entry does not start with a SEQUENCE"
      )

    let length = readTlvLength(bundle, offset + 1)
    if not length.ok:
      return fail[seq[seq[uint8]]](
        length.error.kind,
        "invalid DER certificate length in bundle: " & length.error.message,
        length.error.sw
      )

    let certificateEnd = length.value.nextIndex + length.value.length
    if certificateEnd <= offset or certificateEnd > bundle.len:
      return fail[seq[seq[uint8]]](
        seInvalidResponse,
        "DER certificate bundle entry is truncated"
      )

    let certificateDer = @bundle[offset ..< certificateEnd]
    let parsed = loadX509Certificate(certificateDer)
    if not parsed.ok:
      return fail[seq[seq[uint8]]](
        parsed.error.kind,
        parsed.error.message,
        parsed.error.sw
      )
    x509Free(parsed.value)

    certificates.add(certificateDer)
    offset = certificateEnd

  result = ok(certificates)

# =============================================================================
# Certificate-chain verification
# =============================================================================

proc verifyCertificateChain*(
    leafCertificateDer: openArray[uint8],
    trustAnchorsDer: openArray[seq[uint8]],
    intermediatesDer: openArray[seq[uint8]]
): SE[CertificateChainVerification] =
  ## Builds and validates the leaf certificate chain using only the supplied
  ## trust anchors and optional untrusted intermediate certificates.
  ##
  ## OpenSSL's normal certificate checks remain enabled, including signatures,
  ## issuer constraints, basic constraints, path length, and validity dates.
  if trustAnchorsDer.len == 0:
    return fail[CertificateChainVerification](
      seInvalidArgument,
      "at least one X.509 trust anchor is required"
    )

  let leaf = loadX509Certificate(leafCertificateDer)
  if not leaf.ok:
    return fail[CertificateChainVerification](
      leaf.error.kind,
      leaf.error.message,
      leaf.error.sw
    )

  var loadedAnchors: seq[pointer] = @[]
  var loadedIntermediates: seq[pointer] = @[]

  defer:
    x509Free(leaf.value)
    freeCertificates(loadedAnchors)
    freeCertificates(loadedIntermediates)

  try:
    let store = x509StoreNew()
    if store == nil:
      return fail[CertificateChainVerification](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to allocate an X.509 trust store")
      )

    defer:
      x509StoreFree(store)

    for index, anchorDer in trustAnchorsDer:
      let anchor = loadX509Certificate(anchorDer)
      if not anchor.ok:
        return fail[CertificateChainVerification](
          anchor.error.kind,
          "invalid trust anchor #" & $(index + 1) & ": " & anchor.error.message,
          anchor.error.sw
        )

      loadedAnchors.add(anchor.value)
      opensslErrorClear()
      if x509StoreAddCertificate(store, anchor.value) != 1:
        return fail[CertificateChainVerification](
          seCryptoError,
          opensslErrorMessage(
            "OpenSSL failed to add trust anchor #" & $(index + 1)
          )
        )

    var untrustedStack: pointer = nil
    if intermediatesDer.len > 0:
      untrustedStack = opensslStackNewNull()
      if untrustedStack == nil:
        return fail[CertificateChainVerification](
          seCryptoError,
          opensslErrorMessage("OpenSSL failed to allocate an intermediate certificate stack")
        )

    defer:
      if untrustedStack != nil:
        opensslStackFree(untrustedStack)

    for index, intermediateDer in intermediatesDer:
      let intermediate = loadX509Certificate(intermediateDer)
      if not intermediate.ok:
        return fail[CertificateChainVerification](
          intermediate.error.kind,
          "invalid intermediate certificate #" & $(index + 1) & ": " &
            intermediate.error.message,
          intermediate.error.sw
        )

      loadedIntermediates.add(intermediate.value)
      if opensslStackPush(untrustedStack, intermediate.value) <= 0:
        return fail[CertificateChainVerification](
          seCryptoError,
          opensslErrorMessage(
            "OpenSSL failed to add intermediate certificate #" & $(index + 1)
          )
        )

    let context = x509StoreContextNew()
    if context == nil:
      return fail[CertificateChainVerification](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to allocate an X.509 verification context")
      )

    defer:
      x509StoreContextFree(context)

    if x509StoreContextInit(context, store, leaf.value, untrustedStack) != 1:
      return fail[CertificateChainVerification](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to initialize X.509 chain verification")
      )

    let verified = x509VerifyCertificate(context)
    case verified
    of 1:
      result = ok(CertificateChainVerification(
        trustAnchorCount: trustAnchorsDer.len,
        intermediateCount: intermediatesDer.len
      ))
    of 0:
      let errorCode = x509StoreContextGetError(context)
      let errorDepth = x509StoreContextGetErrorDepth(context)
      let description = x509VerifyErrorString(clong(errorCode))
      result = fail[CertificateChainVerification](
        seCertificateUntrusted,
        "X.509 certificate chain verification failed at depth " &
          $errorDepth & " (error " & $errorCode & "): " & $description
      )
    else:
      result = fail[CertificateChainVerification](
        seCryptoError,
        opensslErrorMessage("OpenSSL X.509 chain verification failed internally")
      )
  except CatchableError as e:
    result = fail[CertificateChainVerification](
      seCryptoError,
      "OpenSSL certificate-chain verification failed: " & e.msg
    )

proc verifyCertificateChain*(
    leafCertificateDer: openArray[uint8],
    trustAnchorsDer: openArray[seq[uint8]]
): SE[CertificateChainVerification] =
  ## Convenience overload for a chain without separately supplied intermediates.
  let noIntermediates: seq[seq[uint8]] = @[]
  result = verifyCertificateChain(
    leafCertificateDer,
    trustAnchorsDer,
    noIntermediates
  )
