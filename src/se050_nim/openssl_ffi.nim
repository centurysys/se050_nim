# =============================================================================
# Minimal OpenSSL 3 host-side FFI
# =============================================================================
#
# Shared libcrypto binding used by host-side certificate and cryptographic
# helpers. The binding intentionally uses opaque pointers and runtime symbol
# loading so building se050_nim does not require OpenSSL C headers or a
# libcrypto.so development symlink. The target system must provide
# libcrypto.so.3.
#
# Keep OpenSSL C imports in this module. Higher-level modules should build
# validation and SE050-specific behavior on top of these bindings instead of
# declaring their own libcrypto FFI.

import std/strutils

import ./errors

const
  LibCrypto = "libcrypto.so.3"

proc opensslSha256*(
    data: ptr uint8,
    length: csize_t,
    digest: ptr uint8
): ptr uint8 {.cdecl, importc: "SHA256", dynlib: LibCrypto.}

proc d2iX509*(
    certificate: ptr pointer,
    input: ptr ptr uint8,
    length: clong
): pointer {.cdecl, importc: "d2i_X509", dynlib: LibCrypto.}

proc x509Free*(certificate: pointer) {.
  cdecl,
  importc: "X509_free",
  dynlib: LibCrypto
.}

proc x509GetPublicKey*(certificate: pointer): pointer {.
  cdecl,
  importc: "X509_get_pubkey",
  dynlib: LibCrypto
.}

proc evpPublicKeyFree*(publicKey: pointer) {.
  cdecl,
  importc: "EVP_PKEY_free",
  dynlib: LibCrypto
.}

proc evpPublicKeyIsA*(publicKey: pointer, name: cstring): cint {.
  cdecl,
  importc: "EVP_PKEY_is_a",
  dynlib: LibCrypto
.}

proc evpPublicKeyGetBits*(publicKey: pointer): cint {.
  cdecl,
  importc: "EVP_PKEY_get_bits",
  dynlib: LibCrypto
.}

proc evpPublicKeyGetUtf8StringParam*(
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

proc evpPublicKeyGetOctetStringParam*(
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

proc evpPublicKeyGetBnParam*(
    publicKey: pointer,
    key: cstring,
    value: ptr pointer
): cint {.
  cdecl,
  importc: "EVP_PKEY_get_bn_param",
  dynlib: LibCrypto
.}

proc evpPublicKeyContextNewFromPkey*(
    libraryContext: pointer,
    publicKey: pointer,
    propertyQuery: cstring
): pointer {.
  cdecl,
  importc: "EVP_PKEY_CTX_new_from_pkey",
  dynlib: LibCrypto
.}

proc evpPublicKeyContextFree*(context: pointer) {.
  cdecl,
  importc: "EVP_PKEY_CTX_free",
  dynlib: LibCrypto
.}

proc evpPublicKeyPrivateCheck*(context: pointer): cint {.
  cdecl,
  importc: "EVP_PKEY_private_check",
  dynlib: LibCrypto
.}

proc evpPublicKeyPairwiseCheck*(context: pointer): cint {.
  cdecl,
  importc: "EVP_PKEY_pairwise_check",
  dynlib: LibCrypto
.}

proc bnToBinaryPadded*(
    value: pointer,
    output: ptr uint8,
    outputLength: cint
): cint {.
  cdecl,
  importc: "BN_bn2binpad",
  dynlib: LibCrypto
.}

proc bnFree*(value: pointer) {.
  cdecl,
  importc: "BN_free",
  dynlib: LibCrypto
.}

proc osslDecoderContextNewForPkey*(
    publicKey: ptr pointer,
    inputType: cstring,
    inputStructure: cstring,
    keyType: cstring,
    selection: cint,
    libraryContext: pointer,
    propertyQuery: cstring
): pointer {.
  cdecl,
  importc: "OSSL_DECODER_CTX_new_for_pkey",
  dynlib: LibCrypto
.}

proc osslDecoderContextFree*(context: pointer) {.
  cdecl,
  importc: "OSSL_DECODER_CTX_free",
  dynlib: LibCrypto
.}

proc osslDecoderFromData*(
    context: pointer,
    data: ptr ptr uint8,
    dataLength: ptr csize_t
): cint {.
  cdecl,
  importc: "OSSL_DECODER_from_data",
  dynlib: LibCrypto
.}

proc evpMdContextNew*(): pointer {.
  cdecl,
  importc: "EVP_MD_CTX_new",
  dynlib: LibCrypto
.}

proc evpMdContextFree*(context: pointer) {.
  cdecl,
  importc: "EVP_MD_CTX_free",
  dynlib: LibCrypto
.}

proc evpSha256*(): pointer {.
  cdecl,
  importc: "EVP_sha256",
  dynlib: LibCrypto
.}

proc evpDigestVerifyInit*(
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

proc evpDigestVerify*(
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

proc i2dPublicKey*(publicKey: pointer, output: ptr ptr uint8): cint {.
  cdecl,
  importc: "i2d_PUBKEY",
  dynlib: LibCrypto
.}

proc x509StoreNew*(): pointer {.
  cdecl,
  importc: "X509_STORE_new",
  dynlib: LibCrypto
.}

proc x509StoreFree*(store: pointer) {.
  cdecl,
  importc: "X509_STORE_free",
  dynlib: LibCrypto
.}

proc x509StoreAddCertificate*(store: pointer, certificate: pointer): cint {.
  cdecl,
  importc: "X509_STORE_add_cert",
  dynlib: LibCrypto
.}

proc x509StoreContextNew*(): pointer {.
  cdecl,
  importc: "X509_STORE_CTX_new",
  dynlib: LibCrypto
.}

proc x509StoreContextFree*(context: pointer) {.
  cdecl,
  importc: "X509_STORE_CTX_free",
  dynlib: LibCrypto
.}

proc x509StoreContextInit*(
    context: pointer,
    store: pointer,
    certificate: pointer,
    untrusted: pointer
): cint {.
  cdecl,
  importc: "X509_STORE_CTX_init",
  dynlib: LibCrypto
.}

proc x509VerifyCertificate*(context: pointer): cint {.
  cdecl,
  importc: "X509_verify_cert",
  dynlib: LibCrypto
.}

proc x509StoreContextGetError*(context: pointer): cint {.
  cdecl,
  importc: "X509_STORE_CTX_get_error",
  dynlib: LibCrypto
.}

proc x509StoreContextGetErrorDepth*(context: pointer): cint {.
  cdecl,
  importc: "X509_STORE_CTX_get_error_depth",
  dynlib: LibCrypto
.}

proc x509VerifyErrorString*(errorCode: clong): cstring {.
  cdecl,
  importc: "X509_verify_cert_error_string",
  dynlib: LibCrypto
.}

proc opensslStackNewNull*(): pointer {.
  cdecl,
  importc: "OPENSSL_sk_new_null",
  dynlib: LibCrypto
.}

proc opensslStackPush*(stack: pointer, value: pointer): cint {.
  cdecl,
  importc: "OPENSSL_sk_push",
  dynlib: LibCrypto
.}

proc opensslStackFree*(stack: pointer) {.
  cdecl,
  importc: "OPENSSL_sk_free",
  dynlib: LibCrypto
.}

proc opensslErrorGet*(): culong {.
  cdecl,
  importc: "ERR_get_error",
  dynlib: LibCrypto
.}

proc opensslErrorString*(
    errorCode: culong,
    buffer: cstring,
    bufferLength: csize_t
) {.
  cdecl,
  importc: "ERR_error_string_n",
  dynlib: LibCrypto
.}

proc opensslErrorClear*() {.
  cdecl,
  importc: "ERR_clear_error",
  dynlib: LibCrypto
.}

proc bytePointer*(data: openArray[uint8]): ptr uint8 =
  if data.len == 0:
    result = nil
  else:
    result = cast[ptr uint8](unsafeAddr data[0])

proc opensslErrorMessage*(fallback: string): string =
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

proc loadX509Certificate*(certificateDer: openArray[uint8]): SE[pointer] =
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
