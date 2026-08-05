# =============================================================================
# Host-side external TLS private-key parsing
# =============================================================================
#
# Parses externally supplied private keys through OpenSSL 3 without invoking
# the openssl command-line tool. This first implementation deliberately
# accepts only NIST P-256 EC private keys, matching the currently supported
# managed TLS identity profile.
#
# No private scalar is exported or retained by this module. The decoded
# EVP_PKEY exists only while the input is being validated and public metadata
# is extracted. A later import step can add narrowly scoped private-component
# extraction immediately before the SE050 write operation.

import ../errors
import ../openssl_ffi

# =============================================================================
# Types and constants
# =============================================================================

type
  P256PrivateKeyInfo* = object
    ## Validated public metadata derived from an external P-256 private key.
    ##
    ## The original private material and OpenSSL EVP_PKEY are intentionally not
    ## retained in this value.
    bits*: int
    curveName*: string
    publicKey*: array[65, uint8]
    publicKeySpkiDer*: seq[uint8]

  ValidatedP256PrivateKey = object
    handle: pointer
    curveName: string

const
  P256Bits = 256
  P256UncompressedPublicKeyLength = 65

  OpenSslParamGroupName = "group"
  OpenSslParamPublicX = "qx"
  OpenSslParamPublicY = "qy"

# =============================================================================
# Internal helpers
# =============================================================================

proc decodePrivateKey(encodedKey: openArray[uint8]): SE[pointer] =
  if encodedKey.len == 0:
    return fail[pointer](
      seInvalidArgument,
      "external private key must not be empty"
    )

  var publicKey: pointer = nil
  var decoderContext: pointer = nil

  try:
    opensslErrorClear()

    decoderContext = osslDecoderContextNewForPkey(
      addr publicKey,
      nil,
      nil,
      nil,
      0,
      nil,
      nil
    )
    if decoderContext == nil:
      return fail[pointer](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to create the private-key decoder")
      )

    var cursor = encodedKey.bytePointer()
    var remaining = csize_t(encodedKey.len)
    if osslDecoderFromData(decoderContext, addr cursor, addr remaining) != 1 or
        publicKey == nil:
      if publicKey != nil:
        evpPublicKeyFree(publicKey)
        publicKey = nil
      return fail[pointer](
        seCryptoError,
        opensslErrorMessage(
          "OpenSSL failed to decode the external private key as PEM or DER"
        )
      )

    if remaining != 0:
      evpPublicKeyFree(publicKey)
      publicKey = nil
      return fail[pointer](
        seInvalidResponse,
        "external private key contains trailing or unparsed bytes"
      )

    result = ok(publicKey)
    publicKey = nil
  except CatchableError as e:
    if publicKey != nil:
      evpPublicKeyFree(publicKey)
      publicKey = nil
    result = fail[pointer](
      seCryptoError,
      "OpenSSL libcrypto is unavailable: " & e.msg
    )
  finally:
    if decoderContext != nil:
      osslDecoderContextFree(decoderContext)

proc readGroupName(publicKey: pointer): SE[string] =
  var buffer: array[80, char]
  var outputLength: csize_t

  if evpPublicKeyGetUtf8StringParam(
      publicKey,
      OpenSslParamGroupName,
      cast[cstring](addr buffer[0]),
      csize_t(buffer.len),
      addr outputLength
  ) != 1:
    return fail[string](
      seCryptoError,
      opensslErrorMessage("OpenSSL failed to read the EC group name")
    )

  result = ok($cast[cstring](addr buffer[0]))

proc validateP256PrivateKey(publicKey: pointer): SE[string] =
  if evpPublicKeyIsA(publicKey, "EC") != 1:
    return fail[string](
      seInvalidArgument,
      "external TLS private key is not an EC key"
    )

  let bits = evpPublicKeyGetBits(publicKey)
  if int(bits) != P256Bits:
    return fail[string](
      seInvalidArgument,
      "external TLS EC private key is not a 256-bit P-256 key"
    )

  let group = readGroupName(publicKey)
  if not group.ok:
    return group

  if group.value != "prime256v1" and
      group.value != "secp256r1" and
      group.value != "P-256":
    return fail[string](
      seInvalidArgument,
      "external TLS EC private key uses unsupported group: " & group.value
    )

  let validationContext = evpPublicKeyContextNewFromPkey(nil, publicKey, nil)
  if validationContext == nil:
    return fail[string](
      seCryptoError,
      opensslErrorMessage("OpenSSL failed to create the private-key validation context")
    )

  defer:
    evpPublicKeyContextFree(validationContext)

  if evpPublicKeyPrivateCheck(validationContext) != 1:
    return fail[string](
      seInvalidArgument,
      opensslErrorMessage("external TLS P-256 private key failed private-key validation")
    )

  if evpPublicKeyPairwiseCheck(validationContext) != 1:
    return fail[string](
      seInvalidArgument,
      opensslErrorMessage("external TLS P-256 key pair failed pairwise validation")
    )

  result = ok(group.value)

proc readP256PublicCoordinate(
    publicKey: pointer,
    parameterName: cstring,
    output: var array[32, uint8]
): SE[void] =
  var value: pointer = nil
  if evpPublicKeyGetBnParam(publicKey, parameterName, addr value) != 1 or
      value == nil:
    return fail[void](
      seCryptoError,
      opensslErrorMessage("OpenSSL failed to read a P-256 public coordinate")
    )

  defer:
    bnFree(value)

  let written = bnToBinaryPadded(value, addr output[0], cint(output.len))
  if written != cint(output.len):
    return fail[void](
      seCryptoError,
      opensslErrorMessage("OpenSSL failed to encode a P-256 public coordinate")
    )

  result = ok()

proc readP256PublicKey(publicKey: pointer): SE[array[65, uint8]] =
  var x: array[32, uint8]
  var y: array[32, uint8]

  let xResult = readP256PublicCoordinate(publicKey, OpenSslParamPublicX, x)
  if not xResult.ok:
    return fail[array[65, uint8]](
      xResult.error.kind,
      xResult.error.message,
      xResult.error.sw
    )

  let yResult = readP256PublicCoordinate(publicKey, OpenSslParamPublicY, y)
  if not yResult.ok:
    return fail[array[65, uint8]](
      yResult.error.kind,
      yResult.error.message,
      yResult.error.sw
    )

  var encoded: array[65, uint8]
  encoded[0] = 0x04'u8
  for i in 0 ..< x.len:
    encoded[1 + i] = x[i]
    encoded[33 + i] = y[i]

  result = ok(encoded)

proc encodePublicKeySpkiDer(publicKey: pointer): SE[seq[uint8]] =
  let encodedLength = i2dPublicKey(publicKey, nil)
  if encodedLength <= 0:
    return fail[seq[uint8]](
      seCryptoError,
      opensslErrorMessage("OpenSSL failed to measure SubjectPublicKeyInfo DER")
    )

  var encoded = newSeq[uint8](int(encodedLength))
  var cursor = encoded.bytePointer()
  let written = i2dPublicKey(publicKey, addr cursor)
  if written != encodedLength:
    return fail[seq[uint8]](
      seCryptoError,
      opensslErrorMessage("OpenSSL failed to encode SubjectPublicKeyInfo DER")
    )

  result = ok(encoded)

proc loadValidatedP256PrivateKey(
    encodedKey: openArray[uint8]
): SE[ValidatedP256PrivateKey] =
  let decoded = decodePrivateKey(encodedKey)
  if not decoded.ok:
    return fail[ValidatedP256PrivateKey](
      decoded.error.kind,
      decoded.error.message,
      decoded.error.sw
    )

  let validation = validateP256PrivateKey(decoded.value)
  if not validation.ok:
    evpPublicKeyFree(decoded.value)
    return fail[ValidatedP256PrivateKey](
      validation.error.kind,
      validation.error.message,
      validation.error.sw
    )

  result = ok(ValidatedP256PrivateKey(
    handle: decoded.value,
    curveName: validation.value
  ))

proc extractP256PrivateKeyInfo(
    publicKeyHandle: pointer,
    curveName: string
): SE[P256PrivateKeyInfo] =
  let publicKey = readP256PublicKey(publicKeyHandle)
  if not publicKey.ok:
    return fail[P256PrivateKeyInfo](
      publicKey.error.kind,
      publicKey.error.message,
      publicKey.error.sw
    )

  let spki = encodePublicKeySpkiDer(publicKeyHandle)
  if not spki.ok:
    return fail[P256PrivateKeyInfo](
      spki.error.kind,
      spki.error.message,
      spki.error.sw
    )

  result = ok(P256PrivateKeyInfo(
    bits: P256Bits,
    curveName: curveName,
    publicKey: publicKey.value,
    publicKeySpkiDer: spki.value
  ))

proc parseP256PrivateKeyBytes(
    encodedKey: openArray[uint8]
): SE[P256PrivateKeyInfo] =
  let decoded = loadValidatedP256PrivateKey(encodedKey)
  if not decoded.ok:
    return fail[P256PrivateKeyInfo](
      decoded.error.kind,
      decoded.error.message,
      decoded.error.sw
    )

  defer:
    evpPublicKeyFree(decoded.value.handle)

  try:
    result = extractP256PrivateKeyInfo(
      decoded.value.handle,
      decoded.value.curveName
    )
  except CatchableError as e:
    result = fail[P256PrivateKeyInfo](
      seCryptoError,
      "OpenSSL private-key handling failed: " & e.msg
    )

proc validateP256PrivateKeyCertificateMatchBytes(
    encodedKey: openArray[uint8],
    certificateDer: openArray[uint8]
): SE[P256PrivateKeyInfo] =
  let decoded = loadValidatedP256PrivateKey(encodedKey)
  if not decoded.ok:
    return fail[P256PrivateKeyInfo](
      decoded.error.kind,
      decoded.error.message,
      decoded.error.sw
    )

  defer:
    evpPublicKeyFree(decoded.value.handle)

  let certificate = loadX509Certificate(certificateDer)
  if not certificate.ok:
    return fail[P256PrivateKeyInfo](
      certificate.error.kind,
      certificate.error.message,
      certificate.error.sw
    )

  defer:
    x509Free(certificate.value)

  try:
    let certificatePublicKey = x509GetPublicKey(certificate.value)
    if certificatePublicKey == nil:
      return fail[P256PrivateKeyInfo](
        seCryptoError,
        opensslErrorMessage("OpenSSL failed to extract the certificate public key")
      )

    defer:
      evpPublicKeyFree(certificatePublicKey)

    opensslErrorClear()
    let comparison = evpPublicKeyEq(decoded.value.handle, certificatePublicKey)
    case comparison
    of 1:
      result = extractP256PrivateKeyInfo(
        decoded.value.handle,
        decoded.value.curveName
      )
    of 0, -1:
      result = fail[P256PrivateKeyInfo](
        seInvalidArgument,
        "certificate public key does not match the external TLS P-256 private key"
      )
    of -2:
      result = fail[P256PrivateKeyInfo](
        seCryptoError,
        "OpenSSL does not support comparing the external private key and " &
          "certificate public key"
      )
    else:
      result = fail[P256PrivateKeyInfo](
        seCryptoError,
        opensslErrorMessage(
          "OpenSSL failed to compare the external private key and certificate public key"
        )
      )
  except CatchableError as e:
    result = fail[P256PrivateKeyInfo](
      seCryptoError,
      "OpenSSL private-key/certificate matching failed: " & e.msg
    )

# =============================================================================
# Public API
# =============================================================================

proc parseP256PrivateKey*(
    encodedKey: openArray[uint8]
): SE[P256PrivateKeyInfo] =
  ## Parses and validates one unencrypted P-256 private key from PEM or DER.
  ##
  ## OpenSSL's decoder auto-detects PKCS#8 and type-specific EC encodings. The
  ## entire input must be consumed. This API returns only public metadata; it
  ## never exports or retains the private scalar.
  result = parseP256PrivateKeyBytes(encodedKey)

proc parseP256PrivateKey*(encodedKey: string): SE[P256PrivateKeyInfo] =
  ## String overload suitable for binary-safe `readFile()` input.
  if encodedKey.len == 0:
    return fail[P256PrivateKeyInfo](
      seInvalidArgument,
      "external private key must not be empty"
    )

  result = parseP256PrivateKeyBytes(
    encodedKey.toOpenArrayByte(0, encodedKey.high)
  )

proc validateP256PrivateKeyCertificateMatch*(
    encodedKey: openArray[uint8],
    certificateDer: openArray[uint8]
): SE[P256PrivateKeyInfo] =
  ## Parses and validates a P-256 private key and verifies that its key pair
  ## matches the SubjectPublicKeyInfo contained in the DER certificate.
  ##
  ## The comparison uses OpenSSL EVP_PKEY semantics rather than bytewise SPKI
  ## comparison. No SE050 operation is performed by this API.
  result = validateP256PrivateKeyCertificateMatchBytes(encodedKey, certificateDer)

proc validateP256PrivateKeyCertificateMatch*(
    encodedKey: string,
    certificateDer: openArray[uint8]
): SE[P256PrivateKeyInfo] =
  ## String overload suitable for binary-safe `readFile()` private-key input.
  if encodedKey.len == 0:
    return fail[P256PrivateKeyInfo](
      seInvalidArgument,
      "external private key must not be empty"
    )

  result = validateP256PrivateKeyCertificateMatchBytes(
    encodedKey.toOpenArrayByte(0, encodedKey.high),
    certificateDer
  )

