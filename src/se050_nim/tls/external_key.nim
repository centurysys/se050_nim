# =============================================================================
# Host-side external TLS private-key parsing
# =============================================================================
#
# Parses externally supplied private keys through OpenSSL 3 without invoking
# the openssl command-line tool. This first implementation deliberately
# accepts only NIST P-256 EC private keys, matching the currently supported
# managed TLS identity profile.
#
# No public API exports or retains the private scalar. The decoded EVP_PKEY
# exists only while the input is being validated. The import path extracts the
# P-256 scalar only after all host-side checks and the SE050 empty-slot guard,
# sends it through the sensitive transport path, and clears the temporary copy.

import ../errors
import ../openssl_ffi
import ../secure_memory
import ../transport
import ../apdu
import ../objects
import ../keys
import ./profile
import ./live_identity

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
  OpenSslParamPrivate = "priv"
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

proc readP256PrivateScalar(
    publicKey: pointer,
    output: var array[32, uint8]
): SE[void] =
  ## Extracts the validated P-256 private scalar into a caller-owned temporary
  ## buffer. The OpenSSL BIGNUM is cleared before release; the caller must also
  ## clear `output` as soon as the SE050 write has completed.
  var value: pointer = nil

  opensslErrorClear()
  if evpPublicKeyGetBnParam(publicKey, OpenSslParamPrivate, addr value) != 1 or
      value == nil:
    return fail[void](
      seCryptoError,
      opensslErrorMessage("OpenSSL failed to read the P-256 private scalar")
    )

  defer:
    bnClearFree(value)

  let written = bnToBinaryPadded(value, addr output[0], cint(output.len))
  if written != cint(output.len):
    return fail[void](
      seCryptoError,
      opensslErrorMessage("OpenSSL failed to encode the P-256 private scalar")
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

proc validateP256PrivateKeyCertificateMatchHandle(
    decoded: ValidatedP256PrivateKey,
    certificateDer: openArray[uint8]
): SE[P256PrivateKeyInfo] =
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
    let comparison = evpPublicKeyEq(decoded.handle, certificatePublicKey)
    case comparison
    of 1:
      result = extractP256PrivateKeyInfo(
        decoded.handle,
        decoded.curveName
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

  result = validateP256PrivateKeyCertificateMatchHandle(
    decoded.value,
    certificateDer
  )

proc withCleanupNote(
    primary: Se050Error,
    cleanupNote: string
): SE[TlsIdentityLiveInfo] =
  if cleanupNote.len == 0:
    return fail[TlsIdentityLiveInfo](
      primary.kind,
      primary.message,
      primary.sw
    )

  result = fail[TlsIdentityLiveInfo](
    primary.kind,
    primary.message & "; " & cleanupNote,
    primary.sw
  )

proc cleanupNewTlsIdentityObject(
    se: Se050Transport,
    profile: TlsIdentityProfile
): string =
  ## Best-effort cleanup after an import attempt. The slot was proven empty
  ## immediately before WriteECKey, so any object now present was created by
  ## this import attempt.
  let exists = se.objectExists(
    objectId = profile.keyObjectId,
    selectFirst = false
  )
  if not exists.ok:
    return "cleanup could not confirm imported object state: " &
      exists.error.errorMessage()

  if not exists.value:
    return ""

  let deleted = se.deleteSecureObject(
    objectId = profile.keyObjectId,
    selectFirst = false
  )
  if not deleted.ok:
    return "cleanup could not delete the newly imported TLS object: " &
      deleted.error.errorMessage()

  result = ""

proc importP256TlsIdentityBytes(
    se: Se050Transport,
    profile: TlsIdentityProfile,
    encodedKey: openArray[uint8],
    certificateDer: openArray[uint8]
): SE[TlsIdentityLiveInfo] =
  ## Imports one externally generated P-256 TLS identity after completing all
  ## host-side key/certificate checks and proving that the managed slot is empty.
  if not profile.isValid():
    return fail[TlsIdentityLiveInfo](
      seInvalidArgument,
      "TLS identity profile is invalid"
    )

  let decoded = loadValidatedP256PrivateKey(encodedKey)
  if not decoded.ok:
    return fail[TlsIdentityLiveInfo](
      decoded.error.kind,
      decoded.error.message,
      decoded.error.sw
    )

  defer:
    evpPublicKeyFree(decoded.value.handle)

  let keyInfo = validateP256PrivateKeyCertificateMatchHandle(
    decoded.value,
    certificateDer
  )
  if not keyInfo.ok:
    return fail[TlsIdentityLiveInfo](
      keyInfo.error.kind,
      keyInfo.error.message,
      keyInfo.error.sw
    )

  # No SE050 command is issued until the complete host-side key and certificate
  # validation above has succeeded.
  let selected = se.selectApplet()
  if not selected.ok:
    return fail[TlsIdentityLiveInfo](
      selected.error.kind,
      selected.error.message,
      selected.error.sw
    )

  let exists = se.objectExists(
    objectId = profile.keyObjectId,
    selectFirst = false
  )
  if not exists.ok:
    return fail[TlsIdentityLiveInfo](
      exists.error.kind,
      exists.error.message,
      exists.error.sw
    )

  if exists.value:
    return fail[TlsIdentityLiveInfo](
      seInvalidArgument,
      "TLS identity import refused because the managed object slot already exists"
    )

  # Extract the private scalar only after all validation and the empty-slot
  # guard have completed. This is the only extra CPU-side copy of the scalar.
  var privateScalar: array[32, uint8]
  let scalar = readP256PrivateScalar(decoded.value.handle, privateScalar)
  if not scalar.ok:
    secureZero(privateScalar)
    return fail[TlsIdentityLiveInfo](
      scalar.error.kind,
      scalar.error.message,
      scalar.error.sw
    )

  var imported: SE[void]
  try:
    imported = se.importP256KeyPair(
      objectId = profile.keyObjectId,
      privateKey = privateScalar,
      publicKey = keyInfo.value.publicKey,
      policy = profile.keyPolicy(),
      selectFirst = false
    )
  finally:
    secureZero(privateScalar)

  if not imported.ok:
    return withCleanupNote(
      imported.error,
      cleanupNewTlsIdentityObject(se, profile)
    )

  let live = se.inspectImportedTlsIdentity(profile)
  if not live.ok:
    return withCleanupNote(
      live.error,
      cleanupNewTlsIdentityObject(se, profile)
    )

  if live.value.publicKey != @(keyInfo.value.publicKey):
    let mismatch = Se050Error(
      kind: seTlsIdentityValidationFailed,
      message: "imported TLS public key does not match the validated external key",
      sw: 0
    )
    return withCleanupNote(
      mismatch,
      cleanupNewTlsIdentityObject(se, profile)
    )

  result = live

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


proc importP256TlsIdentity*(
    se: Se050Transport,
    profile: TlsIdentityProfile,
    encodedKey: openArray[uint8],
    certificateDer: openArray[uint8]
): SE[TlsIdentityLiveInfo] =
  ## Imports an externally generated P-256 private key into one managed TLS slot.
  ##
  ## The private key and DER certificate are fully parsed and matched before any
  ## SE050 command is issued. Existing objects are never overwritten. The
  ## private scalar is extracted only immediately before WriteECKey, sent over
  ## the sensitive transport path, and its temporary CPU copy is then cleared.
  ##
  ## On a failed WriteECKey or failed post-import live validation, the function
  ## makes a best-effort attempt to remove any object created by this call.
  ##
  ## Ownership of `encodedKey` remains with the caller. A caller that loaded the
  ## key into mutable memory (for example with readFile()) should clear that
  ## original buffer after this function returns.
  result = importP256TlsIdentityBytes(
    se = se,
    profile = profile,
    encodedKey = encodedKey,
    certificateDer = certificateDer
  )

proc importP256TlsIdentity*(
    se: Se050Transport,
    profile: TlsIdentityProfile,
    encodedKey: string,
    certificateDer: openArray[uint8]
): SE[TlsIdentityLiveInfo] =
  ## Binary-safe string overload for private-key file contents.
  if encodedKey.len == 0:
    return fail[TlsIdentityLiveInfo](
      seInvalidArgument,
      "external private key must not be empty"
    )

  result = importP256TlsIdentityBytes(
    se = se,
    profile = profile,
    encodedKey = encodedKey.toOpenArrayByte(0, encodedKey.high),
    certificateDer = certificateDer
  )

