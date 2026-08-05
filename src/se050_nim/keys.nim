# =============================================================================
# SE050 key management helpers
# =============================================================================
#
# Low-level helpers for creating SE050 key objects and using EC key objects.
#
# This module intentionally exposes SE050 primitive operations. Product policy,
# factory provisioning records, firmware envelope handling, and CLI safety
# guards belong in higher layers.

import ./errors
import ./transport
import ./apdu
import ./tlv
import ./objects
import ./secure_memory

# =============================================================================
# Constants
# =============================================================================

const
  TagPolicy = 0x11'u8
  Tag1 = 0x41'u8
  Tag2 = 0x42'u8
  Tag3 = 0x43'u8
  Tag4 = 0x44'u8
  Tag7 = 0x47'u8

  # SE05x WriteECKey APDU for generating an EC key pair inside SE050.
  #
  # NXP Plug & Trust names this command:
  #   CLA = 0x80
  #   INS = INS_WRITE = 0x01
  #   P1  = P1_KEY_PAIR | P1_EC = 0x60 | 0x01 = 0x61
  #   P2  = P2_DEFAULT = 0x00
  #
  # Command data for internal key generation:
  #   TAG_POLICY: development policy allowing read/delete/key-agreement
  #   TAG_1     : 4-byte Secure Object identifier
  #   TAG_2     : 1-byte ECCurve identifier
  #
  # TAG_3 private key and TAG_4 public key are deliberately omitted. For
  # P1_KEY_PAIR, omitting both TAG_3 and TAG_4 requests key generation inside
  # the SE050.
  WriteEcKeyCla = 0x80'u8
  WriteEcKeyIns = 0x01'u8
  WriteEcKeyP1KeyPairEc = 0x61'u8
  WriteEcKeyP2Default = 0x00'u8

  # ECCurve constants.
  Se050CurveNistP256* = 0x03'u8
  Se050CurveNistP384* = 0x04'u8
  Se050CurveNistP521* = 0x05'u8
  Se050CurveX25519* = 0x41'u8

  # SecureObjectType constants used by ReadType after key generation.
  Se050TypeEcKeyPair* = 0x01'u8
  Se050TypeEcKeyPairNistP256* = 0x29'u8
  Se050TypeEcPrivKeyNistP256* = 0x2A'u8
  Se050TypeEcPubKeyNistP256* = 0x2B'u8
  Se050TypeEcKeyPairMontDh25519* = 0x69'u8
  Se050TypeEcPrivKeyMontDh25519* = 0x6A'u8
  Se050TypeEcPubKeyMontDh25519* = 0x6B'u8

  # Object policy bits from NXP se05x_const.h.
  #
  # These constants are intentionally kept private. Library users should build
  # object policies through the EcKeyPolicy helpers below instead of composing
  # access-rule bits directly. Explicitly adding ALLOW_KA is required for
  # ECDHGenerateSharedSecret; otherwise the applet may return SW=0x6985
  # (conditions not satisfied) for derive operations.
  PolicyObjAllowSign = 0x10000000'u32
  PolicyObjAllowKa = 0x04000000'u32
  PolicyObjAllowRead = 0x00200000'u32
  PolicyObjAllowWrite = 0x00100000'u32
  PolicyObjAllowGen = 0x00080000'u32
  PolicyObjAllowDelete = 0x00040000'u32

  # One default-auth object-policy entry layout used by Plug & Trust:
  #   byte 0      : length of the policy entry excluding this length byte
  #   bytes 1..4  : auth object ID (0 means default/no auth object)
  #   bytes 5..8  : access-rule header bits
  #
  # This is later wrapped as TLV[TAG_POLICY].
  ObjectPolicyEntryLen = 0x08'u8
  DefaultAuthObjectId = 0x00000000'u32

  # SE05x ECDHGenerateSharedSecret APDU.
  #
  # NXP Plug & Trust names this command:
  #   CLA = 0x80
  #   INS = INS_CRYPTO = 0x03
  #   P1  = P1_EC     = 0x01
  #   P2  = P2_DH     = 0x0F
  #
  # Command data:
  #   TAG_1: 4-byte identifier of the key pair or private key
  #   TAG_2: external public key
  #
  # The AN12413 ECDHGenerateSharedSecret APDU defines only TAG_1 and TAG_2
  # in the C-APDU payload. Do not add TAG_4 here; that tag belongs to other
  # crypto commands and causes SW=0x6985 on this applet.
  #
  # Response data, when TAG_7 output object is not supplied:
  #   TAG_1: returned shared secret
  EcdhCla = 0x80'u8
  EcdhInsCrypto = 0x03'u8
  EcdhP1Ec = 0x01'u8
  EcdhP2Dh = 0x0F'u8

  # SE05x ECDSASign APDU for a host-computed SHA-256 digest.
  #
  # NXP Plug & Trust names this command:
  #   CLA = 0x80
  #   INS = INS_CRYPTO   = 0x03
  #   P1  = P1_SIGNATURE = 0x0C
  #   P2  = P2_SIGN      = 0x09
  #
  # Command data:
  #   TAG_1: 4-byte identifier of the EC key pair or private key
  #   TAG_2: SIG_ECDSA_SHA_256 = 0x21
  #   TAG_3: 32-byte SHA-256 digest computed by the host
  #
  # Response data:
  #   TAG_1: ECDSA signature encoded as ASN.1 DER
  EcdsaSignCla = 0x80'u8
  EcdsaSignInsCrypto = 0x03'u8
  EcdsaSignP1Signature = 0x0C'u8
  EcdsaSignP2Sign = 0x09'u8
  Se050EcSignatureSha256* = 0x21'u8
  EcdsaSha256DigestLength* = 32

  # On-chip asymmetric key generation can take longer than normal object
  # inspection/random commands. During that time the T=1 over I2C layer may see
  # empty reads before the SE050 emits WTX or the final response. Keep the
  # extended wait local to key generation so quick commands keep failing fast.
  KeyGenerationMaxReadRetries = 200
  KeyImportMaxReadRetries = 200
  CryptoOperationMaxReadRetries = 200

  Se050P256PrivateKeyLength* = 32
  Se050P256UncompressedPublicKeyLength* = 65

# =============================================================================
# Types
# =============================================================================

type
  EcCurveKind* = enum
    ecCurveP256,
    ecCurveX25519

  EcKeyPolicy* = object
    ## Access-rule header for an SE050 EC key object policy entry.
    ##
    ## The current helpers create a single default-auth policy entry
    ## (auth object ID 0). The value is the 32-bit access-rule header used by
    ## Plug & Trust object policies.
    ##
    ## se050ctl intentionally keeps using only development policies. Higher-level
    ## provisioning/kitting tools may import this library and choose stricter
    ## policies for customer/vendor object ranges.
    header*: uint32

# =============================================================================
# Internal helpers
# =============================================================================

proc appendU32Be(buf: var seq[uint8], value: uint32) =
  buf.add(uint8((value shr 24) and 0xFF))
  buf.add(uint8((value shr 16) and 0xFF))
  buf.add(uint8((value shr 8) and 0xFF))
  buf.add(uint8(value and 0xFF))

proc appendTlvU32(buf: var seq[uint8], tag: uint8, value: uint32) =
  buf.add(tag)
  buf.add(0x04'u8)
  buf.appendU32Be(value)

proc appendTlvU8(buf: var seq[uint8], tag: uint8, value: uint8) =
  buf.add(tag)
  buf.add(0x01'u8)
  buf.add(value)

proc appendTlvBytes(buf: var seq[uint8], tag: uint8, value: openArray[uint8]) =
  buf.add(tag)
  if value.len < 0x80:
    buf.add(uint8(value.len))
  elif value.len <= 0xFF:
    buf.add(0x81'u8)
    buf.add(uint8(value.len))
  elif value.len <= 0xFFFF:
    buf.add(0x82'u8)
    buf.add(uint8((value.len shr 8) and 0xFF))
    buf.add(uint8(value.len and 0xFF))
  else:
    # The current short APDU path cannot carry this anyway, but keep the helper
    # total and let the APDU builder return seApduTooLarge with command context.
    buf.add(0x83'u8)
    buf.add(uint8((value.len shr 16) and 0xFF))
    buf.add(uint8((value.len shr 8) and 0xFF))
    buf.add(uint8(value.len and 0xFF))

  for b in value:
    buf.add(b)

proc curveId*(curve: EcCurveKind): uint8 =
  result = case curve
  of ecCurveP256: Se050CurveNistP256
  of ecCurveX25519: Se050CurveX25519

proc curveName*(curve: EcCurveKind): string =
  result = case curve
  of ecCurveP256: "p256"
  of ecCurveX25519: "x25519"

proc expectedKeyPairType*(curve: EcCurveKind): uint8 =
  result = case curve
  of ecCurveP256: Se050TypeEcKeyPairNistP256
  of ecCurveX25519: Se050TypeEcKeyPairMontDh25519

proc developmentEcKeyPolicy*(): EcKeyPolicy =
  ## Returns the default development EC key policy.
  ##
  ## This policy is intentionally permissive enough for iterative development:
  ## it allows public-key read/export, key agreement, overwrite/regeneration,
  ## and deletion. se050ctl uses this policy for development-range keys.
  result = EcKeyPolicy(
    header:
      PolicyObjAllowKa or
      PolicyObjAllowRead or
      PolicyObjAllowWrite or
      PolicyObjAllowGen or
      PolicyObjAllowDelete
  )

proc developmentSigningEcKeyPolicy*(): EcKeyPolicy =
  ## Returns a disposable development policy for EC signing-key experiments.
  ##
  ## This policy deliberately stays separate from developmentEcKeyPolicy() so
  ## existing ECDH development keys do not gain signing permission implicitly.
  ## It allows ECDSA signing, public-key read, overwrite/regeneration, and
  ## deletion. Key agreement is intentionally not enabled.
  ##
  ## Product TLS identity policies are defined by a higher layer and should use
  ## the minimum permissions required for their lifecycle.
  result = EcKeyPolicy(
    header:
      PolicyObjAllowSign or
      PolicyObjAllowRead or
      PolicyObjAllowWrite or
      PolicyObjAllowGen or
      PolicyObjAllowDelete
  )

proc deviceEcKeyPolicy*(): EcKeyPolicy =
  ## Returns a production-style device EC key policy.
  ##
  ## This policy is suitable for a device identity/key-agreement key that should
  ## be usable for P-256 ECDH and public-key export, but should not be
  ## overwritten, regenerated, or deleted by ordinary unauthenticated commands.
  ##
  ## Test this policy in a disposable development object ID before using it in a
  ## customer/vendor production range.
  result = EcKeyPolicy(
    header:
      PolicyObjAllowKa or
      PolicyObjAllowRead
  )

proc testDeviceKeyPolicy*(): EcKeyPolicy =
  ## Returns a production-like EC key policy for disposable test objects.
  ##
  ## The key has the same key-agreement and public-key read permissions as a
  ## production device key. DELETE is additionally allowed so development tests
  ## can remove the object and repeat the complete provisioning flow. WRITE and
  ## GEN stay disabled, preventing an existing test key from being overwritten
  ## or regenerated in place.
  result = EcKeyPolicy(
    header:
      PolicyObjAllowKa or
      PolicyObjAllowRead or
      PolicyObjAllowDelete
  )

proc oneTimeDeviceKeyPolicy*(): EcKeyPolicy =
  ## Returns a one-time-write style production EC key policy.
  ##
  ## For internally generated EC key pairs, the initial WriteECKey command creates
  ## the object and installs this policy. Because the resulting object does not
  ## allow WRITE, GEN, or DELETE, later overwrite/regeneration/deletion attempts
  ## should be rejected by the applet.
  ##
  ## In the current raw policy model this is equivalent to deviceEcKeyPolicy().
  ## It is kept as a separate API name so provisioning code can state its intent
  ## clearly and so future applet-specific one-time attributes can be added
  ## without changing callers.
  result = deviceEcKeyPolicy()

proc customEcKeyPolicy*(header: uint32): EcKeyPolicy =
  ## Builds an EC key policy from a raw Plug & Trust access-rule header.
  ##
  ## Use this only when the predefined helpers are not sufficient. The caller is
  ## responsible for validating that the supplied bit mask is correct for the
  ## target applet and object type.
  result = EcKeyPolicy(header: header)

proc policyHeader*(policy: EcKeyPolicy): uint32 =
  ## Returns the raw 32-bit access-rule header used by this policy.
  result = policy.header

proc encodeEcKeyPolicy(policy: EcKeyPolicy): seq[uint8] =
  ## Builds a single default-auth object-policy entry for WriteECKey.
  result = @[]
  result.add(ObjectPolicyEntryLen)
  result.appendU32Be(DefaultAuthObjectId)
  result.appendU32Be(policy.header)

proc buildDevelopmentEcKeyPolicy(): seq[uint8] =
  ## Builds the current default development policy entry for existing callers.
  result = encodeEcKeyPolicy(developmentEcKeyPolicy())

proc parseTag1Value(response: openArray[uint8], commandName: string): SE[seq[uint8]] =
  let st = checkStatus(response, commandName)
  if not st.ok:
    return fail[seq[uint8]](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[seq[uint8]](data.error.kind, data.error.message, data.error.sw)

  if data.value.len < 3:
    return fail[seq[uint8]](
      seInvalidResponse,
      commandName & " response does not contain TAG/LEN/VALUE"
    )

  if data.value[0] != Tag1:
    return fail[seq[uint8]](
      seInvalidResponse,
      commandName & " response does not start with TAG_1"
    )

  let tlvLen = readTlvLength(data.value, 1)
  if not tlvLen.ok:
    return fail[seq[uint8]](tlvLen.error.kind, tlvLen.error.message, tlvLen.error.sw)

  let valueStart = tlvLen.value.nextIndex
  let valueEnd = valueStart + tlvLen.value.length
  if valueEnd > data.value.len:
    return fail[seq[uint8]](
      seInvalidResponse,
      commandName & " response value is shorter than expected"
    )

  let value = data.value[valueStart ..< valueEnd]
  result = ok(value)

proc buildGenerateEcKeyPairApdu(
    objectId: uint32,
    curve: EcCurveKind,
    policy: EcKeyPolicy
): SE[seq[uint8]] =
  var payload: seq[uint8] = @[]

  # Put TAG_POLICY first, matching the order shown in the SE05x APDU
  # specification. The applet is generally TLV-based, but keeping the specified
  # order makes the raw APDU easier to compare with Plug & Trust logs.
  payload.appendTlvBytes(TagPolicy, encodeEcKeyPolicy(policy))
  payload.appendTlvU32(Tag1, objectId)
  payload.appendTlvU8(Tag2, curve.curveId())

  if payload.len > 255:
    return fail[seq[uint8]](
      seApduTooLarge,
      "WriteECKey payload is too large for a short APDU"
    )

  result.value = @[
    WriteEcKeyCla,
    WriteEcKeyIns,
    WriteEcKeyP1KeyPairEc,
    WriteEcKeyP2Default,
    uint8(payload.len)
  ]
  for b in payload:
    result.value.add(b)
  result.ok = true

proc buildImportP256KeyPairApdu*(
    objectId: uint32,
    privateKey: openArray[uint8],
    publicKey: openArray[uint8],
    policy: EcKeyPolicy
): SE[seq[uint8]] =
  ## Builds a WriteECKey APDU that imports an externally generated P-256 key pair.
  ##
  ## AN12413 requires TAG_3 (private key) and TAG_4 (public key) to either both
  ## be present or both be absent for P1_KEY_PAIR. P-256 private keys are exactly
  ## 32 bytes and Weierstrass public keys use 65-byte uncompressed 0x04 || X || Y
  ## encoding.
  ##
  ## The returned APDU contains the private scalar. Callers must treat it as
  ## sensitive memory and clear it after use.
  if privateKey.len != Se050P256PrivateKeyLength:
    return fail[seq[uint8]](
      seInvalidArgument,
      "P-256 private key must be exactly 32 bytes"
    )

  if publicKey.len != Se050P256UncompressedPublicKeyLength:
    return fail[seq[uint8]](
      seInvalidArgument,
      "P-256 public key must be exactly 65 bytes"
    )

  if publicKey[0] != 0x04'u8:
    return fail[seq[uint8]](
      seInvalidArgument,
      "P-256 public key must use uncompressed 0x04 || X || Y encoding"
    )

  var payload: seq[uint8] = @[]
  defer:
    secureZero(payload)

  payload.appendTlvBytes(TagPolicy, encodeEcKeyPolicy(policy))
  payload.appendTlvU32(Tag1, objectId)
  payload.appendTlvU8(Tag2, Se050CurveNistP256)
  payload.appendTlvBytes(Tag3, privateKey)
  payload.appendTlvBytes(Tag4, publicKey)

  if payload.len > 255:
    return fail[seq[uint8]](
      seApduTooLarge,
      "WriteECKey P-256 import payload is too large for a short APDU"
    )

  result.value = @[
    WriteEcKeyCla,
    WriteEcKeyIns,
    WriteEcKeyP1KeyPairEc,
    WriteEcKeyP2Default,
    uint8(payload.len)
  ]
  for b in payload:
    result.value.add(b)
  result.ok = true

proc buildEcdsaSignApdu*(
    objectId: uint32,
    digest: openArray[uint8]
): SE[seq[uint8]] =
  ## Builds an SE05x ECDSASign APDU for a host-computed SHA-256 digest.
  ##
  ## AN12413 requires TLV[TAG_3] to contain the digest rather than the original
  ## message and requires the input length to match the selected signature
  ## algorithm. The response is requested as ASN.1 DER in TLV[TAG_1].
  if digest.len != EcdsaSha256DigestLength:
    return fail[seq[uint8]](
      seInvalidArgument,
      "ECDSA/SHA-256 digest must be exactly 32 bytes"
    )

  var payload: seq[uint8] = @[]
  payload.appendTlvU32(Tag1, objectId)
  payload.appendTlvU8(Tag2, Se050EcSignatureSha256)
  payload.appendTlvBytes(Tag3, digest)

  if payload.len > 255:
    return fail[seq[uint8]](
      seApduTooLarge,
      "ECDSASign payload is too large for a short APDU"
    )

  result.value = @[
    EcdsaSignCla,
    EcdsaSignInsCrypto,
    EcdsaSignP1Signature,
    EcdsaSignP2Sign,
    uint8(payload.len)
  ]
  for b in payload:
    result.value.add(b)

  # Le: request the ASN.1 DER ECDSA signature in TLV[TAG_1].
  result.value.add(0x00'u8)
  result.ok = true

proc buildEcdhSharedSecretApdu(
    objectId: uint32,
    peerPublicKey: openArray[uint8]
): SE[seq[uint8]] =
  var payload: seq[uint8] = @[]

  payload.appendTlvU32(Tag1, objectId)
  payload.appendTlvBytes(Tag2, peerPublicKey)

  if payload.len > 255:
    return fail[seq[uint8]](
      seApduTooLarge,
      "ECDHGenerateSharedSecret payload is too large for a short APDU"
    )

  result.value = @[
    EcdhCla,
    EcdhInsCrypto,
    EcdhP1Ec,
    EcdhP2Dh,
    uint8(payload.len)
  ]
  for b in payload:
    result.value.add(b)

  # Le: request the shared secret as TLV[TAG_1] in the response.
  result.value.add(0x00'u8)
  result.ok = true

# =============================================================================
# API
# =============================================================================

proc generateEcKeyPair*(
    se: Se050Transport,
    objectId: uint32,
    curve: EcCurveKind,
    policy: EcKeyPolicy,
    selectFirst: bool = true
): SE[void] =
  ## Generates an EC key pair inside the selected SE050 applet with an explicit
  ## object policy.
  ##
  ## This is the raw low-level primitive. It does not check whether the target
  ## ID is in a safe development range, whether it already exists, or whether it
  ## belongs to a vendor-reserved namespace. CLI/provisioning tools must enforce
  ## those policies before calling this function.
  ##
  ## Use developmentEcKeyPolicy() for disposable development objects. Use
  ## deviceEcKeyPolicy() or oneTimeDeviceKeyPolicy() only after validating the
  ## policy in a disposable range, because restrictive policies may prevent
  ## overwrite/regeneration/deletion.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[void](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildGenerateEcKeyPairApdu(
    objectId = objectId,
    curve = curve,
    policy = policy
  )
  if not apdu.ok:
    return fail[void](apdu.error.kind, apdu.error.message, apdu.error.sw)

  let oldMaxRetries = se.maxRetries
  if se.maxRetries < KeyGenerationMaxReadRetries:
    se.maxRetries = KeyGenerationMaxReadRetries

  let response = se.transceiveApdu(apdu.value)
  se.maxRetries = oldMaxRetries

  if not response.ok:
    return fail[void](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = checkStatus(response.value, "WriteECKey")

proc generateEcKeyPair*(
    se: Se050Transport,
    objectId: uint32,
    curve: EcCurveKind,
    selectFirst: bool = true
): SE[void] =
  ## Generates an EC key pair with the default development policy.
  ##
  ## This wrapper preserves the historical se050_nim behavior for se050ctl,
  ## examples, and existing callers. Higher-level provisioning tools should call
  ## the overload that accepts EcKeyPolicy explicitly.
  result = se.generateEcKeyPair(
    objectId = objectId,
    curve = curve,
    policy = developmentEcKeyPolicy(),
    selectFirst = selectFirst
  )

proc generateX25519KeyPair*(
    se: Se050Transport,
    objectId: uint32,
    policy: EcKeyPolicy,
    selectFirst: bool = true
): SE[void] =
  ## Generates an X25519 key pair inside SE050 with an explicit object policy.
  result = se.generateEcKeyPair(
    objectId = objectId,
    curve = ecCurveX25519,
    policy = policy,
    selectFirst = selectFirst
  )

proc generateX25519KeyPair*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[void] =
  ## Generates an X25519 key pair inside SE050 with the development policy.
  result = se.generateX25519KeyPair(
    objectId = objectId,
    policy = developmentEcKeyPolicy(),
    selectFirst = selectFirst
  )

proc generateP256KeyPair*(
    se: Se050Transport,
    objectId: uint32,
    policy: EcKeyPolicy,
    selectFirst: bool = true
): SE[void] =
  ## Generates a NIST P-256 key pair inside SE050 with an explicit object policy.
  result = se.generateEcKeyPair(
    objectId = objectId,
    curve = ecCurveP256,
    policy = policy,
    selectFirst = selectFirst
  )

proc generateP256KeyPair*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[void] =
  ## Generates a NIST P-256 key pair inside SE050 with the development policy.
  result = se.generateP256KeyPair(
    objectId = objectId,
    policy = developmentEcKeyPolicy(),
    selectFirst = selectFirst
  )


proc importP256KeyPair*(
    se: Se050Transport,
    objectId: uint32,
    privateKey: openArray[uint8],
    publicKey: openArray[uint8],
    policy: EcKeyPolicy,
    selectFirst: bool = true
): SE[void] =
  ## Imports an externally generated NIST P-256 key pair into SE050.
  ##
  ## This is a raw low-level primitive. It deliberately does not check managed
  ## TLS object ranges, existing-object ownership, certificate matching, or
  ## attestation semantics. Higher layers must perform those checks before
  ## calling this function.
  ##
  ## The WriteECKey command contains the private scalar, so the complete
  ## transaction uses the sensitive transport path and the temporary APDU copy
  ## is cleared before returning.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[void](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  var apdu = buildImportP256KeyPairApdu(
    objectId = objectId,
    privateKey = privateKey,
    publicKey = publicKey,
    policy = policy
  )
  if not apdu.ok:
    return fail[void](
      apdu.error.kind,
      apdu.error.message,
      apdu.error.sw
    )

  defer:
    secureZero(apdu.value)

  let oldMaxRetries = se.maxRetries
  if se.maxRetries < KeyImportMaxReadRetries:
    se.maxRetries = KeyImportMaxReadRetries

  let response = se.transceiveSensitiveApdu(apdu.value)
  se.maxRetries = oldMaxRetries

  if not response.ok:
    return fail[void](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = checkStatus(response.value, "WriteECKey")

proc importP256KeyPair*(
    se: Se050Transport,
    objectId: uint32,
    privateKey: openArray[uint8],
    publicKey: openArray[uint8],
    selectFirst: bool = true
): SE[void] =
  ## Imports a P-256 key pair using the historical development EC-key policy.
  ##
  ## Product TLS provisioning should pass the managed TLS profile policy
  ## explicitly rather than using this convenience overload.
  result = se.importP256KeyPair(
    objectId = objectId,
    privateKey = privateKey,
    publicKey = publicKey,
    policy = developmentEcKeyPolicy(),
    selectFirst = selectFirst
  )

proc readPublicKey*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[seq[uint8]] =
  ## Reads the public key material from an SE050 EC key pair or EC public key.
  ##
  ## This compatibility helper delegates to readSecureObject(). The SE050
  ## returns the public key for EC key-pair and EC-public-key objects. The caller
  ## remains responsible for checking the Secure Object type when stricter
  ## semantics are required.
  result = se.readSecureObject(
    objectId = objectId,
    selectFirst = selectFirst
  )

proc signDigest*(
    se: Se050Transport,
    objectId: uint32,
    digest: openArray[uint8],
    selectFirst: bool = true
): SE[seq[uint8]] =
  ## Signs a host-computed SHA-256 digest with an SE050 EC key pair/private key.
  ##
  ## The digest must be exactly 32 bytes. The key object must allow
  ## POLICY_OBJ_ALLOW_SIGN. The returned signature is the ASN.1 DER ECDSA
  ## signature supplied by the SE050 in TLV[TAG_1].
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[seq[uint8]](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildEcdsaSignApdu(objectId, digest)
  if not apdu.ok:
    return fail[seq[uint8]](apdu.error.kind, apdu.error.message, apdu.error.sw)

  let oldMaxRetries = se.maxRetries
  if se.maxRetries < CryptoOperationMaxReadRetries:
    se.maxRetries = CryptoOperationMaxReadRetries

  let response = se.transceiveApdu(apdu.value)
  se.maxRetries = oldMaxRetries

  if not response.ok:
    return fail[seq[uint8]](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseTag1Value(response.value, "ECDSASign")

proc deriveSharedSecret*(
    se: Se050Transport,
    objectId: uint32,
    peerPublicKey: openArray[uint8],
    selectFirst: bool = true
): SE[seq[uint8]] =
  ## Performs ECDH using an SE050 EC key pair/private key and an external public key.
  ##
  ## This is the raw low-level primitive. It returns the shared secret to the CPU
  ## as TLV[TAG_1] response data. Higher layers are responsible for feeding that
  ## value into HKDF or storing the result into another SE050 object when that is
  ## desired.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[seq[uint8]](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildEcdhSharedSecretApdu(objectId, peerPublicKey)
  if not apdu.ok:
    return fail[seq[uint8]](apdu.error.kind, apdu.error.message, apdu.error.sw)

  let oldMaxRetries = se.maxRetries
  if se.maxRetries < CryptoOperationMaxReadRetries:
    se.maxRetries = CryptoOperationMaxReadRetries

  # The response contains the derived shared secret, so suppress raw T=1
  # frame logging and clear temporary transport copies.
  let response = se.transceiveSensitiveApdu(apdu.value)
  se.maxRetries = oldMaxRetries

  if not response.ok:
    return fail[seq[uint8]](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseTag1Value(response.value, "ECDHGenerateSharedSecret")
