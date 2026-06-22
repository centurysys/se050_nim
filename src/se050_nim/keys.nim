# =============================================================================
# SE050 key management helpers
# =============================================================================
#
# Low-level helpers for creating SE050 key objects.
#
# This module intentionally exposes SE050 primitive operations. Product policy,
# factory provisioning records, firmware envelope handling, and CLI safety
# guards belong in higher layers.

import ./errors
import ./transport
import ./apdu
import ./tlv

# =============================================================================
# Constants
# =============================================================================

const
  Tag1 = 0x41'u8
  Tag2 = 0x42'u8

  # SE05x WriteECKey APDU for generating an EC key pair inside SE050.
  #
  # NXP Plug & Trust names this command:
  #   CLA = 0x80
  #   INS = INS_WRITE = 0x01
  #   P1  = P1_KEY_PAIR | P1_EC = 0x60 | 0x01 = 0x61
  #   P2  = P2_DEFAULT = 0x00
  #
  # Command data for internal key generation:
  #   TAG_1: 4-byte Secure Object identifier
  #   TAG_2: 1-byte ECCurve identifier
  #
  # TAG_3 private key and TAG_4 public key are deliberately omitted. For
  # P1_KEY_PAIR, omitting both TAG_3 and TAG_4 requests key generation inside
  # the SE050.
  WriteEcKeyCla = 0x80'u8
  WriteEcKeyIns = 0x01'u8
  WriteEcKeyP1KeyPairEc = 0x61'u8
  WriteEcKeyP2Default = 0x00'u8

  # ECCurve constants.
  Se050CurveX25519* = 0x41'u8

  # SecureObjectType constants used by ReadType after key generation.
  Se050TypeEcKeyPairMontDh25519* = 0x69'u8

  # SE05x ReadObject APDU.
  #
  # NXP AN12413 describes ReadObject as:
  #   CLA = 0x80
  #   INS = INS_READ   = 0x02
  #   P1  = P1_DEFAULT = 0x00
  #   P2  = P2_DEFAULT = 0x00
  #
  # Command data:
  #   TAG_1: 4-byte Secure Object identifier
  #
  # Response data:
  #   TAG_1: Data read from the Secure Object
  #
  # For an EC key pair or EC public key, ReadObject returns the public key.
  ReadObjectCla = 0x80'u8
  ReadObjectIns = 0x02'u8
  ReadObjectP1 = 0x00'u8
  ReadObjectP2 = 0x00'u8

  # On-chip asymmetric key generation can take longer than normal object
  # inspection/random commands. During that time the T=1 over I2C layer may see
  # empty reads before the SE050 emits WTX or the final response. Keep the
  # extended wait local to key generation so quick commands keep failing fast.
  KeyGenerationMaxReadRetries = 200

# =============================================================================
# Types
# =============================================================================

type
  EcCurveKind* = enum
    ecCurveX25519

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

proc curveId*(curve: EcCurveKind): uint8 =
  result = case curve
  of ecCurveX25519: Se050CurveX25519

proc curveName*(curve: EcCurveKind): string =
  result = case curve
  of ecCurveX25519: "x25519"

proc expectedKeyPairType*(curve: EcCurveKind): uint8 =
  result = case curve
  of ecCurveX25519: Se050TypeEcKeyPairMontDh25519

proc buildReadObjectApdu(objectId: uint32): seq[uint8] =
  result = @[
    ReadObjectCla,
    ReadObjectIns,
    ReadObjectP1,
    ReadObjectP2,
    0x06'u8,

    # TAG_1: 4-byte Secure Object identifier
    Tag1,
    0x04'u8
  ]
  result.appendU32Be(objectId)

  # Le
  result.add(0x00'u8)

proc parseReadObjectValue(response: openArray[uint8]): SE[seq[uint8]] =
  let st = checkStatus(response, "ReadObject")
  if not st.ok:
    return fail[seq[uint8]](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[seq[uint8]](data.error.kind, data.error.message, data.error.sw)

  if data.value.len < 3:
    return fail[seq[uint8]](
      seInvalidResponse,
      "ReadObject response does not contain TAG/LEN/VALUE"
    )

  if data.value[0] != Tag1:
    return fail[seq[uint8]](
      seInvalidResponse,
      "ReadObject response does not start with TAG_1"
    )

  let tlvLen = readTlvLength(data.value, 1)
  if not tlvLen.ok:
    return fail[seq[uint8]](tlvLen.error.kind, tlvLen.error.message, tlvLen.error.sw)

  let valueStart = tlvLen.value.nextIndex
  let valueEnd = valueStart + tlvLen.value.length
  if valueEnd > data.value.len:
    return fail[seq[uint8]](
      seInvalidResponse,
      "ReadObject response value is shorter than expected"
    )

  let value = data.value[valueStart ..< valueEnd]
  result = ok(value)

proc buildGenerateEcKeyPairApdu(objectId: uint32, curve: EcCurveKind): SE[seq[uint8]] =
  var payload: seq[uint8] = @[]
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

# =============================================================================
# API
# =============================================================================

proc generateEcKeyPair*(
    se: Se050Transport,
    objectId: uint32,
    curve: EcCurveKind,
    selectFirst: bool = true
): SE[void] =
  ## Generates an EC key pair inside the selected SE050 applet.
  ##
  ## This is the raw low-level primitive. It does not check whether the target
  ## ID is in a safe development range, whether it already exists, or whether it
  ## belongs to a vendor-reserved namespace. CLI/provisioning tools must enforce
  ## those policies before calling this function.
  ##
  ## No explicit object policy is attached here. The SE050 default object policy
  ## therefore applies.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[void](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildGenerateEcKeyPairApdu(objectId = objectId, curve = curve)
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

proc generateX25519KeyPair*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[void] =
  ## Generates an X25519 key pair inside SE050.
  result = se.generateEcKeyPair(
    objectId = objectId,
    curve = ecCurveX25519,
    selectFirst = selectFirst
  )


proc readPublicKey*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[seq[uint8]] =
  ## Reads the public key material from an SE050 EC key pair or EC public key.
  ##
  ## This is a raw ReadObject helper. The SE050 returns the public key for EC
  ## key-pair and EC-public-key objects. The caller is responsible for checking
  ## the Secure Object type before calling this helper if it needs stricter
  ## semantics.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[seq[uint8]](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let response = se.transceiveApdu(buildReadObjectApdu(objectId))
  if not response.ok:
    return fail[seq[uint8]](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseReadObjectValue(response.value)
