# =============================================================================
# SE050 management helpers
# =============================================================================
#
# Low-level helpers for generic SE050 applet management/status commands.

import std/strformat
import std/strutils

import ./errors
import ./transport
import ./apdu
import ./tlv
from ./keys import Se050CurveNistP384

# =============================================================================
# Constants
# =============================================================================

const
  Tag1 = 0x41'u8

  MgmtCla = 0x80'u8
  MgmtIns = 0x04'u8
  P1Default = 0x00'u8
  P2Version = 0x20'u8

  # SE05x ReadECCurveList:
  #   CLA = 0x80
  #   INS = INS_READ = 0x02
  #   P1  = P1_CURVE = 0x0B
  #   P2  = P2_LIST  = 0x25
  #   Le  = 0x00
  CurveListCla = 0x80'u8
  CurveListInsRead = 0x02'u8
  CurveListP1Curve = 0x0B'u8
  CurveListP2List = 0x25'u8

  # SE05x EC curve management APDUs:
  #
  #   CreateECCurve     80 01 0B 04
  #   SetECCurveParam   80 01 0B 40
  #   DeleteECCurve     80 04 0B 28
  #
  # DeleteECCurve deliberately uses the documented P2_DELETE_OBJECT value
  # 0x28. Some newer header files also define P2_DELETE_CURVE, but AN12543
  # continues to specify 0x28 for the command itself.
  CurveMgmtCla = 0x80'u8
  CurveMgmtInsWrite = 0x01'u8
  CurveMgmtInsMgmt = 0x04'u8
  CurveMgmtP1Curve = 0x0B'u8
  CurveMgmtP2Create = 0x04'u8
  CurveMgmtP2Param = 0x40'u8
  CurveMgmtP2Delete = 0x28'u8

  Tag2 = 0x42'u8
  Tag3 = 0x43'u8

  SetIndicatorNotSet = 0x01'u8
  SetIndicatorSet = 0x02'u8

  ConfigEcdaa* = 0x0001'u16
  ConfigEcdsaEcdhEcdhe* = 0x0002'u16
  ConfigEddsa* = 0x0004'u16
  ConfigDhMont* = 0x0008'u16
  ConfigHmac* = 0x0010'u16
  ConfigRsaPlain* = 0x0020'u16
  ConfigRsaCrt* = 0x0040'u16
  ConfigAes* = 0x0080'u16
  ConfigDes* = 0x0100'u16
  ConfigPbkdf* = 0x0200'u16
  ConfigTls* = 0x0400'u16
  ConfigMifare* = 0x0800'u16
  ConfigFipsModeDisabled* = 0x1000'u16
  ConfigI2cm* = 0x2000'u16

  # NIST P-384 / secp384r1 domain parameters, encoded exactly as SE05x
  # SetECCurveParam expects them:
  #
  #   A/B/N/PRIME: unsigned big-endian 48-byte integers
  #   G:           uncompressed point 0x04 || X || Y (97 bytes)
  #
  # No leading ASN.1 sign-padding byte is included.
  NistP384A: array[48, uint8] = [
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFE'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFC'u8
  ]

  NistP384B: array[48, uint8] = [
    0xB3'u8, 0x31'u8, 0x2F'u8, 0xA7'u8, 0xE2'u8, 0x3E'u8, 0xE7'u8, 0xE4'u8,
    0x98'u8, 0x8E'u8, 0x05'u8, 0x6B'u8, 0xE3'u8, 0xF8'u8, 0x2D'u8, 0x19'u8,
    0x18'u8, 0x1D'u8, 0x9C'u8, 0x6E'u8, 0xFE'u8, 0x81'u8, 0x41'u8, 0x12'u8,
    0x03'u8, 0x14'u8, 0x08'u8, 0x8F'u8, 0x50'u8, 0x13'u8, 0x87'u8, 0x5A'u8,
    0xC6'u8, 0x56'u8, 0x39'u8, 0x8D'u8, 0x8A'u8, 0x2E'u8, 0xD1'u8, 0x9D'u8,
    0x2A'u8, 0x85'u8, 0xC8'u8, 0xED'u8, 0xD3'u8, 0xEC'u8, 0x2A'u8, 0xEF'u8
  ]

  NistP384G: array[97, uint8] = [
    0x04'u8,
    0xAA'u8, 0x87'u8, 0xCA'u8, 0x22'u8, 0xBE'u8, 0x8B'u8, 0x05'u8, 0x37'u8,
    0x8E'u8, 0xB1'u8, 0xC7'u8, 0x1E'u8, 0xF3'u8, 0x20'u8, 0xAD'u8, 0x74'u8,
    0x6E'u8, 0x1D'u8, 0x3B'u8, 0x62'u8, 0x8B'u8, 0xA7'u8, 0x9B'u8, 0x98'u8,
    0x59'u8, 0xF7'u8, 0x41'u8, 0xE0'u8, 0x82'u8, 0x54'u8, 0x2A'u8, 0x38'u8,
    0x55'u8, 0x02'u8, 0xF2'u8, 0x5D'u8, 0xBF'u8, 0x55'u8, 0x29'u8, 0x6C'u8,
    0x3A'u8, 0x54'u8, 0x5E'u8, 0x38'u8, 0x72'u8, 0x76'u8, 0x0A'u8, 0xB7'u8,
    0x36'u8, 0x17'u8, 0xDE'u8, 0x4A'u8, 0x96'u8, 0x26'u8, 0x2C'u8, 0x6F'u8,
    0x5D'u8, 0x9E'u8, 0x98'u8, 0xBF'u8, 0x92'u8, 0x92'u8, 0xDC'u8, 0x29'u8,
    0xF8'u8, 0xF4'u8, 0x1D'u8, 0xBD'u8, 0x28'u8, 0x9A'u8, 0x14'u8, 0x7C'u8,
    0xE9'u8, 0xDA'u8, 0x31'u8, 0x13'u8, 0xB5'u8, 0xF0'u8, 0xB8'u8, 0xC0'u8,
    0x0A'u8, 0x60'u8, 0xB1'u8, 0xCE'u8, 0x1D'u8, 0x7E'u8, 0x81'u8, 0x9D'u8,
    0x7A'u8, 0x43'u8, 0x1D'u8, 0x7C'u8, 0x90'u8, 0xEA'u8, 0x0E'u8, 0x5F'u8
  ]

  NistP384N: array[48, uint8] = [
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8,
    0xC7'u8, 0x63'u8, 0x4D'u8, 0x81'u8, 0xF4'u8, 0x37'u8, 0x2D'u8, 0xDF'u8,
    0x58'u8, 0x1A'u8, 0x0D'u8, 0xB2'u8, 0x48'u8, 0xB0'u8, 0xA7'u8, 0x7A'u8,
    0xEC'u8, 0xEC'u8, 0x19'u8, 0x6A'u8, 0xCC'u8, 0xC5'u8, 0x29'u8, 0x73'u8
  ]

  NistP384Prime: array[48, uint8] = [
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFE'u8,
    0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8
  ]

# =============================================================================
# Types
# =============================================================================

type
  Se050VersionInfo* = object
    major*: uint8
    minor*: uint8
    patch*: uint8
    appletConfig*: uint16
    secureBoxMajor*: uint8
    secureBoxMinor*: uint8

  EcCurveSetState* = enum
    ## ReadECCurveList state for one Weierstrass curve identifier.
    ##
    ## "Set" means the curve parameters are instantiated in the SE05x and the
    ## curve is available to EC key commands. It is deliberately not named
    ## "supported": ReadECCurveList reports current instantiation state, not the
    ## complete silicon capability matrix.
    ecCurveNotSet,
    ecCurveSet

  EcCurveListInfo* = object
    ## SetIndicator values returned by ReadECCurveList.
    ##
    ## Index 0 corresponds to curve ID 0x01, index 1 to 0x02, and so on.
    ## Keeping this as a sequence lets newer applets append future Weierstrass
    ## identifiers without making the parser reject an otherwise valid response.
    indicators*: seq[uint8]

  EcCurveParam* = enum
    ## One of the five Weierstrass parameters required by SetECCurveParam.
    ##
    ## The enum intentionally uses ordinary Nim ordinals. ecCurveParamWireValue()
    ## maps these names to the non-contiguous SE05x wire identifiers.
    ecCurveParamA,
    ecCurveParamB,
    ecCurveParamG,
    ecCurveParamN,
    ecCurveParamPrime

  EcCurveProvisionResult* = enum
    ## Idempotent result from a standard-curve provisioning operation.
    ecCurveAlreadyInstantiated,
    ecCurveProvisioned

# =============================================================================
# Internal helpers
# =============================================================================

proc hasFeature*(info: Se050VersionInfo, bit: uint16): bool =
  result = (info.appletConfig and bit) != 0

proc featureName*(bit: uint16): string =
  case bit
  of ConfigEcdaa: "ECDAA"
  of ConfigEcdsaEcdhEcdhe: "ECDSA_ECDH_ECDHE"
  of ConfigEddsa: "EDDSA"
  of ConfigDhMont: "DH_MONT"
  of ConfigHmac: "HMAC"
  of ConfigRsaPlain: "RSA_PLAIN"
  of ConfigRsaCrt: "RSA_CRT"
  of ConfigAes: "AES"
  of ConfigDes: "DES"
  of ConfigPbkdf: "PBKDF"
  of ConfigTls: "TLS"
  of ConfigMifare: "MIFARE"
  of ConfigFipsModeDisabled: "FIPS_MODE_DISABLED"
  of ConfigI2cm: "I2CM"
  else: &"UNKNOWN_0x{bit.toHex(4)}"

proc knownFeatureBits*(): seq[uint16] =
  result = @[
    ConfigEcdaa,
    ConfigEcdsaEcdhEcdhe,
    ConfigEddsa,
    ConfigDhMont,
    ConfigHmac,
    ConfigRsaPlain,
    ConfigRsaCrt,
    ConfigAes,
    ConfigDes,
    ConfigPbkdf,
    ConfigTls,
    ConfigMifare,
    ConfigFipsModeDisabled,
    ConfigI2cm,
  ]

proc ecCurveParamWireValue*(param: EcCurveParam): uint8 =
  ## Returns the SE05x_ECCurveParam_t value used in TAG_2.
  result = case param
  of ecCurveParamA: 0x01'u8
  of ecCurveParamB: 0x02'u8
  of ecCurveParamG: 0x04'u8
  of ecCurveParamN: 0x08'u8
  of ecCurveParamPrime: 0x10'u8

proc ecCurveParamName*(param: EcCurveParam): string =
  result = case param
  of ecCurveParamA: "A"
  of ecCurveParamB: "B"
  of ecCurveParamG: "G"
  of ecCurveParamN: "N"
  of ecCurveParamPrime: "PRIME"

proc isKnownWeierstrassCurveId(curveId: uint8): bool =
  ## The current SE05x enum defines consecutive Weierstrass identifiers
  ## 0x01..0x11. Reserved Ed/Montgomery identifiers start at 0x40.
  result = curveId >= 0x01'u8 and curveId <= 0x11'u8

proc appendCurveTlvLength(buf: var seq[uint8], length: int) =
  ## BER-TLV length encoding used by SetECCurveParam.
  ##
  ## P-521 G is 133 bytes, so the 0x81 form is required even though the whole
  ## command still fits in a short APDU.
  doAssert length >= 0

  if length < 0x80:
    buf.add(uint8(length))
  elif length <= 0xFF:
    buf.add(0x81'u8)
    buf.add(uint8(length))
  elif length <= 0xFFFF:
    buf.add(0x82'u8)
    buf.add(uint8((length shr 8) and 0xFF))
    buf.add(uint8(length and 0xFF))
  else:
    # The caller rejects the resulting payload as too large for this short-APDU
    # helper. Keeping the encoder total makes that failure deterministic.
    buf.add(0x83'u8)
    buf.add(uint8((length shr 16) and 0xFF))
    buf.add(uint8((length shr 8) and 0xFF))
    buf.add(uint8(length and 0xFF))

proc appendCurveTlvU8(buf: var seq[uint8], tag: uint8, value: uint8) =
  buf.add(tag)
  buf.add(0x01'u8)
  buf.add(value)

proc appendCurveTlvBytes(
    buf: var seq[uint8],
    tag: uint8,
    value: openArray[uint8]
) =
  buf.add(tag)
  buf.appendCurveTlvLength(value.len)
  for b in value:
    buf.add(b)

proc buildCurveManagementApdu(
    ins: uint8,
    p2: uint8,
    payload: openArray[uint8],
    commandName: string
): SE[seq[uint8]] =
  if payload.len > 255:
    return fail[seq[uint8]](
      seApduTooLarge,
      commandName & " payload is too large for a short APDU"
    )

  result.value = @[
    CurveMgmtCla,
    ins,
    CurveMgmtP1Curve,
    p2,
    uint8(payload.len)
  ]
  for b in payload:
    result.value.add(b)
  result.ok = true

proc buildCreateEcCurveApdu*(curveId: uint8): SE[seq[uint8]] =
  ## Builds CreateECCurve.
  ##
  ## This only encodes the APDU. It does not alter the SE05x until a caller
  ## explicitly transmits the returned bytes.
  if not isKnownWeierstrassCurveId(curveId):
    return fail[seq[uint8]](
      seInvalidArgument,
      &"curve ID 0x{curveId.toHex(2)} is not a known Weierstrass curve identifier"
    )

  var payload: seq[uint8] = @[]
  payload.appendCurveTlvU8(Tag1, curveId)

  result = buildCurveManagementApdu(
    CurveMgmtInsWrite,
    CurveMgmtP2Create,
    payload,
    "CreateECCurve"
  )

proc buildSetEcCurveParamApdu*(
    curveId: uint8,
    param: EcCurveParam,
    value: openArray[uint8]
): SE[seq[uint8]] =
  ## Builds SetECCurveParam for one standard Weierstrass parameter.
  ##
  ## NXP requires all five A/B/G/N/PRIME parameters to be configured before a
  ## newly created Weierstrass curve becomes usable. The secure element checks
  ## that the supplied values match the selected standard curve.
  if not isKnownWeierstrassCurveId(curveId):
    return fail[seq[uint8]](
      seInvalidArgument,
      &"curve ID 0x{curveId.toHex(2)} is not a known Weierstrass curve identifier"
    )

  if value.len == 0:
    return fail[seq[uint8]](
      seInvalidArgument,
      &"EC curve parameter {param.ecCurveParamName()} must not be empty"
    )

  var payload: seq[uint8] = @[]
  payload.appendCurveTlvU8(Tag1, curveId)
  payload.appendCurveTlvU8(Tag2, param.ecCurveParamWireValue())
  payload.appendCurveTlvBytes(Tag3, value)

  result = buildCurveManagementApdu(
    CurveMgmtInsWrite,
    CurveMgmtP2Param,
    payload,
    "SetECCurveParam"
  )

proc buildDeleteEcCurveApdu*(curveId: uint8): SE[seq[uint8]] =
  ## Builds DeleteECCurve for rollback/recovery of a non-default curve.
  ##
  ## This helper is added before any live provisioning API so a future
  ## transaction can always construct its documented rollback command first.
  if not isKnownWeierstrassCurveId(curveId):
    return fail[seq[uint8]](
      seInvalidArgument,
      &"curve ID 0x{curveId.toHex(2)} is not a known Weierstrass curve identifier"
    )

  var payload: seq[uint8] = @[]
  payload.appendCurveTlvU8(Tag1, curveId)

  result = buildCurveManagementApdu(
    CurveMgmtInsMgmt,
    CurveMgmtP2Delete,
    payload,
    "DeleteECCurve"
  )

proc nistP384CurveParamValue(param: EcCurveParam): seq[uint8] =
  result = case param
  of ecCurveParamA: @NistP384A
  of ecCurveParamB: @NistP384B
  of ecCurveParamG: @NistP384G
  of ecCurveParamN: @NistP384N
  of ecCurveParamPrime: @NistP384Prime

proc buildNistP384ProvisioningApdus*(): SE[seq[seq[uint8]]] =
  ## Builds the complete standard P-384 provisioning sequence without touching
  ## the secure element.
  ##
  ## Command order is fixed so callers cannot accidentally omit or substitute
  ## one of the five standard domain parameters:
  ##
  ##   Create -> A -> B -> G -> N -> PRIME
  let create = buildCreateEcCurveApdu(Se050CurveNistP384)
  if not create.ok:
    return fail[seq[seq[uint8]]](
      create.error.kind,
      create.error.message,
      create.error.sw
    )

  var commands = @[create.value]
  for param in [
      ecCurveParamA,
      ecCurveParamB,
      ecCurveParamG,
      ecCurveParamN,
      ecCurveParamPrime
  ]:
    let built = buildSetEcCurveParamApdu(
      Se050CurveNistP384,
      param,
      nistP384CurveParamValue(param)
    )
    if not built.ok:
      return fail[seq[seq[uint8]]](
        built.error.kind,
        built.error.message,
        built.error.sw
      )
    commands.add(built.value)

  result = ok(commands)

proc sendCurveManagementCommand(
    se: Se050Transport,
    apdu: openArray[uint8],
    context: string
): SE[void] =
  let response = se.transceiveApdu(apdu)
  if not response.ok:
    return fail[void](
      response.error.kind,
      context & ": " & response.error.message,
      response.error.sw
    )

  let status = checkStatus(response.value, context)
  if not status.ok:
    return fail[void](
      status.error.kind,
      status.error.message,
      status.error.sw
    )

  result = ok()

proc rollbackCurveAfterProvisionFailure[T](
    se: Se050Transport,
    deleteApdu: openArray[uint8],
    cause: Se050Error
): SE[T] =
  ## Best-effort rollback after this call has received a successful
  ## CreateECCurve response and therefore owns the partial curve state.
  let rolledBack = sendCurveManagementCommand(
    se,
    deleteApdu,
    "DeleteECCurve rollback"
  )

  if rolledBack.ok:
    return fail[T](cause.kind, cause.message, cause.sw)

  result = fail[T](
    cause.kind,
    cause.message & "; rollback failed: " & rolledBack.error.errorMessage(),
    cause.sw
  )

proc ecCurveName*(curveId: uint8): string =
  ## Human-readable names for the consecutive SE05x Weierstrass curve IDs.
  result = case curveId
  of 0x01'u8: "NIST P-192"
  of 0x02'u8: "NIST P-224"
  of 0x03'u8: "NIST P-256"
  of 0x04'u8: "NIST P-384"
  of 0x05'u8: "NIST P-521"
  of 0x06'u8: "Brainpool P-160"
  of 0x07'u8: "Brainpool P-192"
  of 0x08'u8: "Brainpool P-224"
  of 0x09'u8: "Brainpool P-256"
  of 0x0A'u8: "Brainpool P-320"
  of 0x0B'u8: "Brainpool P-384"
  of 0x0C'u8: "Brainpool P-512"
  of 0x0D'u8: "secp160k1"
  of 0x0E'u8: "secp192k1"
  of 0x0F'u8: "secp224k1"
  of 0x10'u8: "secp256k1"
  of 0x11'u8: "TPM ECC BN P-256"
  else: &"curve 0x{curveId.toHex(2)}"

proc buildReadEcCurveListApdu*(): seq[uint8] =
  ## Builds the no-payload ReadECCurveList Case-2 short APDU.
  result = @[
    CurveListCla,
    CurveListInsRead,
    CurveListP1Curve,
    CurveListP2List,
    0x00'u8 # Le
  ]

proc parseReadEcCurveListResponse*(
    response: openArray[uint8]
): SE[EcCurveListInfo] =
  ## Parses ReadECCurveList TAG_1 SetIndicator bytes.
  ##
  ## SE05x_ECCurve_t assigns the Weierstrass identifiers consecutively from
  ## 0x01. Therefore TAG_1 byte zero describes curve 0x01, byte one describes
  ## curve 0x02, etc.
  let st = checkStatus(response, "ReadECCurveList")
  if not st.ok:
    return fail[EcCurveListInfo](
      st.error.kind,
      st.error.message,
      st.error.sw
    )

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[EcCurveListInfo](
      data.error.kind,
      data.error.message,
      data.error.sw
    )

  if data.value.len < 2:
    return fail[EcCurveListInfo](
      seInvalidResponse,
      "ReadECCurveList response does not contain TAG_1"
    )

  if data.value[0] != Tag1:
    return fail[EcCurveListInfo](
      seInvalidResponse,
      "ReadECCurveList response does not start with TAG_1"
    )

  let tlvLen = readTlvLength(data.value, 1)
  if not tlvLen.ok:
    return fail[EcCurveListInfo](
      tlvLen.error.kind,
      tlvLen.error.message,
      tlvLen.error.sw
    )

  let valueStart = tlvLen.value.nextIndex
  let valueEnd = valueStart + tlvLen.value.length
  if valueEnd > data.value.len:
    return fail[EcCurveListInfo](
      seInvalidResponse,
      "ReadECCurveList TAG_1 value is truncated"
    )

  if valueEnd != data.value.len:
    return fail[EcCurveListInfo](
      seInvalidResponse,
      "ReadECCurveList response contains trailing data"
    )

  if tlvLen.value.length == 0:
    return fail[EcCurveListInfo](
      seInvalidResponse,
      "ReadECCurveList returned an empty curve list"
    )

  var indicators = newSeq[uint8](tlvLen.value.length)
  for i in 0 ..< tlvLen.value.length:
    let indicator = data.value[valueStart + i]
    if indicator != SetIndicatorNotSet and indicator != SetIndicatorSet:
      return fail[EcCurveListInfo](
        seInvalidResponse,
        &"ReadECCurveList contains invalid SetIndicator 0x{indicator.toHex(2)} at curve ID 0x{(i + 1).toHex(2)}"
      )
    indicators[i] = indicator

  result = ok(EcCurveListInfo(indicators: indicators))

proc ecCurveSetState*(
    info: EcCurveListInfo,
    curveId: uint8
): SE[EcCurveSetState] =
  ## Returns the current instantiation state for one Weierstrass curve ID.
  if curveId == 0'u8 or curveId >= 0x40'u8:
    return fail[EcCurveSetState](
      seInvalidArgument,
      &"curve ID 0x{curveId.toHex(2)} is not a Weierstrass curve identifier"
    )

  let index = int(curveId) - 1
  if index >= info.indicators.len:
    return fail[EcCurveSetState](
      seInvalidArgument,
      &"curve ID 0x{curveId.toHex(2)} is not present in this ReadECCurveList response"
    )

  case info.indicators[index]
  of SetIndicatorNotSet:
    result = ok(ecCurveNotSet)
  of SetIndicatorSet:
    result = ok(ecCurveSet)
  else:
    result = fail[EcCurveSetState](
      seInvalidResponse,
      &"invalid SetIndicator for curve ID 0x{curveId.toHex(2)}"
    )

proc isEcCurveInstantiated*(
    info: EcCurveListInfo,
    curveId: uint8
): SE[bool] =
  let state = info.ecCurveSetState(curveId)
  if not state.ok:
    return fail[bool](
      state.error.kind,
      state.error.message,
      state.error.sw
    )

  result = ok(state.value == ecCurveSet)

proc buildGetVersionApduWithEmptyLc(): seq[uint8] =
  ## GetVersion has no payload. AN12413 lists an Lc field and Le=0x00.
  ## For this APDU, use an explicit empty Lc followed by Le=0x00.
  ##
  ## The previous implementation used Le=0x0B, which the applet rejected with
  ## SW=0x6700 (wrong length). SE05x documents this as Le=0x00 even though the
  ## returned TLV normally contains 7 bytes of VersionInfo.
  result = @[
    MgmtCla,
    MgmtIns,
    P1Default,
    P2Version,
    0x00'u8, # Lc: no payload
    0x00'u8  # Le: applet-chosen TLV response length
  ]

proc buildGetVersionApduCase2(): seq[uint8] =
  ## Fallback Case-2 short APDU form: CLA INS P1 P2 Le.
  ## Some APDU stacks represent no-payload commands this way. Keep it as a
  ## fallback so version probing remains diagnostic rather than brittle.
  result = @[
    MgmtCla,
    MgmtIns,
    P1Default,
    P2Version,
    0x00'u8  # Le
  ]

proc parseGetVersionResponse(response: openArray[uint8]): SE[Se050VersionInfo] =
  let st = checkStatus(response, "GetVersion")
  if not st.ok:
    return fail[Se050VersionInfo](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[Se050VersionInfo](data.error.kind, data.error.message, data.error.sw)

  if data.value.len < 3:
    return fail[Se050VersionInfo](
      seInvalidResponse,
      "GetVersion response does not contain TAG/LEN/VALUE"
    )

  if data.value[0] != Tag1:
    return fail[Se050VersionInfo](
      seInvalidResponse,
      "GetVersion response does not start with TAG_1"
    )

  let tlvLen = readTlvLength(data.value, 1)
  if not tlvLen.ok:
    return fail[Se050VersionInfo](tlvLen.error.kind, tlvLen.error.message, tlvLen.error.sw)

  let valueStart = tlvLen.value.nextIndex
  let valueEnd = valueStart + tlvLen.value.length
  if valueEnd > data.value.len:
    return fail[Se050VersionInfo](
      seInvalidResponse,
      "GetVersion response value is shorter than expected"
    )

  if tlvLen.value.length != 7:
    return fail[Se050VersionInfo](
      seInvalidResponse,
      &"GetVersion VersionInfo length must be 7 bytes, got {tlvLen.value.length}"
    )

  let v = data.value[valueStart ..< valueEnd]
  result = ok(Se050VersionInfo(
    major: v[0],
    minor: v[1],
    patch: v[2],
    appletConfig: (uint16(v[3]) shl 8) or uint16(v[4]),
    secureBoxMajor: v[5],
    secureBoxMinor: v[6]
  ))

# =============================================================================
# API
# =============================================================================

proc readEcCurveList*(
    se: Se050Transport,
    selectFirst: bool = true
): SE[EcCurveListInfo] =
  ## Reads the current Weierstrass-curve instantiation state from the SE05x.
  ##
  ## This is a read-only diagnostic operation. It does not create, modify, or
  ## delete any curve parameters.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[EcCurveListInfo](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let response = se.transceiveApdu(buildReadEcCurveListApdu())
  if not response.ok:
    return fail[EcCurveListInfo](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseReadEcCurveListResponse(response.value)

proc provisionNistP384Curve*(
    se: Se050Transport,
    selectFirst: bool = true
): SE[EcCurveProvisionResult] =
  ## Idempotently provisions the standard NIST P-384 curve parameters.
  ##
  ## Safety properties:
  ## - If ReadECCurveList already reports P-384 as set, no write command is sent.
  ## - All provisioning/delete APDUs are built before the first mutation.
  ## - Once CreateECCurve has returned success, any later failure triggers a
  ##   best-effort DeleteECCurve rollback.
  ## - A transport failure while sending CreateECCurve itself is NOT followed by
  ##   DeleteECCurve because ownership is ambiguous without a successful create
  ##   response.
  ## - Success is returned only after ReadECCurveList reports P-384 as set.
  let commands = buildNistP384ProvisioningApdus()
  if not commands.ok:
    return fail[EcCurveProvisionResult](
      commands.error.kind,
      commands.error.message,
      commands.error.sw
    )

  let deleteApdu = buildDeleteEcCurveApdu(Se050CurveNistP384)
  if not deleteApdu.ok:
    return fail[EcCurveProvisionResult](
      deleteApdu.error.kind,
      deleteApdu.error.message,
      deleteApdu.error.sw
    )

  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[EcCurveProvisionResult](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let before = se.readEcCurveList(selectFirst = false)
  if not before.ok:
    return fail[EcCurveProvisionResult](
      before.error.kind,
      before.error.message,
      before.error.sw
    )

  let beforeState = before.value.ecCurveSetState(Se050CurveNistP384)
  if not beforeState.ok:
    return fail[EcCurveProvisionResult](
      beforeState.error.kind,
      beforeState.error.message,
      beforeState.error.sw
    )

  if beforeState.value == ecCurveSet:
    return ok(ecCurveAlreadyInstantiated)

  # Create is handled separately. Until this command returns success, this
  # process cannot safely claim ownership of any partial curve state.
  let created = sendCurveManagementCommand(
    se,
    commands.value[0],
    "CreateECCurve NIST P-384"
  )
  if not created.ok:
    return fail[EcCurveProvisionResult](
      created.error.kind,
      created.error.message,
      created.error.sw
    )

  let params = [
    ecCurveParamA,
    ecCurveParamB,
    ecCurveParamG,
    ecCurveParamN,
    ecCurveParamPrime
  ]

  for i, param in params:
    let configured = sendCurveManagementCommand(
      se,
      commands.value[i + 1],
      "SetECCurveParam NIST P-384 " & param.ecCurveParamName()
    )
    if not configured.ok:
      return rollbackCurveAfterProvisionFailure[EcCurveProvisionResult](
        se,
        deleteApdu.value,
        configured.error
      )

  let after = se.readEcCurveList(selectFirst = false)
  if not after.ok:
    return rollbackCurveAfterProvisionFailure[EcCurveProvisionResult](
      se,
      deleteApdu.value,
      after.error
    )

  let afterState = after.value.ecCurveSetState(Se050CurveNistP384)
  if not afterState.ok:
    return rollbackCurveAfterProvisionFailure[EcCurveProvisionResult](
      se,
      deleteApdu.value,
      afterState.error
    )

  if afterState.value != ecCurveSet:
    return rollbackCurveAfterProvisionFailure[EcCurveProvisionResult](
      se,
      deleteApdu.value,
      Se050Error(
        kind: seInvalidResponse,
        message: "NIST P-384 provisioning completed but ReadECCurveList still reports not-set",
        sw: 0
      )
    )

  result = ok(ecCurveProvisioned)

proc getVersionInfo*(
    se: Se050Transport,
    selectFirst: bool = true
): SE[Se050VersionInfo] =
  ## Reads the SE050 applet version and feature bitmap.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[Se050VersionInfo](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let response = se.transceiveApdu(buildGetVersionApduWithEmptyLc())
  if not response.ok:
    return fail[Se050VersionInfo](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  let parsed = parseGetVersionResponse(response.value)
  if parsed.ok:
    return parsed

  # If the applet rejects the explicit-empty-Lc APDU as a length error, try the
  # Case-2 short APDU representation. This keeps the helper tolerant across
  # small APDU encoding differences while still surfacing non-length failures.
  if parsed.error.kind == seApduStatusError and parsed.error.sw == 0x6700'u16:
    let fallbackResponse = se.transceiveApdu(buildGetVersionApduCase2())
    if not fallbackResponse.ok:
      return fail[Se050VersionInfo](
        fallbackResponse.error.kind,
        fallbackResponse.error.message,
        fallbackResponse.error.sw
      )
    return parseGetVersionResponse(fallbackResponse.value)

  result = parsed
