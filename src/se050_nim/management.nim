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
