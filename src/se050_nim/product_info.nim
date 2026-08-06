# =============================================================================
# SE05x product identification helpers
# =============================================================================
#
# Reads the GlobalPlatform IDENTIFY data used by NXP's "Get Info" example.
# This is Card Manager data, not an SE05x IoT Applet command.

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
  IdentifyCla = 0x80'u8
  IdentifyInsGetData = 0xCA'u8
  IdentifyP1 = 0x00'u8
  IdentifyP2Proprietary = 0xFE'u8
  IdentifyTagHigh = 0xDF'u8
  IdentifyTagLow = 0x28'u8

  ProprietaryDataTag = 0xFE'u8
  ConfigurationIdTag = 0x01'u8
  PatchIdTag = 0x02'u8
  PlatformBuildIdTag = 0x03'u8
  FipsModeTag = 0x05'u8
  PrePersoStateTag = 0x07'u8
  RomIdTag = 0x08'u8

  ConfigurationIdLength = 12
  PatchIdLength = 8
  PlatformBuildIdLength = 24
  RomIdLength = 8
  JcopPlatformIdLength = 16

  Se050OefSe050C1* = 0xA200'u16
  Se050OefSe050C2* = 0xA201'u16
  Se050OefSe050B1* = 0xA202'u16
  Se050OefSe050B2* = 0xA203'u16
  Se050OefSe050A1* = 0xA204'u16
  Se050OefSe050A2* = 0xA205'u16
  Se050OefSe050D2* = 0xA43B'u16
  Se050OefSe050F2Legacy* = 0xA77E'u16
  Se050OefSe050E2* = 0xA921'u16
  Se050OefSe050F2* = 0xA92A'u16
  Se050OefDevelopmentBoard* = 0xA1F4'u16

# =============================================================================
# Types
# =============================================================================

type
  Se050ProductInfo* = object
    ## GlobalPlatform IDENTIFY data returned by the SE05x Card Manager.
    configurationId*: seq[uint8]
    oefId*: uint16
    patchId*: seq[uint8]
    platformBuildId*: seq[uint8]
    fipsMode*: uint8
    prePersoState*: uint8
    romId*: seq[uint8]

# =============================================================================
# Helpers
# =============================================================================

proc se050ProductName*(oefId: uint16): string =
  ## Maps OEF IDs documented by AN12436 to human-readable SE050 variants.
  ## Unknown/newer IDs remain usable and are reported as "unknown".
  result = case oefId
  of Se050OefSe050C1: "SE050C1"
  of Se050OefSe050C2: "SE050C2"
  of Se050OefSe050B1: "SE050B1"
  of Se050OefSe050B2: "SE050B2"
  of Se050OefSe050A1: "SE050A1"
  of Se050OefSe050A2: "SE050A2"
  of Se050OefSe050D2: "SE050D2"
  of Se050OefSe050F2Legacy, Se050OefSe050F2: "SE050F2"
  of Se050OefSe050E2: "SE050E2"
  of Se050OefDevelopmentBoard: "SE050 development board"
  else: "unknown"

proc jcopPlatformId*(info: Se050ProductInfo): string =
  ## Returns the printable 16-byte JCOP Platform ID prefix used by NXP's
  ## GetInfo example. An empty string means the field is not printable.
  if info.platformBuildId.len < JcopPlatformIdLength:
    return ""

  for i in 0 ..< JcopPlatformIdLength:
    let b = info.platformBuildId[i]
    if b < 0x20'u8 or b > 0x7E'u8:
      return ""
    result.add(char(b))

proc buildGetDataIdentifyApdu*(): seq[uint8] =
  ## Builds the GlobalPlatform GET DATA (IDENTIFY) command used by NXP's
  ## GetInfo example to read the DF28 card-identification data.
  result = @[
    IdentifyCla,
    IdentifyInsGetData,
    IdentifyP1,
    IdentifyP2Proprietary,
    0x02'u8,
    IdentifyTagHigh,
    IdentifyTagLow,
    0x00'u8
  ]

proc fieldLengthError(name: string, expected: int, actual: int): SE[Se050ProductInfo] =
  result = fail[Se050ProductInfo](
    seInvalidResponse,
    &"GetDataIdentify {name} length must be {expected} bytes, got {actual}"
  )

proc parseGetDataIdentifyResponse*(
    response: openArray[uint8]
): SE[Se050ProductInfo] =
  ## Parses GlobalPlatform IDENTIFY / DF28 data.
  ##
  ## The known inner tags are validated strictly. Unknown inner tags are
  ## skipped so newer platform revisions can add fields without breaking OEF
  ## identification.
  let st = checkStatus(response, "GetDataIdentify")
  if not st.ok:
    return fail[Se050ProductInfo](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[Se050ProductInfo](data.error.kind, data.error.message, data.error.sw)

  if data.value.len < 6:
    return fail[Se050ProductInfo](
      seInvalidResponse,
      "GetDataIdentify response is too short for FE/DF28 identification data"
    )

  if data.value[0] != ProprietaryDataTag:
    return fail[Se050ProductInfo](
      seInvalidResponse,
      &"GetDataIdentify response does not start with proprietary tag 0x{ProprietaryDataTag.toHex(2)}"
    )

  let outerLength = readTlvLength(data.value, 1)
  if not outerLength.ok:
    return fail[Se050ProductInfo](
      outerLength.error.kind,
      outerLength.error.message,
      outerLength.error.sw
    )

  let outerStart = outerLength.value.nextIndex
  let outerEnd = outerStart + outerLength.value.length
  if outerEnd != data.value.len:
    return fail[Se050ProductInfo](
      seInvalidResponse,
      "GetDataIdentify proprietary-data length does not match response length"
    )

  if outerStart + 3 > outerEnd or
      data.value[outerStart] != IdentifyTagHigh or
      data.value[outerStart + 1] != IdentifyTagLow:
    return fail[Se050ProductInfo](
      seInvalidResponse,
      "GetDataIdentify response does not contain DF28 card-identification data"
    )

  let cardLength = readTlvLength(data.value, outerStart + 2)
  if not cardLength.ok:
    return fail[Se050ProductInfo](
      cardLength.error.kind,
      cardLength.error.message,
      cardLength.error.sw
    )

  let cardStart = cardLength.value.nextIndex
  let cardEnd = cardStart + cardLength.value.length
  if cardEnd != outerEnd:
    return fail[Se050ProductInfo](
      seInvalidResponse,
      "GetDataIdentify DF28 length does not match proprietary-data length"
    )

  var info: Se050ProductInfo
  var haveConfiguration = false
  var havePatch = false
  var havePlatformBuild = false
  var haveFipsMode = false
  var havePrePerso = false
  var haveRomId = false

  var index = cardStart
  while index < cardEnd:
    let parsed = readRawTlv(data.value, index)
    if not parsed.ok:
      return fail[Se050ProductInfo](
        parsed.error.kind,
        parsed.error.message,
        parsed.error.sw
      )

    if parsed.value.nextIndex > cardEnd:
      return fail[Se050ProductInfo](
        seInvalidResponse,
        "GetDataIdentify inner TLV extends past DF28 data"
      )

    let field = parsed.value.tlv
    case field.tag
    of ConfigurationIdTag:
      if haveConfiguration:
        return fail[Se050ProductInfo](seInvalidResponse, "duplicate GetDataIdentify configuration ID")
      if field.value.len != ConfigurationIdLength:
        return fieldLengthError("configuration ID", ConfigurationIdLength, field.value.len)
      info.configurationId = field.value
      info.oefId = (uint16(field.value[2]) shl 8) or uint16(field.value[3])
      haveConfiguration = true

    of PatchIdTag:
      if havePatch:
        return fail[Se050ProductInfo](seInvalidResponse, "duplicate GetDataIdentify patch ID")
      if field.value.len != PatchIdLength:
        return fieldLengthError("patch ID", PatchIdLength, field.value.len)
      info.patchId = field.value
      havePatch = true

    of PlatformBuildIdTag:
      if havePlatformBuild:
        return fail[Se050ProductInfo](seInvalidResponse, "duplicate GetDataIdentify platform build ID")
      if field.value.len != PlatformBuildIdLength:
        return fieldLengthError("platform build ID", PlatformBuildIdLength, field.value.len)
      info.platformBuildId = field.value
      havePlatformBuild = true

    of FipsModeTag:
      if haveFipsMode:
        return fail[Se050ProductInfo](seInvalidResponse, "duplicate GetDataIdentify FIPS mode")
      if field.value.len != 1:
        return fieldLengthError("FIPS mode", 1, field.value.len)
      info.fipsMode = field.value[0]
      haveFipsMode = true

    of PrePersoStateTag:
      if havePrePerso:
        return fail[Se050ProductInfo](seInvalidResponse, "duplicate GetDataIdentify pre-perso state")
      if field.value.len != 1:
        return fieldLengthError("pre-perso state", 1, field.value.len)
      info.prePersoState = field.value[0]
      havePrePerso = true

    of RomIdTag:
      if haveRomId:
        return fail[Se050ProductInfo](seInvalidResponse, "duplicate GetDataIdentify ROM ID")
      if field.value.len != RomIdLength:
        return fieldLengthError("ROM ID", RomIdLength, field.value.len)
      info.romId = field.value
      haveRomId = true

    else:
      discard

    index = parsed.value.nextIndex

  if not haveConfiguration:
    return fail[Se050ProductInfo](seInvalidResponse, "GetDataIdentify response is missing configuration ID")
  if not havePatch:
    return fail[Se050ProductInfo](seInvalidResponse, "GetDataIdentify response is missing patch ID")
  if not havePlatformBuild:
    return fail[Se050ProductInfo](seInvalidResponse, "GetDataIdentify response is missing platform build ID")
  if not haveFipsMode:
    return fail[Se050ProductInfo](seInvalidResponse, "GetDataIdentify response is missing FIPS mode")
  if not havePrePerso:
    return fail[Se050ProductInfo](seInvalidResponse, "GetDataIdentify response is missing pre-perso state")
  if not haveRomId:
    return fail[Se050ProductInfo](seInvalidResponse, "GetDataIdentify response is missing ROM ID")

  result = ok(info)

# =============================================================================
# API
# =============================================================================

proc getProductInfo*(se: Se050Transport): SE[Se050ProductInfo] =
  ## Reads Card Manager identification data.
  ##
  ## Call this directly after ATR/reset, before selecting the SE05x IoT Applet.
  ## NXP's GetInfo example sends this command as a raw GlobalPlatform APDU.
  let response = se.transceiveApdu(buildGetDataIdentifyApdu())
  if not response.ok:
    return fail[Se050ProductInfo](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseGetDataIdentifyResponse(response.value)
