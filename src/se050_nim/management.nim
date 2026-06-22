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
