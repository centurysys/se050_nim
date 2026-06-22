# =============================================================================
# SE050 random number generation
# =============================================================================
#
# Low-level helper for the SE050 GetRandom command.
#
# This module intentionally exposes only the SE050 primitive operation. It does
# not know about firmware packages, envelopes, key wrapping, or provisioning
# records.

import ./errors
import ./transport
import ./apdu
import ./tlv

# =============================================================================
# Constants
# =============================================================================

const
  Se050MaxRandomLength* = 255

  Tag1 = 0x41'u8

  # SE05x GetRandom APDU.
  #
  # NXP Plug & Trust names this command:
  #   CLA = 0x80
  #   INS = INS_MGMT   = 0x04
  #   P1  = P1_DEFAULT = 0x00
  #   P2  = P2_RANDOM  = 0x49
  #
  # Command data:
  #   TAG_1: requested random byte length as u16
  #
  # Response data:
  #   TAG_1: generated random bytes
  GetRandomCla = 0x80'u8
  GetRandomIns = 0x04'u8
  GetRandomP1 = 0x00'u8
  GetRandomP2 = 0x49'u8

# =============================================================================
# Hex helpers
# =============================================================================

proc hexByte(b: uint8): string =
  const hex = "0123456789ABCDEF"
  result = newString(2)
  result[0] = hex[int((b shr 4) and 0x0F)]
  result[1] = hex[int(b and 0x0F)]

proc bytesToHex*(data: openArray[uint8], separator: string = ""): string =
  ## Converts bytes into uppercase hexadecimal text.
  for i, b in data:
    if i > 0:
      result.add(separator)
    result.add(hexByte(b))

# =============================================================================
# Internal helpers
# =============================================================================

proc validateRandomLength(length: int): SE[void] =
  if length <= 0:
    return fail[void](
      seInvalidArgument,
      "random length must be greater than zero"
    )

  if length > Se050MaxRandomLength:
    return fail[void](
      seInvalidArgument,
      "random length must be <= 255 bytes for one APDU"
    )

  result = ok()

proc buildGetRandomApdu(length: int): SE[seq[uint8]] =
  let valid = validateRandomLength(length)
  if not valid.ok:
    return fail[seq[uint8]](valid.error.kind, valid.error.message, valid.error.sw)

  result = ok(@[
    GetRandomCla,
    GetRandomIns,
    GetRandomP1,
    GetRandomP2,
    0x04'u8,

    # TAG_1: requested length as u16
    Tag1,
    0x02'u8,
    uint8((length shr 8) and 0xFF),
    uint8(length and 0xFF),

    # Le
    0x00'u8
  ])

proc parseRandomResponse(response: openArray[uint8], expectedLength: int): SE[seq[uint8]] =
  let st = checkStatus(response, "GetRandom")
  if not st.ok:
    return fail[seq[uint8]](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[seq[uint8]](data.error.kind, data.error.message, data.error.sw)

  if data.value.len < 2:
    return fail[seq[uint8]](
      seInvalidResponse,
      "GetRandom response does not contain TAG/LEN"
    )

  if data.value[0] != Tag1:
    return fail[seq[uint8]](
      seInvalidResponse,
      "GetRandom response does not start with TAG_1"
    )

  let tlvLen = readTlvLength(data.value, 1)
  if not tlvLen.ok:
    return fail[seq[uint8]](
      tlvLen.error.kind,
      tlvLen.error.message,
      tlvLen.error.sw
    )

  if tlvLen.value.length != expectedLength:
    return fail[seq[uint8]](
      seInvalidResponse,
      "GetRandom response length does not match requested length"
    )

  if data.value.len < tlvLen.value.nextIndex + expectedLength:
    return fail[seq[uint8]](
      seInvalidResponse,
      "GetRandom response is shorter than expected"
    )

  result = ok(data.value[tlvLen.value.nextIndex ..< tlvLen.value.nextIndex + expectedLength])

# =============================================================================
# API
# =============================================================================

proc getRandomBytes*(
    se: Se050Transport,
    length: int,
    selectFirst: bool = true
): SE[seq[uint8]] =
  ## Generates random bytes using the SE050 GetRandom command.
  ##
  ## The current implementation performs one APDU exchange and therefore limits
  ## length to 1..255 bytes. Longer outputs should be built by a higher-level
  ## chunking helper once needed.
  let valid = validateRandomLength(length)
  if not valid.ok:
    return fail[seq[uint8]](valid.error.kind, valid.error.message, valid.error.sw)

  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[seq[uint8]](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildGetRandomApdu(length)
  if not apdu.ok:
    return fail[seq[uint8]](apdu.error.kind, apdu.error.message, apdu.error.sw)

  let response = se.transceiveApdu(apdu.value)
  if not response.ok:
    return fail[seq[uint8]](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseRandomResponse(response.value, length)

proc getRandomHex*(
    se: Se050Transport,
    length: int,
    separator: string = "",
    selectFirst: bool = true
): SE[string] =
  ## Generates random bytes and returns them as uppercase hexadecimal text.
  let randomBytes = se.getRandomBytes(length = length, selectFirst = selectFirst)
  if not randomBytes.ok:
    return fail[string](randomBytes.error.kind, randomBytes.error.message, randomBytes.error.sw)

  result = ok(bytesToHex(randomBytes.value, separator))
