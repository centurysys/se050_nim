# =============================================================================
# SE050 UID access
# =============================================================================
#
# Minimal high-level helper to read the 18-byte unique ID from NXP SE050/SE051.
#
# Layering:
#
#   i2c.nim
#     ↓
#   transport.nim
#     ↓
#   uid.nim
#
# This module only uses plain APDU exchange over the transport layer.
# It does not require SCP03, authentication, or NXP Plug & Trust Middleware.

import ./errors
import ./transport

# =============================================================================
# Constants
# =============================================================================

const
  Se050UidLength* = 18

  Se050UniqueIdObjectId* = 0x7FFF0206'u32

  SwSuccess = 0x9000'u16

  Tag1 = 0x41'u8

  SelectAppletApdu*: array[22, uint8] = [
    0x00'u8, 0xA4'u8, 0x04'u8, 0x00'u8, 0x10'u8,
    0xA0'u8, 0x00'u8, 0x00'u8, 0x03'u8,
    0x96'u8, 0x54'u8, 0x53'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x01'u8, 0x03'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8
  ]

  ReadUidObjectApdu*: array[20, uint8] = [
    0x80'u8, 0x02'u8, 0x00'u8, 0x00'u8, 0x0E'u8,

    # TAG_1: object id = 0x7FFF0206
    0x41'u8, 0x04'u8,
    0x7F'u8, 0xFF'u8, 0x02'u8, 0x06'u8,

    # TAG_2: 2-byte offset = 0
    0x42'u8, 0x02'u8, 0x00'u8, 0x00'u8,

    # TAG_3: 2-byte length = 18
    0x43'u8, 0x02'u8, 0x00'u8, 0x12'u8,

    0x00'u8
  ]

# --------------------------------------------------------------------------------
# Utility:
# --------------------------------------------------------------------------------

proc hexByte(b: uint8): string =
  const hex = "0123456789ABCDEF"
  result = newString(2)
  result[0] = hex[int((b shr 4) and 0x0F)]
  result[1] = hex[int(b and 0x0F)]

# --------------------------------------------------------------------------------
# API:
# --------------------------------------------------------------------------------

proc uidToHex*(uid: openArray[uint8], separator: string = ""): string =
  ## Converts UID bytes into uppercase hexadecimal text.
  for i, b in uid:
    if i > 0:
      result.add(separator)
    result.add(hexByte(b))

# --------------------------------------------------------------------------------
# Internal:
# --------------------------------------------------------------------------------

proc statusWord(response: openArray[uint8]): SE[uint16] =
  if response.len < 2:
    return fail[uint16](seInvalidResponse, "APDU response is too short")

  let sw1 = uint16(response[response.len - 2])
  let sw2 = uint16(response[response.len - 1])
  result = ok((sw1 shl 8) or sw2)

# --------------------------------------------------------------------------------
# Internal:
# --------------------------------------------------------------------------------

proc checkStatus(response: openArray[uint8], context: string): SE[void] =
  let sw = statusWord(response)
  if not sw.ok:
    return fail[void](sw.error.kind, sw.error.message, sw.error.sw)

  if sw.value != SwSuccess:
    return fail[void](
      seApduStatusError,
      context & " failed",
      sw.value
    )

  result = ok()

# --------------------------------------------------------------------------------
# Internal:
# --------------------------------------------------------------------------------

proc dataWithoutStatus(response: openArray[uint8]): SE[seq[uint8]] =
  if response.len < 2:
    return fail[seq[uint8]](seInvalidResponse, "APDU response is too short")

  result = ok(@response[0 ..< response.len - 2])

# --------------------------------------------------------------------------------
# Internal:
# --------------------------------------------------------------------------------

proc readTlvLength(data: openArray[uint8], index: int): SE[tuple[length: int, nextIndex: int]] =
  ## Reads short or extended BER-TLV style length.
  ##
  ## Supported forms:
  ##   12          -> length 0x12
  ##   81 80       -> length 0x80
  ##   82 00 12    -> length 0x12
  if index >= data.len:
    return fail[tuple[length: int, nextIndex: int]](
      seInvalidResponse,
      "TLV length is missing"
    )

  let first = data[index]

  if (first and 0x80'u8) == 0:
    return ok((int(first), index + 1))

  let lenBytes = int(first and 0x7F'u8)
  if lenBytes == 0 or lenBytes > 2:
    return fail[tuple[length: int, nextIndex: int]](
      seInvalidResponse,
      "unsupported TLV length encoding"
    )

  if index + lenBytes >= data.len:
    return fail[tuple[length: int, nextIndex: int]](
      seInvalidResponse,
      "extended TLV length is truncated"
    )

  var value = 0
  for i in 0 ..< lenBytes:
    value = (value shl 8) or int(data[index + 1 + i])

  result = ok((value, index + 1 + lenBytes))

# --------------------------------------------------------------------------------
# Internal:
# --------------------------------------------------------------------------------

proc parseUidFromReadObjectResponse(response: openArray[uint8]): SE[array[Se050UidLength, uint8]] =
  let st = checkStatus(response, "Read UID object")
  if not st.ok:
    return fail[array[Se050UidLength, uint8]](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[array[Se050UidLength, uint8]](data.error.kind, data.error.message, data.error.sw)

  if data.value.len < 2:
    return fail[array[Se050UidLength, uint8]](
      seInvalidResponse,
      "ReadObject response does not contain TAG/LEN"
    )

  if data.value[0] != Tag1:
    return fail[array[Se050UidLength, uint8]](
      seInvalidResponse,
      "ReadObject response does not start with TAG_1"
    )

  let tlvLen = readTlvLength(data.value, 1)
  if not tlvLen.ok:
    return fail[array[Se050UidLength, uint8]](
      tlvLen.error.kind,
      tlvLen.error.message,
      tlvLen.error.sw
    )

  if tlvLen.value.length != Se050UidLength:
    return fail[array[Se050UidLength, uint8]](
      seInvalidResponse,
      "ReadObject response length is not 18 bytes"
    )

  if data.value.len < tlvLen.value.nextIndex + Se050UidLength:
    return fail[array[Se050UidLength, uint8]](
      seInvalidResponse,
      "ReadObject response is shorter than UID length"
    )

  for i in 0 ..< Se050UidLength:
    result.value[i] = data.value[tlvLen.value.nextIndex + i]

  result.ok = true

# --------------------------------------------------------------------------------
# API:
# --------------------------------------------------------------------------------

proc selectApplet*(se: Se050Transport): SE[void] =
  ## Selects the SE050 IoT applet.
  let response = se.transceiveApdu(SelectAppletApdu)
  if not response.ok:
    return fail[void](response.error.kind, response.error.message, response.error.sw)

  result = checkStatus(response.value, "SELECT applet")

# --------------------------------------------------------------------------------
# API:
# --------------------------------------------------------------------------------

proc readUidRaw*(se: Se050Transport, selectFirst: bool = true): SE[array[Se050UidLength, uint8]] =
  ## Reads the 18-byte SE050 unique ID.
  ##
  ## By default this selects the SE050 IoT applet first, then reads object
  ## 0x7FFF0206.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[array[Se050UidLength, uint8]](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let response = se.transceiveApdu(ReadUidObjectApdu)
  if not response.ok:
    return fail[array[Se050UidLength, uint8]](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseUidFromReadObjectResponse(response.value)

# --------------------------------------------------------------------------------
# API:
# --------------------------------------------------------------------------------

proc readUidHex*(se: Se050Transport, separator: string = "", selectFirst: bool = true): SE[string] =
  ## Reads the SE050 unique ID and returns it as uppercase hexadecimal text.
  let uid = se.readUidRaw(selectFirst = selectFirst)
  if not uid.ok:
    return fail[string](uid.error.kind, uid.error.message, uid.error.sw)

  result = ok(uidToHex(uid.value, separator))
