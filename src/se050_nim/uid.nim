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
import ./apdu
import ./tlv

# =============================================================================
# Constants
# =============================================================================

const
  Se050UidLength* = 18

  Se050UniqueIdObjectId* = 0x7FFF0206'u32

  Tag1 = 0x41'u8

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
