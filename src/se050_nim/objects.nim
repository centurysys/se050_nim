# =============================================================================
# SE050 Secure Object helpers
# =============================================================================
#
# Low-level helpers for SE050 Secure Object management and inspection.
#
# This module intentionally exposes only SE050 primitive operations. It does not
# know about firmware packages, envelopes, provisioning records, or product
# policy.

import ./errors
import ./transport
import ./apdu
import ./tlv

# =============================================================================
# Constants
# =============================================================================

const
  Tag1 = 0x41'u8

  ResultSuccess = 0x01'u8
  ResultFailure = 0x02'u8

  # SE05x CheckObjectExists APDU.
  #
  # NXP AN12413 names this command:
  #   CLA = 0x80
  #   INS = INS_MGMT   = 0x04
  #   P1  = P1_DEFAULT = 0x00
  #   P2  = P2_EXIST   = 0x27
  #
  # Command data:
  #   TAG_1: 4-byte Secure Object identifier
  #
  # Response data:
  #   TAG_1: 1-byte Result
  CheckObjectExistsCla = 0x80'u8
  CheckObjectExistsIns = 0x04'u8
  CheckObjectExistsP1 = 0x00'u8
  CheckObjectExistsP2 = 0x27'u8

# =============================================================================
# Internal helpers
# =============================================================================

proc appendU32Be(buf: var seq[uint8], value: uint32) =
  buf.add(uint8((value shr 24) and 0xFF))
  buf.add(uint8((value shr 16) and 0xFF))
  buf.add(uint8((value shr 8) and 0xFF))
  buf.add(uint8(value and 0xFF))

proc buildCheckObjectExistsApdu(objectId: uint32): seq[uint8] =
  result = @[
    CheckObjectExistsCla,
    CheckObjectExistsIns,
    CheckObjectExistsP1,
    CheckObjectExistsP2,
    0x06'u8,

    # TAG_1: 4-byte Secure Object identifier
    Tag1,
    0x04'u8
  ]
  result.appendU32Be(objectId)

  # Le
  result.add(0x00'u8)

proc parseExistsResponse(response: openArray[uint8]): SE[bool] =
  let st = checkStatus(response, "CheckObjectExists")
  if not st.ok:
    return fail[bool](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[bool](data.error.kind, data.error.message, data.error.sw)

  if data.value.len < 3:
    return fail[bool](
      seInvalidResponse,
      "CheckObjectExists response does not contain TAG/LEN/VALUE"
    )

  if data.value[0] != Tag1:
    return fail[bool](
      seInvalidResponse,
      "CheckObjectExists response does not start with TAG_1"
    )

  let tlvLen = readTlvLength(data.value, 1)
  if not tlvLen.ok:
    return fail[bool](tlvLen.error.kind, tlvLen.error.message, tlvLen.error.sw)

  if tlvLen.value.length != 1:
    return fail[bool](
      seInvalidResponse,
      "CheckObjectExists response result length is not 1 byte"
    )

  if data.value.len < tlvLen.value.nextIndex + 1:
    return fail[bool](
      seInvalidResponse,
      "CheckObjectExists response is shorter than expected"
    )

  let value = data.value[tlvLen.value.nextIndex]
  case value
  of ResultSuccess:
    result = ok(true)
  of ResultFailure:
    result = ok(false)
  else:
    result = fail[bool](
      seInvalidResponse,
      "CheckObjectExists response contains an unknown Result value"
    )

# =============================================================================
# API
# =============================================================================

proc objectExists*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[bool] =
  ## Checks whether a Secure Object identifier exists in the selected SE050 applet.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[bool](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildCheckObjectExistsApdu(objectId)
  let response = se.transceiveApdu(apdu)
  if not response.ok:
    return fail[bool](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseExistsResponse(response.value)
