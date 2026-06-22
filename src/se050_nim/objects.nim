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
  Tag2 = 0x42'u8

  ResultSuccess = 0x01'u8
  ResultFailure = 0x02'u8

  # SE05x_MoreIndicator_t in NXP Plug & Trust middleware:
  #   kSE05x_MoreIndicator_NA      = 0x00
  #   kSE05x_MoreIndicator_NO_MORE = 0x01
  #   kSE05x_MoreIndicator_MORE    = 0x02
  MoreInvalid = 0x00'u8
  MoreNoMore = 0x01'u8
  MorePresent = 0x02'u8

  SecureObjectTypeAll* = 0xFF'u8

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

  # SE05x ReadIDList APDU.
  #
  # NXP AN12413 names this command:
  #   CLA = 0x80
  #   INS = INS_READ   = 0x02
  #   P1  = P1_DEFAULT = 0x00
  #   P2  = P2_LIST    = 0x25
  #
  # Command data:
  #   TAG_1: 2-byte 0-based output offset
  #   TAG_2: 1-byte SecureObjectType filter, or 0xFF for all types
  #
  # Response data:
  #   TAG_1: 1-byte MoreIndicator
  #          0x01 = no more data, 0x02 = more data
  #   TAG_2: byte array containing 4-byte Secure Object identifiers
  ReadIdListCla = 0x80'u8
  ReadIdListIns = 0x02'u8
  ReadIdListP1 = 0x00'u8
  ReadIdListP2 = 0x25'u8

# =============================================================================
# Types
# =============================================================================

type
  ObjectIdListChunk* = object
    ## One ReadIDList response chunk.
    more*: bool
    ids*: seq[uint32]

# =============================================================================
# Internal helpers
# =============================================================================

proc appendU16Be(buf: var seq[uint8], value: uint16) =
  buf.add(uint8((value shr 8) and 0xFF))
  buf.add(uint8(value and 0xFF))

proc appendU32Be(buf: var seq[uint8], value: uint32) =
  buf.add(uint8((value shr 24) and 0xFF))
  buf.add(uint8((value shr 16) and 0xFF))
  buf.add(uint8((value shr 8) and 0xFF))
  buf.add(uint8(value and 0xFF))

proc readU32Be(data: openArray[uint8], index: int): uint32 =
  result =
    (uint32(data[index]) shl 24) or
    (uint32(data[index + 1]) shl 16) or
    (uint32(data[index + 2]) shl 8) or
    uint32(data[index + 3])

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

proc buildReadIdListApdu(offset: uint16, filter: uint8): seq[uint8] =
  result = @[
    ReadIdListCla,
    ReadIdListIns,
    ReadIdListP1,
    ReadIdListP2,
    0x07'u8,

    # TAG_1: 2-byte 0-based output offset
    Tag1,
    0x02'u8
  ]
  result.appendU16Be(offset)

  # TAG_2: 1-byte SecureObjectType filter, or 0xFF for all types
  result.add(Tag2)
  result.add(0x01'u8)
  result.add(filter)

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

proc parseReadIdListResponse(response: openArray[uint8]): SE[ObjectIdListChunk] =
  let st = checkStatus(response, "ReadIDList")
  if not st.ok:
    return fail[ObjectIdListChunk](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[ObjectIdListChunk](data.error.kind, data.error.message, data.error.sw)

  var index = 0
  var seenMore = false
  var seenIds = false

  while index < data.value.len:
    let tag = data.value[index]
    inc index

    let tlvLen = readTlvLength(data.value, index)
    if not tlvLen.ok:
      return fail[ObjectIdListChunk](
        tlvLen.error.kind,
        tlvLen.error.message,
        tlvLen.error.sw
      )

    index = tlvLen.value.nextIndex
    let nextIndex = index + tlvLen.value.length
    if nextIndex > data.value.len:
      return fail[ObjectIdListChunk](
        seInvalidResponse,
        "ReadIDList response TLV value is truncated"
      )

    case tag
    of Tag1:
      if tlvLen.value.length != 1:
        return fail[ObjectIdListChunk](
          seInvalidResponse,
          "ReadIDList MoreIndicator length is not 1 byte"
        )

      let moreValue = data.value[index]
      case moreValue
      of MoreNoMore:
        result.value.more = false
      of MorePresent:
        result.value.more = true
      else:
        return fail[ObjectIdListChunk](
          seInvalidResponse,
          "ReadIDList response contains an unknown MoreIndicator value"
        )
      seenMore = true

    of Tag2:
      if (tlvLen.value.length mod 4) != 0:
        return fail[ObjectIdListChunk](
          seInvalidResponse,
          "ReadIDList ID list length is not a multiple of 4"
        )

      var p = index
      while p < nextIndex:
        result.value.ids.add(readU32Be(data.value, p))
        p += 4
      seenIds = true

    else:
      # Keep parsing known fields even if a future applet returns extra TLVs.
      discard

    index = nextIndex

  if not seenMore:
    return fail[ObjectIdListChunk](
      seInvalidResponse,
      "ReadIDList response does not contain TAG_1 MoreIndicator"
    )

  if not seenIds:
    return fail[ObjectIdListChunk](
      seInvalidResponse,
      "ReadIDList response does not contain TAG_2 ID list"
    )

  result.ok = true

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

proc readObjectIdListChunk*(
    se: Se050Transport,
    offset: uint16 = 0,
    filter: uint8 = SecureObjectTypeAll,
    selectFirst: bool = true
): SE[ObjectIdListChunk] =
  ## Reads one chunk of Secure Object identifiers from the selected SE050 applet.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[ObjectIdListChunk](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildReadIdListApdu(offset = offset, filter = filter)
  let response = se.transceiveApdu(apdu)
  if not response.ok:
    return fail[ObjectIdListChunk](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseReadIdListResponse(response.value)

proc listObjectIds*(
    se: Se050Transport,
    filter: uint8 = SecureObjectTypeAll,
    selectFirst: bool = true
): SE[seq[uint32]] =
  ## Reads all visible Secure Object identifiers from the selected SE050 applet.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[seq[uint32]](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  var offset = 0
  var chunks = 0

  while true:
    if offset > int(uint16.high):
      return fail[seq[uint32]](
        seInvalidArgument,
        "ReadIDList offset exceeded uint16 range"
      )

    let chunk = se.readObjectIdListChunk(
      offset = uint16(offset),
      filter = filter,
      selectFirst = false
    )
    if not chunk.ok:
      return fail[seq[uint32]](
        chunk.error.kind,
        chunk.error.message,
        chunk.error.sw
      )

    for objectId in chunk.value.ids:
      result.value.add(objectId)

    inc chunks
    if chunks > 256:
      return fail[seq[uint32]](
        seInvalidResponse,
        "ReadIDList returned too many chunks"
      )

    if not chunk.value.more:
      break

    if chunk.value.ids.len == 0:
      return fail[seq[uint32]](
        seInvalidResponse,
        "ReadIDList indicated more chunks but returned no identifiers"
      )

    offset += chunk.value.ids.len

  result.ok = true
