# =============================================================================
# SE050 Secure Object helpers
# =============================================================================
#
# Low-level helpers for SE050 Secure Object management and inspection.
#
# This module intentionally exposes only SE050 primitive operations. It does not
# know about firmware packages, envelopes, provisioning records, or product
# policy.

import std/options

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
  Se050TypeBinaryFile* = 0x0B'u8

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

  # SE05x ReadType APDU.
  #
  # NXP names this command:
  #   CLA = 0x80
  #   INS = INS_READ   = 0x02
  #   P1  = P1_DEFAULT = 0x00
  #   P2  = P2_TYPE    = 0x26
  #
  # Command data:
  #   TAG_1: 4-byte Secure Object identifier
  #
  # Response data:
  #   TAG_1: 1-byte Secure Object type
  #   TAG_2: 1-byte TransientIndicator
  ReadTypeCla = 0x80'u8
  ReadTypeIns = 0x02'u8
  ReadTypeP1 = 0x00'u8
  ReadTypeP2 = 0x26'u8

  # SE05x ReadSize APDU.
  #
  # NXP names this command:
  #   CLA = 0x80
  #   INS = INS_READ   = 0x02
  #   P1  = P1_DEFAULT = 0x00
  #   P2  = P2_SIZE    = 0x07
  #
  # Command data:
  #   TAG_1: 4-byte Secure Object identifier
  #
  # Response data:
  #   TAG_1: byte array containing size, normally 2-byte big-endian
  ReadSizeCla = 0x80'u8
  ReadSizeIns = 0x02'u8
  ReadSizeP1 = 0x00'u8
  ReadSizeP2 = 0x07'u8

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
  ReadObjectCla = 0x80'u8
  ReadObjectIns = 0x02'u8
  ReadObjectP1 = 0x00'u8
  ReadObjectP2 = 0x00'u8

  # SE05x DeleteSecureObject APDU.
  #
  # NXP AN12413 names this command:
  #   CLA = 0x80
  #   INS = INS_MGMT          = 0x04
  #   P1  = P1_DEFAULT        = 0x00
  #   P2  = P2_DELETE_OBJECT  = 0x28
  #
  # Command data:
  #   TAG_1: 4-byte existing Secure Object identifier
  #
  # Response data:
  #   none, only SW1/SW2
  DeleteObjectCla = 0x80'u8
  DeleteObjectIns = 0x04'u8
  DeleteObjectP1 = 0x00'u8
  DeleteObjectP2 = 0x28'u8

  TransientPersistent = 0x01'u8
  TransientObject = 0x02'u8

  # Object deletion can take longer than normal inspection commands, especially
  # when removing key objects. During that time the T=1 over I2C layer may see
  # empty reads before the SE050 emits WTX or the final response. Keep the
  # extended wait local to deletion so quick commands keep failing fast.
  DeleteOperationMaxReadRetries = 200

# =============================================================================
# Types
# =============================================================================

type
  ObjectIdListChunk* = object
    ## One ReadIDList response chunk.
    more*: bool
    ids*: seq[uint32]

  ObjectTypeInfo* = object
    ## Type information returned by ReadType.
    objectType*: uint8
    transientIndicator*: Option[uint8]

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

proc readUIntBe(data: openArray[uint8], index: int, length: int): uint32 =
  ## Reads a 1..4 byte big-endian unsigned integer.
  for i in 0 ..< length:
    result = (result shl 8) or uint32(data[index + i])

proc buildReadObjectPropertyApdu(
    cla: uint8,
    ins: uint8,
    p1: uint8,
    p2: uint8,
    objectId: uint32
): seq[uint8] =
  result = @[
    cla,
    ins,
    p1,
    p2,
    0x06'u8,

    # TAG_1: 4-byte Secure Object identifier
    Tag1,
    0x04'u8
  ]
  result.appendU32Be(objectId)

  # Le
  result.add(0x00'u8)

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

proc buildReadTypeApdu(objectId: uint32): seq[uint8] =
  result = buildReadObjectPropertyApdu(
    cla = ReadTypeCla,
    ins = ReadTypeIns,
    p1 = ReadTypeP1,
    p2 = ReadTypeP2,
    objectId = objectId
  )

proc buildReadSizeApdu(objectId: uint32): seq[uint8] =
  result = buildReadObjectPropertyApdu(
    cla = ReadSizeCla,
    ins = ReadSizeIns,
    p1 = ReadSizeP1,
    p2 = ReadSizeP2,
    objectId = objectId
  )

proc buildReadObjectApdu(objectId: uint32): seq[uint8] =
  result = buildReadObjectPropertyApdu(
    cla = ReadObjectCla,
    ins = ReadObjectIns,
    p1 = ReadObjectP1,
    p2 = ReadObjectP2,
    objectId = objectId
  )

proc buildDeleteObjectApdu(objectId: uint32): seq[uint8] =
  result = @[
    DeleteObjectCla,
    DeleteObjectIns,
    DeleteObjectP1,
    DeleteObjectP2,
    0x06'u8,

    # TAG_1: 4-byte Secure Object identifier
    Tag1,
    0x04'u8
  ]
  result.appendU32Be(objectId)

  # DeleteSecureObject has no Le field.

proc parseReadSecureObjectResponse*(
    response: openArray[uint8]
): SE[seq[uint8]] =
  ## Parses a ReadObject response and returns the TAG_1 value.
  ##
  ## This pure helper is exported so higher-level parsers and unit tests can
  ## validate captured APDU responses without requiring a live SE050 transport.
  let st = checkStatus(response, "ReadObject")
  if not st.ok:
    return fail[seq[uint8]](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[seq[uint8]](data.error.kind, data.error.message, data.error.sw)

  if data.value.len < 2:
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
    return fail[seq[uint8]](
      tlvLen.error.kind,
      tlvLen.error.message,
      tlvLen.error.sw
    )

  let valueStart = tlvLen.value.nextIndex
  let valueEnd = valueStart + tlvLen.value.length
  if valueEnd > data.value.len:
    return fail[seq[uint8]](
      seInvalidResponse,
      "ReadObject response value is shorter than expected"
    )

  if valueEnd != data.value.len:
    return fail[seq[uint8]](
      seInvalidResponse,
      "ReadObject response contains trailing data after TAG_1"
    )

  result = ok(data.value[valueStart ..< valueEnd])

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

proc parseReadTypeResponse(response: openArray[uint8]): SE[ObjectTypeInfo] =
  let st = checkStatus(response, "ReadType")
  if not st.ok:
    return fail[ObjectTypeInfo](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[ObjectTypeInfo](data.error.kind, data.error.message, data.error.sw)

  var index = 0
  var seenType = false

  while index < data.value.len:
    let tag = data.value[index]
    inc index

    let tlvLen = readTlvLength(data.value, index)
    if not tlvLen.ok:
      return fail[ObjectTypeInfo](
        tlvLen.error.kind,
        tlvLen.error.message,
        tlvLen.error.sw
      )

    index = tlvLen.value.nextIndex
    let nextIndex = index + tlvLen.value.length
    if nextIndex > data.value.len:
      return fail[ObjectTypeInfo](
        seInvalidResponse,
        "ReadType response TLV value is truncated"
      )

    case tag
    of Tag1:
      if tlvLen.value.length != 1:
        return fail[ObjectTypeInfo](
          seInvalidResponse,
          "ReadType TAG_1 object type length is not 1 byte"
        )
      result.value.objectType = data.value[index]
      seenType = true

    of Tag2:
      if tlvLen.value.length != 1:
        return fail[ObjectTypeInfo](
          seInvalidResponse,
          "ReadType TAG_2 transient indicator length is not 1 byte"
        )
      result.value.transientIndicator = some(data.value[index])

    else:
      # Keep parsing known fields even if a future applet returns extra TLVs.
      discard

    index = nextIndex

  if not seenType:
    return fail[ObjectTypeInfo](
      seInvalidResponse,
      "ReadType response does not contain TAG_1 object type"
    )

  result.ok = true

proc parseReadSizeResponse(response: openArray[uint8]): SE[uint32] =
  let st = checkStatus(response, "ReadSize")
  if not st.ok:
    return fail[uint32](st.error.kind, st.error.message, st.error.sw)

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[uint32](data.error.kind, data.error.message, data.error.sw)

  if data.value.len < 3:
    return fail[uint32](
      seInvalidResponse,
      "ReadSize response does not contain TAG/LEN/VALUE"
    )

  if data.value[0] != Tag1:
    return fail[uint32](
      seInvalidResponse,
      "ReadSize response does not start with TAG_1"
    )

  let tlvLen = readTlvLength(data.value, 1)
  if not tlvLen.ok:
    return fail[uint32](tlvLen.error.kind, tlvLen.error.message, tlvLen.error.sw)

  if tlvLen.value.length <= 0 or tlvLen.value.length > 4:
    return fail[uint32](
      seInvalidResponse,
      "ReadSize value length is not in supported range 1..4"
    )

  if data.value.len < tlvLen.value.nextIndex + tlvLen.value.length:
    return fail[uint32](
      seInvalidResponse,
      "ReadSize response is shorter than expected"
    )

  result = ok(readUIntBe(
    data.value,
    tlvLen.value.nextIndex,
    tlvLen.value.length
  ))

proc objectTypeName*(objectType: uint8): string =
  ## Returns a readable SE05x secure object type name for common values.
  result = case objectType
  of 0x00: "NA"
  of 0x01: "EC_KEY_PAIR"
  of 0x02: "EC_PRIV_KEY"
  of 0x03: "EC_PUB_KEY"
  of 0x04: "RSA_KEY_PAIR"
  of 0x05: "RSA_KEY_PAIR_CRT"
  of 0x06: "RSA_PRIV_KEY"
  of 0x07: "RSA_PRIV_KEY_CRT"
  of 0x08: "RSA_PUB_KEY"
  of 0x09: "AES_KEY"
  of 0x0A: "DES_KEY"
  of 0x0B: "BINARY_FILE"
  of 0x0C: "UserID"
  of 0x0D: "COUNTER"
  of 0x0F: "PCR"
  of 0x10: "CURVE"
  of 0x11: "HMAC_KEY"
  of 0x21: "EC_KEY_PAIR_NIST_P192"
  of 0x22: "EC_PRIV_KEY_NIST_P192"
  of 0x23: "EC_PUB_KEY_NIST_P192"
  of 0x25: "EC_KEY_PAIR_NIST_P224"
  of 0x26: "EC_PRIV_KEY_NIST_P224"
  of 0x27: "EC_PUB_KEY_NIST_P224"
  of 0x29: "EC_KEY_PAIR_NIST_P256"
  of 0x2A: "EC_PRIV_KEY_NIST_P256"
  of 0x2B: "EC_PUB_KEY_NIST_P256"
  of 0x2D: "EC_KEY_PAIR_NIST_P384"
  of 0x2E: "EC_PRIV_KEY_NIST_P384"
  of 0x2F: "EC_PUB_KEY_NIST_P384"
  of 0x31: "EC_KEY_PAIR_NIST_P521"
  of 0x32: "EC_PRIV_KEY_NIST_P521"
  of 0x33: "EC_PUB_KEY_NIST_P521"
  of 0x65: "EC_KEY_PAIR_ED25519"
  of 0x66: "EC_PRIV_KEY_ED25519"
  of 0x67: "EC_PUB_KEY_ED25519"
  of 0x69: "EC_KEY_PAIR_MONT_DH_25519"
  of 0x6A: "EC_PRIV_KEY_MONT_DH_25519"
  of 0x6B: "EC_PUB_KEY_MONT_DH_25519"
  of 0x71: "EC_KEY_PAIR_MONT_DH_448"
  of 0x72: "EC_PRIV_KEY_MONT_DH_448"
  of 0x73: "EC_PUB_KEY_MONT_DH_448"
  else: "UNKNOWN"

proc transientIndicatorName*(value: uint8): string =
  result = case value
  of TransientPersistent: "persistent"
  of TransientObject: "transient"
  else: "unknown"

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

proc readObjectType*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[ObjectTypeInfo] =
  ## Reads the type and transient indicator for a Secure Object identifier.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[ObjectTypeInfo](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildReadTypeApdu(objectId)
  let response = se.transceiveApdu(apdu)
  if not response.ok:
    return fail[ObjectTypeInfo](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseReadTypeResponse(response.value)

proc readObjectSize*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[uint32] =
  ## Reads the size of a Secure Object identifier in bytes.
  ##
  ## Some object types may reject ReadSize with a status word. The caller should
  ## decide whether that is fatal for its use case.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[uint32](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildReadSizeApdu(objectId)
  let response = se.transceiveApdu(apdu)
  if not response.ok:
    return fail[uint32](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = parseReadSizeResponse(response.value)

proc readSecureObject*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[seq[uint8]] =
  ## Reads the raw value of a readable SE050 Secure Object.
  ##
  ## For EC key-pair and EC-public-key objects, the returned value is the public
  ## key. For a BINARY_FILE object, the returned value is the stored byte array.
  ## Object-type and policy checks remain the caller's responsibility.
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

  result = parseReadSecureObjectResponse(response.value)

proc deleteSecureObject*(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool = true
): SE[void] =
  ## Deletes a Secure Object identifier from the selected SE050 applet.
  ##
  ## This is the raw low-level primitive. User-facing safety policy, such as
  ## refusing to delete reserved object ranges, belongs in CLI/provisioning
  ## tools rather than in this library function. The SE050 object policy may
  ## still reject deletion.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[void](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let apdu = buildDeleteObjectApdu(objectId)

  let oldMaxRetries = se.maxRetries
  if se.maxRetries < DeleteOperationMaxReadRetries:
    se.maxRetries = DeleteOperationMaxReadRetries

  let response = se.transceiveApdu(apdu)
  se.maxRetries = oldMaxRetries

  if not response.ok:
    return fail[void](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  result = checkStatus(response.value, "DeleteSecureObject")

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
