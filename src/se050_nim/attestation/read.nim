# =============================================================================
# SE050 ReadObject with Attestation
# =============================================================================
#
# Low-level Applet 7.2 ReadObject-with-Attestation support.
#
# This module intentionally stops before X.509 chain and ECDSA verification.
# It preserves the exact command APDU and response TLV bytes required by the
# later verification layer.

import ../errors
import ../transport
import ../apdu
import ../tlv
import ./constants

# =============================================================================
# Constants
# =============================================================================

const
  Se050ReadWithAttestationCla* = 0x80'u8
  Se050ReadWithAttestationIns* = 0x22'u8
  Se050ReadWithAttestationP1* = 0x00'u8
  Se050ReadWithAttestationP2* = 0x00'u8

  TagObjectData = 0x41'u8
  TagChipId = 0x42'u8
  TagAttributes = 0x43'u8
  TagObjectInfo = 0x44'u8
  TagAttestationKeyId = 0x45'u8
  TagAttestationAlgorithm = 0x46'u8
  TagFreshness = 0x47'u8
  TagTimestamp = 0x4F'u8
  TagSignature = 0x52'u8

# =============================================================================
# Types
# =============================================================================

type
  AttestationRequest* = object
    ## Encoded ReadObject-with-Attestation request.
    objectId*: uint32
    offset*: uint16
    length*: uint16
    attestationKeyId*: uint32
    algorithm*: uint8
    freshness*: seq[uint8]

    ## APDU bytes covered by the Applet 7.2 attestation signature.
    ## This is the command header, extended Lc, and command data. It excludes Le.
    signedCommandApdu*: seq[uint8]

    ## APDU sent to the SE050, including the two-byte extended Le.
    transmitApdu*: seq[uint8]

  AttestationResponse* = object
    ## Parsed response fields. `fields` and the raw byte arrays preserve the
    ## exact response encoding for subsequent ECDSA verification.
    objectDataPresent*: bool
    objectData*: seq[uint8]
    chipId*: seq[uint8]
    attributes*: seq[uint8]
    objectInfo*: seq[uint8]
    timestamp*: seq[uint8]
    signature*: seq[uint8]

    fields*: seq[RawTlv]

    ## Concatenated encoded TLVs preceding TAG_SIGNATURE.
    signedResponseData*: seq[uint8]

    ## Complete response data excluding SW1/SW2.
    rawResponseData*: seq[uint8]

  AttestedObjectRead* = object
    request*: AttestationRequest
    response*: AttestationResponse

# =============================================================================
# Encoding helpers
# =============================================================================

proc appendU16Be(buf: var seq[uint8], value: uint16) =
  buf.add(uint8((value shr 8) and 0xFF))
  buf.add(uint8(value and 0xFF))

proc appendU32Be(buf: var seq[uint8], value: uint32) =
  buf.add(uint8((value shr 24) and 0xFF))
  buf.add(uint8((value shr 16) and 0xFF))
  buf.add(uint8((value shr 8) and 0xFF))
  buf.add(uint8(value and 0xFF))

proc appendTlvLength(buf: var seq[uint8], length: int) =
  doAssert length >= 0
  doAssert length <= int(uint16.high)

  if length < 0x80:
    buf.add(uint8(length))
  elif length <= 0xFF:
    buf.add(0x81'u8)
    buf.add(uint8(length))
  else:
    buf.add(0x82'u8)
    buf.add(uint8((length shr 8) and 0xFF))
    buf.add(uint8(length and 0xFF))

proc appendByteArrayTlv(
    buf: var seq[uint8],
    tag: uint8,
    value: openArray[uint8]
) =
  buf.add(tag)
  buf.appendTlvLength(value.len)
  buf.add(value)

proc appendU8Tlv(buf: var seq[uint8], tag: uint8, value: uint8) =
  buf.add(tag)
  buf.add(0x01'u8)
  buf.add(value)

proc appendU16Tlv(buf: var seq[uint8], tag: uint8, value: uint16) =
  buf.add(tag)
  buf.add(0x02'u8)
  buf.appendU16Be(value)

proc appendU32Tlv(buf: var seq[uint8], tag: uint8, value: uint32) =
  buf.add(tag)
  buf.add(0x04'u8)
  buf.appendU32Be(value)

# =============================================================================
# Request encoding
# =============================================================================

proc buildReadObjectWithAttestationRequest*(
    objectId: uint32,
    freshness: openArray[uint8],
    attestationKeyId: uint32 = Se050AttestationKeyObjectId,
    algorithm: uint8 = Se050AttestationAlgorithmEcSha256,
    offset: uint16 = 0,
    length: uint16 = 0
): SE[AttestationRequest] =
  ## Builds the Applet 7.2 ReadObject-with-Attestation extended APDU.
  ##
  ## Optional TAG_2/TAG_3 are emitted only when offset/length are non-zero,
  ## matching the NXP Plug & Trust middleware request layout.
  if objectId == 0'u32:
    return fail[AttestationRequest](
      seInvalidArgument,
      "attested object id must not be zero"
    )

  if attestationKeyId == 0'u32:
    return fail[AttestationRequest](
      seInvalidArgument,
      "attestation key object id must not be zero"
    )

  if algorithm == 0'u8:
    return fail[AttestationRequest](
      seInvalidArgument,
      "attestation algorithm must not be zero"
    )

  if freshness.len == 0 or freshness.len > Se050AttestationFreshnessMaxLength:
    return fail[AttestationRequest](
      seInvalidArgument,
      "attestation freshness length must be in range 1..16 bytes"
    )

  var body: seq[uint8] = @[]
  body.appendU32Tlv(TagObjectData, objectId)

  if offset != 0'u16:
    body.appendU16Tlv(TagChipId, offset)

  if length != 0'u16:
    body.appendU16Tlv(TagAttributes, length)

  body.appendU32Tlv(TagAttestationKeyId, attestationKeyId)
  body.appendU8Tlv(TagAttestationAlgorithm, algorithm)
  body.appendByteArrayTlv(TagFreshness, freshness)

  if body.len > int(uint16.high):
    return fail[AttestationRequest](
      seApduTooLarge,
      "ReadObject-with-Attestation command data exceeds extended APDU length"
    )

  var signedApdu = @[
    Se050ReadWithAttestationCla,
    Se050ReadWithAttestationIns,
    Se050ReadWithAttestationP1,
    Se050ReadWithAttestationP2,

    # Extended Lc marker and 16-bit command-data length.
    0x00'u8,
    uint8((body.len shr 8) and 0xFF),
    uint8(body.len and 0xFF)
  ]
  signedApdu.add(body)

  var transmitApdu = signedApdu

  # Extended Le = 0x0000. The NXP middleware excludes these bytes from the
  # command APDU input used by attestation verification.
  transmitApdu.add(0x00'u8)
  transmitApdu.add(0x00'u8)

  result = ok(AttestationRequest(
    objectId: objectId,
    offset: offset,
    length: length,
    attestationKeyId: attestationKeyId,
    algorithm: algorithm,
    freshness: @freshness,
    signedCommandApdu: signedApdu,
    transmitApdu: transmitApdu
  ))

# =============================================================================
# Response parsing
# =============================================================================

proc parseReadObjectWithAttestationResponse*(
    response: openArray[uint8]
): SE[AttestationResponse] =
  ## Parses an Applet 7.2 ReadObject-with-Attestation response.
  ##
  ## Expected order:
  ##   optional TAG_1 object data
  ##   TAG_2 chip ID
  ##   TAG_3 object attributes
  ##   TAG_4 object information
  ##   TAG_TIMESTAMP
  ##   TAG_SIGNATURE
  let st = checkStatus(response, "ReadObject with Attestation")
  if not st.ok:
    return fail[AttestationResponse](
      st.error.kind,
      st.error.message,
      st.error.sw
    )

  let data = dataWithoutStatus(response)
  if not data.ok:
    return fail[AttestationResponse](
      data.error.kind,
      data.error.message,
      data.error.sw
    )

  let parsed = parseRawTlvs(data.value)
  if not parsed.ok:
    return fail[AttestationResponse](
      parsed.error.kind,
      parsed.error.message,
      parsed.error.sw
    )

  if parsed.value.len != 5 and parsed.value.len != 6:
    return fail[AttestationResponse](
      seInvalidResponse,
      "ReadObject-with-Attestation response must contain five or six TLVs"
    )

  var index = 0
  var objectDataPresent = false
  var objectData: seq[uint8] = @[]

  if parsed.value[index].tag == TagObjectData:
    objectDataPresent = true
    objectData = parsed.value[index].value
    inc index

  let expectedTags = @[
    TagChipId,
    TagAttributes,
    TagObjectInfo,
    TagTimestamp,
    TagSignature
  ]

  if parsed.value.len - index != expectedTags.len:
    return fail[AttestationResponse](
      seInvalidResponse,
      "ReadObject-with-Attestation response field count is invalid"
    )

  for expectedTag in expectedTags:
    if parsed.value[index].tag != expectedTag:
      return fail[AttestationResponse](
        seInvalidResponse,
        "ReadObject-with-Attestation response TLV order is invalid"
      )
    inc index

  let base = if objectDataPresent: 1 else: 0
  let chipId = parsed.value[base].value
  let attributes = parsed.value[base + 1].value
  let objectInfo = parsed.value[base + 2].value
  let timestamp = parsed.value[base + 3].value
  let signature = parsed.value[base + 4].value

  if chipId.len == 0:
    return fail[AttestationResponse](
      seInvalidResponse,
      "ReadObject-with-Attestation response has an empty chip ID"
    )

  if attributes.len == 0:
    return fail[AttestationResponse](
      seInvalidResponse,
      "ReadObject-with-Attestation response has empty object attributes"
    )

  if objectInfo.len == 0:
    return fail[AttestationResponse](
      seInvalidResponse,
      "ReadObject-with-Attestation response has empty object information"
    )

  if timestamp.len == 0:
    return fail[AttestationResponse](
      seInvalidResponse,
      "ReadObject-with-Attestation response has an empty timestamp"
    )

  if signature.len == 0:
    return fail[AttestationResponse](
      seInvalidResponse,
      "ReadObject-with-Attestation response has an empty signature"
    )

  var signedResponseData: seq[uint8] = @[]
  for fieldIndex in 0 ..< parsed.value.len - 1:
    signedResponseData.add(parsed.value[fieldIndex].encoded)

  result = ok(AttestationResponse(
    objectDataPresent: objectDataPresent,
    objectData: objectData,
    chipId: chipId,
    attributes: attributes,
    objectInfo: objectInfo,
    timestamp: timestamp,
    signature: signature,
    fields: parsed.value,
    signedResponseData: signedResponseData,
    rawResponseData: data.value
  ))

# =============================================================================
# Live SE050 API
# =============================================================================

proc readObjectWithAttestation*(
    se: Se050Transport,
    objectId: uint32,
    freshness: openArray[uint8],
    attestationKeyId: uint32 = Se050AttestationKeyObjectId,
    algorithm: uint8 = Se050AttestationAlgorithmEcSha256,
    offset: uint16 = 0,
    length: uint16 = 0,
    selectFirst: bool = true
): SE[AttestedObjectRead] =
  ## Reads a Secure Object with an NXP-provisioned attestation key.
  ##
  ## The returned structure is intentionally unverified. The exact verification
  ## inputs are retained for the later X.509/ECDSA verification layer.
  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[AttestedObjectRead](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let request = buildReadObjectWithAttestationRequest(
    objectId = objectId,
    freshness = freshness,
    attestationKeyId = attestationKeyId,
    algorithm = algorithm,
    offset = offset,
    length = length
  )
  if not request.ok:
    return fail[AttestedObjectRead](
      request.error.kind,
      request.error.message,
      request.error.sw
    )

  let response = se.transceiveApdu(request.value.transmitApdu)
  if not response.ok:
    return fail[AttestedObjectRead](
      response.error.kind,
      response.error.message,
      response.error.sw
    )

  let parsed = parseReadObjectWithAttestationResponse(response.value)
  if not parsed.ok:
    return fail[AttestedObjectRead](
      parsed.error.kind,
      parsed.error.message,
      parsed.error.sw
    )

  result = ok(AttestedObjectRead(
    request: request.value,
    response: parsed.value
  ))
