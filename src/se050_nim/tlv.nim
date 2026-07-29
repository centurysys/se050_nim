# =============================================================================
# SE050 TLV helpers
# =============================================================================
#
# Small BER-TLV style helpers used by SE050 APDU response parsers.
#
# Attestation verification needs the exact Tag + Length + Value byte sequence,
# not only the decoded value. RawTlv therefore preserves both representations.

import ./errors

# =============================================================================
# Types
# =============================================================================

type
  TlvLength* = tuple[length: int, nextIndex: int]

  RawTlv* = object
    ## One BER-TLV value preserving its original byte representation.
    tag*: uint8
    encoded*: seq[uint8]
    value*: seq[uint8]

# =============================================================================
# API
# =============================================================================

proc readTlvLength*(data: openArray[uint8], index: int): SE[TlvLength] =
  ## Reads short or extended BER-TLV style length.
  ##
  ## Supported forms:
  ##   12          -> length 0x12
  ##   81 80       -> length 0x80
  ##   82 00 12    -> length 0x12
  if index < 0 or index >= data.len:
    return fail[TlvLength](
      seInvalidResponse,
      "TLV length is missing"
    )

  let first = data[index]

  if (first and 0x80'u8) == 0:
    return ok((int(first), index + 1))

  let lenBytes = int(first and 0x7F'u8)
  if lenBytes == 0 or lenBytes > 2:
    return fail[TlvLength](
      seInvalidResponse,
      "unsupported TLV length encoding"
    )

  if index + lenBytes >= data.len:
    return fail[TlvLength](
      seInvalidResponse,
      "extended TLV length is truncated"
    )

  var value = 0
  for i in 0 ..< lenBytes:
    value = (value shl 8) or int(data[index + 1 + i])

  result = ok((value, index + 1 + lenBytes))

proc readRawTlv*(
    data: openArray[uint8],
    index: int
): SE[tuple[tlv: RawTlv, nextIndex: int]] =
  ## Reads one TLV and preserves the original encoded bytes.
  if index < 0 or index >= data.len:
    return fail[tuple[tlv: RawTlv, nextIndex: int]](
      seInvalidResponse,
      "TLV tag is missing"
    )

  let length = readTlvLength(data, index + 1)
  if not length.ok:
    return fail[tuple[tlv: RawTlv, nextIndex: int]](
      length.error.kind,
      length.error.message,
      length.error.sw
    )

  let valueStart = length.value.nextIndex
  let valueEnd = valueStart + length.value.length
  if valueEnd > data.len:
    return fail[tuple[tlv: RawTlv, nextIndex: int]](
      seInvalidResponse,
      "TLV value is truncated"
    )

  var tlv = RawTlv(tag: data[index])
  tlv.encoded = @data[index ..< valueEnd]
  if valueStart < valueEnd:
    tlv.value = @data[valueStart ..< valueEnd]
  else:
    tlv.value = @[]

  result = ok((tlv, valueEnd))

proc parseRawTlvs*(data: openArray[uint8]): SE[seq[RawTlv]] =
  ## Parses a byte sequence containing only complete, consecutive TLVs.
  var index = 0
  while index < data.len:
    let parsed = readRawTlv(data, index)
    if not parsed.ok:
      return fail[seq[RawTlv]](
        parsed.error.kind,
        parsed.error.message,
        parsed.error.sw
      )

    result.value.add(parsed.value.tlv)
    index = parsed.value.nextIndex

  result.ok = true
