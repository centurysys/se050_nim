# =============================================================================
# SE050 TLV helpers
# =============================================================================
#
# Small BER-TLV style helpers used by SE050 APDU response parsers.

import ./errors

# =============================================================================
# Types
# =============================================================================

type
  TlvLength* = tuple[length: int, nextIndex: int]

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
  if index >= data.len:
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
