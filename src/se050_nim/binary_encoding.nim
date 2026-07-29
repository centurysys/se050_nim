# =============================================================================
# Strict Base64 helpers for kitting records
# =============================================================================

import ./errors

const Base64Alphabet =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

proc base64Value(c: char): int =
  case c
  of 'A' .. 'Z': result = ord(c) - ord('A')
  of 'a' .. 'z': result = ord(c) - ord('a') + 26
  of '0' .. '9': result = ord(c) - ord('0') + 52
  of '+': result = 62
  of '/': result = 63
  else: result = -1

proc encodeBase64*(data: openArray[uint8]): string =
  ## Encodes bytes as canonical padded RFC 4648 Base64.
  var index = 0
  while index + 3 <= data.len:
    let value =
      (uint32(data[index]) shl 16) or
      (uint32(data[index + 1]) shl 8) or
      uint32(data[index + 2])

    result.add(Base64Alphabet[int((value shr 18) and 0x3F)])
    result.add(Base64Alphabet[int((value shr 12) and 0x3F)])
    result.add(Base64Alphabet[int((value shr 6) and 0x3F)])
    result.add(Base64Alphabet[int(value and 0x3F)])
    index += 3

  let remaining = data.len - index
  if remaining == 1:
    let value = uint32(data[index]) shl 16
    result.add(Base64Alphabet[int((value shr 18) and 0x3F)])
    result.add(Base64Alphabet[int((value shr 12) and 0x3F)])
    result.add("==")
  elif remaining == 2:
    let value =
      (uint32(data[index]) shl 16) or
      (uint32(data[index + 1]) shl 8)
    result.add(Base64Alphabet[int((value shr 18) and 0x3F)])
    result.add(Base64Alphabet[int((value shr 12) and 0x3F)])
    result.add(Base64Alphabet[int((value shr 6) and 0x3F)])
    result.add('=')

proc decodeBase64*(text: string): SE[seq[uint8]] =
  ## Decodes canonical padded RFC 4648 Base64.
  ## Whitespace and non-canonical padding are rejected.
  if text.len == 0:
    return ok(newSeq[uint8]())

  if (text.len mod 4) != 0:
    return fail[seq[uint8]](
      seInvalidArgument,
      "Base64 length must be a multiple of four"
    )

  var index = 0
  while index < text.len:
    let isLast = index + 4 == text.len
    let c0 = text[index]
    let c1 = text[index + 1]
    let c2 = text[index + 2]
    let c3 = text[index + 3]

    let v0 = base64Value(c0)
    let v1 = base64Value(c1)
    if v0 < 0 or v1 < 0:
      return fail[seq[uint8]](
        seInvalidArgument,
        "Base64 contains an invalid character"
      )

    let pad2 = c2 == '='
    let pad3 = c3 == '='

    if pad2 and not pad3:
      return fail[seq[uint8]](
        seInvalidArgument,
        "Base64 has invalid padding"
      )

    if (pad2 or pad3) and not isLast:
      return fail[seq[uint8]](
        seInvalidArgument,
        "Base64 padding is only allowed in the final quartet"
      )

    var v2 = 0
    var v3 = 0
    if not pad2:
      v2 = base64Value(c2)
      if v2 < 0:
        return fail[seq[uint8]](
          seInvalidArgument,
          "Base64 contains an invalid character"
        )

    if not pad3:
      v3 = base64Value(c3)
      if v3 < 0:
        return fail[seq[uint8]](
          seInvalidArgument,
          "Base64 contains an invalid character"
        )

    if pad2 and (v1 and 0x0F) != 0:
      return fail[seq[uint8]](
        seInvalidArgument,
        "Base64 has non-canonical two-byte padding bits"
      )

    if pad3 and not pad2 and (v2 and 0x03) != 0:
      return fail[seq[uint8]](
        seInvalidArgument,
        "Base64 has non-canonical one-byte padding bits"
      )

    let value =
      (uint32(v0) shl 18) or
      (uint32(v1) shl 12) or
      (uint32(v2) shl 6) or
      uint32(v3)

    result.value.add(uint8((value shr 16) and 0xFF))
    if not pad2:
      result.value.add(uint8((value shr 8) and 0xFF))
    if not pad3:
      result.value.add(uint8(value and 0xFF))

    index += 4

  result.ok = true
