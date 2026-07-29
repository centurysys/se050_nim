import std/unittest

import se050_nim

suite "SE050 generic Secure Object read parsing":
  test "parses a short TAG_1 value":
    let response = @[
      0x41'u8, 0x03'u8,
      0x01'u8, 0x02'u8, 0x03'u8,
      0x90'u8, 0x00'u8
    ]

    let parsed = parseReadSecureObjectResponse(response)

    check parsed.ok
    check parsed.value == @[0x01'u8, 0x02'u8, 0x03'u8]

  test "parses an extended TAG_1 length":
    var response = @[0x41'u8, 0x81'u8, 0x80'u8]
    for i in 0 ..< 128:
      response.add(uint8(i))
    response.add(0x90'u8)
    response.add(0x00'u8)

    let parsed = parseReadSecureObjectResponse(response)

    check parsed.ok
    check parsed.value.len == 128
    check parsed.value[0] == 0x00'u8
    check parsed.value[^1] == 0x7F'u8

  test "rejects a non-success status word":
    let response = @[0x41'u8, 0x00'u8, 0x6A'u8, 0x82'u8]

    let parsed = parseReadSecureObjectResponse(response)

    check not parsed.ok
    check parsed.error.kind == seApduStatusError
    check parsed.error.sw == 0x6A82'u16

  test "rejects a response with the wrong first tag":
    let response = @[0x42'u8, 0x01'u8, 0x00'u8, 0x90'u8, 0x00'u8]

    let parsed = parseReadSecureObjectResponse(response)

    check not parsed.ok
    check parsed.error.kind == seInvalidResponse

  test "rejects a truncated value":
    let response = @[
      0x41'u8, 0x03'u8,
      0x01'u8, 0x02'u8,
      0x90'u8, 0x00'u8
    ]

    let parsed = parseReadSecureObjectResponse(response)

    check not parsed.ok
    check parsed.error.kind == seInvalidResponse

  test "rejects trailing response data":
    let response = @[
      0x41'u8, 0x01'u8, 0xAA'u8,
      0x42'u8, 0x00'u8,
      0x90'u8, 0x00'u8
    ]

    let parsed = parseReadSecureObjectResponse(response)

    check not parsed.ok
    check parsed.error.kind == seInvalidResponse

  test "builds an explicit BinaryFile range read APDU":
    let apdu = buildReadObjectRangeApdu(
      objectId = 0xF0000013'u32,
      offset = 0x00E0'u16,
      length = 0x00E0'u16
    )

    check apdu == @[
      0x80'u8, 0x02'u8, 0x00'u8, 0x00'u8, 0x0E'u8,
      0x41'u8, 0x04'u8, 0xF0'u8, 0x00'u8, 0x00'u8, 0x13'u8,
      0x42'u8, 0x02'u8, 0x00'u8, 0xE0'u8,
      0x43'u8, 0x02'u8, 0x00'u8, 0xE0'u8,
      0x00'u8
    ]

  test "uses a one-frame default BinaryFile chunk size":
    check DefaultBinaryReadChunkSize == 224

