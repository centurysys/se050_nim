import std/unittest

import se050_nim

suite "SE050 raw TLV parsing":
  test "preserves a short-form TLV":
    let data = @[0x41'u8, 0x03'u8, 0x01'u8, 0x02'u8, 0x03'u8]

    let parsed = readRawTlv(data, 0)

    check parsed.ok
    check parsed.value.nextIndex == data.len
    check parsed.value.tlv.tag == 0x41'u8
    check parsed.value.tlv.value == @[0x01'u8, 0x02'u8, 0x03'u8]
    check parsed.value.tlv.encoded == data

  test "preserves an extended-length TLV":
    var data = @[0x41'u8, 0x81'u8, 0x80'u8]
    for i in 0 ..< 128:
      data.add(uint8(i))

    let parsed = readRawTlv(data, 0)

    check parsed.ok
    check parsed.value.nextIndex == data.len
    check parsed.value.tlv.value.len == 128
    check parsed.value.tlv.value[0] == 0x00'u8
    check parsed.value.tlv.value[^1] == 0x7F'u8
    check parsed.value.tlv.encoded == data

  test "accepts a zero-length value":
    let data = @[0x42'u8, 0x00'u8]

    let parsed = readRawTlv(data, 0)

    check parsed.ok
    check parsed.value.tlv.tag == 0x42'u8
    check parsed.value.tlv.value.len == 0
    check parsed.value.tlv.encoded == data

  test "parses consecutive TLVs":
    let data = @[
      0x41'u8, 0x01'u8, 0xAA'u8,
      0x42'u8, 0x02'u8, 0xBB'u8, 0xCC'u8
    ]

    let parsed = parseRawTlvs(data)

    check parsed.ok
    check parsed.value.len == 2
    check parsed.value[0].tag == 0x41'u8
    check parsed.value[0].value == @[0xAA'u8]
    check parsed.value[1].tag == 0x42'u8
    check parsed.value[1].value == @[0xBB'u8, 0xCC'u8]

  test "rejects a missing tag":
    let data: seq[uint8] = @[]

    let parsed = readRawTlv(data, 0)

    check not parsed.ok
    check parsed.error.kind == seInvalidResponse

  test "rejects a truncated value":
    let data = @[0x41'u8, 0x03'u8, 0x01'u8, 0x02'u8]

    let parsed = readRawTlv(data, 0)

    check not parsed.ok
    check parsed.error.kind == seInvalidResponse

  test "rejects an unsupported length encoding":
    let data = @[0x41'u8, 0x83'u8, 0x00'u8, 0x00'u8, 0x01'u8, 0xAA'u8]

    let parsed = readRawTlv(data, 0)

    check not parsed.ok
    check parsed.error.kind == seInvalidResponse
