import std/strutils
import std/unittest

import se050_nim

proc wrapIdentify(cardData: openArray[uint8]): seq[uint8] =
  doAssert cardData.len < 0x80
  let outerLength = 2 + 1 + cardData.len
  doAssert outerLength < 0x80

  result = @[
    0xFE'u8,
    uint8(outerLength),
    0xDF'u8,
    0x28'u8,
    uint8(cardData.len)
  ]
  for b in cardData:
    result.add(b)
  result.add(0x90'u8)
  result.add(0x00'u8)

proc se050E2CardData(): seq[uint8] =
  result = @[
    # Configuration ID. Bytes 2..3 are the documented OEF ID A921.
    0x01'u8, 0x0C'u8,
    0x00'u8, 0x01'u8, 0xA9'u8, 0x21'u8,
    0x89'u8, 0x0A'u8, 0x6F'u8, 0x56'u8,
    0x4A'u8, 0x23'u8, 0x9C'u8, 0x41'u8,

    # Patch ID.
    0x02'u8, 0x08'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x01'u8,

    # Platform build ID. The first 16 bytes spell J3R351029B411100.
    0x03'u8, 0x18'u8,
    0x4A'u8, 0x33'u8, 0x52'u8, 0x33'u8,
    0x35'u8, 0x31'u8, 0x30'u8, 0x32'u8,
    0x39'u8, 0x42'u8, 0x34'u8, 0x31'u8,
    0x31'u8, 0x31'u8, 0x30'u8, 0x30'u8,
    0x1A'u8, 0x08'u8, 0xFA'u8, 0x50'u8,
    0x67'u8, 0xB5'u8, 0xF2'u8, 0x56'u8,

    0x05'u8, 0x01'u8, 0x00'u8, # FIPS mode
    0x07'u8, 0x01'u8, 0x00'u8, # pre-perso state

    # ROM ID.
    0x08'u8, 0x08'u8,
    0x2E'u8, 0x5A'u8, 0xD8'u8, 0x84'u8,
    0x09'u8, 0xC9'u8, 0xBA'u8, 0xDB'u8
  ]

suite "SE05x product identification":
  test "builds the GlobalPlatform IDENTIFY APDU":
    check buildGetDataIdentifyApdu() == @[
      0x80'u8, 0xCA'u8, 0x00'u8, 0xFE'u8,
      0x02'u8, 0xDF'u8, 0x28'u8, 0x00'u8
    ]

  test "parses an SE050E2 GetInfo response":
    let parsed = parseGetDataIdentifyResponse(wrapIdentify(se050E2CardData()))
    require parsed.ok

    check parsed.value.oefId == Se050OefSe050E2
    check se050ProductName(parsed.value.oefId) == "SE050E2"
    check parsed.value.configurationId == @[
      0x00'u8, 0x01'u8, 0xA9'u8, 0x21'u8,
      0x89'u8, 0x0A'u8, 0x6F'u8, 0x56'u8,
      0x4A'u8, 0x23'u8, 0x9C'u8, 0x41'u8
    ]
    check parsed.value.patchId == @[
      0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
      0x00'u8, 0x00'u8, 0x00'u8, 0x01'u8
    ]
    check parsed.value.jcopPlatformId() == "J3R351029B411100"
    check parsed.value.fipsMode == 0x00'u8
    check parsed.value.prePersoState == 0x00'u8
    check parsed.value.romId == @[
      0x2E'u8, 0x5A'u8, 0xD8'u8, 0x84'u8,
      0x09'u8, 0xC9'u8, 0xBA'u8, 0xDB'u8
    ]

  test "ignores unknown future DF28 fields":
    var cardData = se050E2CardData()
    cardData.add(@[0x09'u8, 0x02'u8, 0x12'u8, 0x34'u8])

    let parsed = parseGetDataIdentifyResponse(wrapIdentify(cardData))
    require parsed.ok
    check parsed.value.oefId == Se050OefSe050E2

  test "maps documented SE050 OEF variants":
    check se050ProductName(Se050OefSe050E2) == "SE050E2"
    check se050ProductName(Se050OefSe050F2) == "SE050F2"
    check se050ProductName(Se050OefSe050F2Legacy) == "SE050F2"
    check se050ProductName(0xFFFF'u16) == "unknown"

  test "rejects a malformed configuration ID":
    var cardData = se050E2CardData()
    cardData[1] = 0x0B'u8

    let parsed = parseGetDataIdentifyResponse(wrapIdentify(cardData))
    check not parsed.ok
    check parsed.error.kind == seInvalidResponse
    check parsed.error.message.contains("configuration ID length")
