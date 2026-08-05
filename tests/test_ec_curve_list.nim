import std/unittest

import se050_nim

suite "SE050 EC curve list":
  test "builds ReadECCurveList APDU":
    check buildReadEcCurveListApdu() == @[
      0x80'u8,
      0x02'u8,
      0x0B'u8,
      0x25'u8,
      0x00'u8
    ]

  test "parses SetIndicator list with extended TLV length":
    # Representative 17-entry response: curve IDs 0x01..0x11 each carry one
    # SetIndicator. P-256/P-384/P-521 are set in this vector.
    let response = @[
      0x41'u8, 0x82'u8, 0x00'u8, 0x11'u8,
      0x01'u8, 0x01'u8, 0x02'u8, 0x02'u8, 0x02'u8,
      0x01'u8, 0x02'u8, 0x01'u8, 0x01'u8, 0x01'u8,
      0x01'u8, 0x01'u8, 0x01'u8, 0x01'u8, 0x01'u8,
      0x02'u8, 0x01'u8,
      0x90'u8, 0x00'u8
    ]

    let parsed = parseReadEcCurveListResponse(response)
    check parsed.ok
    check parsed.value.indicators.len == 17

    let p256 = parsed.value.ecCurveSetState(Se050CurveNistP256)
    let p384 = parsed.value.ecCurveSetState(Se050CurveNistP384)
    let p521 = parsed.value.ecCurveSetState(Se050CurveNistP521)
    let p224 = parsed.value.ecCurveSetState(0x02'u8)

    check p256.ok
    check p256.value == ecCurveSet
    check p384.ok
    check p384.value == ecCurveSet
    check p521.ok
    check p521.value == ecCurveSet
    check p224.ok
    check p224.value == ecCurveNotSet

  test "reports curve instantiation state":
    let info = EcCurveListInfo(indicators: @[
      0x01'u8,
      0x01'u8,
      0x02'u8,
      0x01'u8,
      0x02'u8
    ])

    let p256 = info.isEcCurveInstantiated(Se050CurveNistP256)
    let p384 = info.isEcCurveInstantiated(Se050CurveNistP384)
    let p521 = info.isEcCurveInstantiated(Se050CurveNistP521)

    check p256.ok and p256.value
    check p384.ok and not p384.value
    check p521.ok and p521.value

  test "rejects invalid SetIndicator":
    let response = @[
      0x41'u8, 0x03'u8,
      0x01'u8, 0x00'u8, 0x02'u8,
      0x90'u8, 0x00'u8
    ]

    let parsed = parseReadEcCurveListResponse(response)
    check not parsed.ok
    check parsed.error.kind == seInvalidResponse

  test "rejects non-Weierstrass and out-of-list curve IDs":
    let info = EcCurveListInfo(indicators: @[0x01'u8, 0x02'u8])

    let zero = info.ecCurveSetState(0x00'u8)
    check not zero.ok
    check zero.error.kind == seInvalidArgument

    let montgomery = info.ecCurveSetState(0x41'u8)
    check not montgomery.ok
    check montgomery.error.kind == seInvalidArgument

    let missing = info.ecCurveSetState(0x03'u8)
    check not missing.ok
    check missing.error.kind == seInvalidArgument

  test "rejects malformed ReadECCurveList response":
    let wrongTag = parseReadEcCurveListResponse(@[
      0x42'u8, 0x01'u8, 0x02'u8,
      0x90'u8, 0x00'u8
    ])
    check not wrongTag.ok
    check wrongTag.error.kind == seInvalidResponse

    let truncated = parseReadEcCurveListResponse(@[
      0x41'u8, 0x03'u8,
      0x01'u8, 0x02'u8,
      0x90'u8, 0x00'u8
    ])
    check not truncated.ok
    check truncated.error.kind == seInvalidResponse

    let failed = parseReadEcCurveListResponse(@[
      0x69'u8, 0x85'u8
    ])
    check not failed.ok
    check failed.error.kind == seApduStatusError
    check failed.error.sw == 0x6985'u16
