import std/unittest

import se050_nim

suite "SE050 EC curve provisioning APDU":
  test "maps curve parameter identifiers":
    check ecCurveParamWireValue(ecCurveParamA) == 0x01'u8
    check ecCurveParamWireValue(ecCurveParamB) == 0x02'u8
    check ecCurveParamWireValue(ecCurveParamG) == 0x04'u8
    check ecCurveParamWireValue(ecCurveParamN) == 0x08'u8
    check ecCurveParamWireValue(ecCurveParamPrime) == 0x10'u8

  test "builds P-384 CreateECCurve APDU":
    let apdu = buildCreateEcCurveApdu(Se050CurveNistP384)
    check apdu.ok
    check apdu.value == @[
      0x80'u8, 0x01'u8, 0x0B'u8, 0x04'u8,
      0x03'u8,
      0x41'u8, 0x01'u8, 0x04'u8
    ]

  test "builds P-384 SetECCurveParam A APDU":
    var value = newSeq[uint8](48)
    for i in 0 ..< value.len:
      value[i] = uint8(i)

    let apdu = buildSetEcCurveParamApdu(
      Se050CurveNistP384,
      ecCurveParamA,
      value
    )

    check apdu.ok
    check apdu.value.len == 5 + 56
    check apdu.value[0 .. 10] == @[
      0x80'u8, 0x01'u8, 0x0B'u8, 0x40'u8,
      0x38'u8,
      0x41'u8, 0x01'u8, 0x04'u8,
      0x42'u8, 0x01'u8, 0x01'u8
    ]
    check apdu.value[11] == 0x43'u8
    check apdu.value[12] == 0x30'u8
    check apdu.value[13 .. ^1] == value

  test "encodes P-384 generator without extended TLV length":
    var generator = newSeq[uint8](97)
    generator[0] = 0x04'u8

    let apdu = buildSetEcCurveParamApdu(
      Se050CurveNistP384,
      ecCurveParamG,
      generator
    )

    check apdu.ok
    check apdu.value[4] == 0x69'u8
    check apdu.value[11] == 0x43'u8
    check apdu.value[12] == 0x61'u8
    check apdu.value[13 .. ^1] == generator

  test "encodes P-521 generator with 0x81 TLV length":
    var generator = newSeq[uint8](133)
    generator[0] = 0x04'u8

    let apdu = buildSetEcCurveParamApdu(
      Se050CurveNistP521,
      ecCurveParamG,
      generator
    )

    check apdu.ok
    check apdu.value[4] == 0x8E'u8
    check apdu.value[11] == 0x43'u8
    check apdu.value[12] == 0x81'u8
    check apdu.value[13] == 0x85'u8
    check apdu.value[14 .. ^1] == generator

  test "builds P-384 DeleteECCurve APDU":
    let apdu = buildDeleteEcCurveApdu(Se050CurveNistP384)
    check apdu.ok
    check apdu.value == @[
      0x80'u8, 0x04'u8, 0x0B'u8, 0x28'u8,
      0x03'u8,
      0x41'u8, 0x01'u8, 0x04'u8
    ]

  test "rejects non-Weierstrass curve identifiers":
    let createMontgomery = buildCreateEcCurveApdu(Se050CurveX25519)
    check not createMontgomery.ok
    check createMontgomery.error.kind == seInvalidArgument

    let setInvalid = buildSetEcCurveParamApdu(
      0x00'u8,
      ecCurveParamPrime,
      [0x01'u8]
    )
    check not setInvalid.ok
    check setInvalid.error.kind == seInvalidArgument

    let deleteReserved = buildDeleteEcCurveApdu(0x40'u8)
    check not deleteReserved.ok
    check deleteReserved.error.kind == seInvalidArgument

  test "rejects an empty curve parameter":
    let apdu = buildSetEcCurveParamApdu(
      Se050CurveNistP384,
      ecCurveParamB,
      newSeq[uint8](0)
    )
    check not apdu.ok
    check apdu.error.kind == seInvalidArgument

  test "rejects a SetECCurveParam payload larger than a short APDU":
    let oversized = newSeq[uint8](250)
    let apdu = buildSetEcCurveParamApdu(
      Se050CurveNistP384,
      ecCurveParamPrime,
      oversized
    )
    check not apdu.ok
    check apdu.error.kind == seApduTooLarge
