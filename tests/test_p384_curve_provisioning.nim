import std/unittest

import se050_nim

proc hexBytes(value: string): seq[uint8] =
  check (value.len mod 2) == 0
  result = newSeq[uint8](value.len div 2)

  proc nibble(ch: char): uint8 =
    case ch
    of '0'..'9': uint8(ord(ch) - ord('0'))
    of 'a'..'f': uint8(ord(ch) - ord('a') + 10)
    of 'A'..'F': uint8(ord(ch) - ord('A') + 10)
    else:
      check false
      0'u8

  for i in 0 ..< result.len:
    result[i] = (nibble(value[i * 2]) shl 4) or nibble(value[i * 2 + 1])

proc expectedSetParamApdu(
    paramWireValue: uint8,
    value: seq[uint8]
): seq[uint8] =
  let payloadLen = 3 + 3 + 2 + value.len
  check payloadLen <= 255

  result = @[
    0x80'u8,
    0x01'u8,
    0x0B'u8,
    0x40'u8,
    uint8(payloadLen),
    0x41'u8,
    0x01'u8,
    Se050CurveNistP384,
    0x42'u8,
    0x01'u8,
    paramWireValue,
    0x43'u8,
    uint8(value.len)
  ]
  result.add(value)

suite "NIST P-384 curve provisioning":
  test "builds the fixed standard parameter sequence":
    let plan = buildNistP384ProvisioningApdus()
    check plan.ok
    check plan.value.len == 6

    check plan.value[0] == @[
      0x80'u8, 0x01'u8, 0x0B'u8, 0x04'u8,
      0x03'u8,
      0x41'u8, 0x01'u8, Se050CurveNistP384
    ]

    let a = hexBytes(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" &
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" &
      "FFFFFFFF0000000000000000FFFFFFFC"
    )
    let b = hexBytes(
      "B3312FA7E23EE7E4988E056BE3F82D19" &
      "181D9C6EFE8141120314088F5013875A" &
      "C656398D8A2ED19D2A85C8EDD3EC2AEF"
    )
    let g = hexBytes(
      "04" &
      "AA87CA22BE8B05378EB1C71EF320AD74" &
      "6E1D3B628BA79B9859F741E082542A38" &
      "5502F25DBF55296C3A545E3872760AB7" &
      "3617DE4A96262C6F5D9E98BF9292DC29" &
      "F8F41DBD289A147CE9DA3113B5F0B8C0" &
      "0A60B1CE1D7E819D7A431D7C90EA0E5F"
    )
    let n = hexBytes(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" &
      "FFFFFFFFFFFFFFFFC7634D81F4372DDF" &
      "581A0DB248B0A77AECEC196ACCC52973"
    )
    let prime = hexBytes(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" &
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" &
      "FFFFFFFF0000000000000000FFFFFFFF"
    )

    check a.len == 48
    check b.len == 48
    check g.len == 97
    check n.len == 48
    check prime.len == 48

    check plan.value[1] == expectedSetParamApdu(0x01'u8, a)
    check plan.value[2] == expectedSetParamApdu(0x02'u8, b)
    check plan.value[3] == expectedSetParamApdu(0x04'u8, g)
    check plan.value[4] == expectedSetParamApdu(0x08'u8, n)
    check plan.value[5] == expectedSetParamApdu(0x10'u8, prime)

  test "uses no ASN.1 sign padding for P-384 integers":
    let plan = buildNistP384ProvisioningApdus()
    check plan.ok

    # TAG_3 starts at byte 11 and its one-byte length at byte 12 for all
    # 48-byte integer parameters. The first value byte must be the actual 0xFF
    # field element, not an ASN.1 INTEGER sign-padding 0x00.
    for commandIndex in [1, 4, 5]:
      check plan.value[commandIndex][11] == 0x43'u8
      check plan.value[commandIndex][12] == 0x30'u8
      check plan.value[commandIndex][13] == 0xFF'u8

  test "keeps generator in uncompressed SEC1 form":
    let plan = buildNistP384ProvisioningApdus()
    check plan.ok

    let generatorCommand = plan.value[3]
    check generatorCommand[11] == 0x43'u8
    check generatorCommand[12] == 0x61'u8
    check generatorCommand[13] == 0x04'u8
    check generatorCommand.len == 5 + 105

  test "builds rollback before any live provisioning is needed":
    let deleteApdu = buildDeleteEcCurveApdu(Se050CurveNistP384)
    check deleteApdu.ok
    check deleteApdu.value == @[
      0x80'u8, 0x04'u8, 0x0B'u8, 0x28'u8,
      0x03'u8,
      0x41'u8, 0x01'u8, Se050CurveNistP384
    ]
