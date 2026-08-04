import std/unittest

import se050_nim/kitting/board_identity

suite "board serial number":
  test "removes only trailing Device Tree terminators":
    let parsed = parseBoardSerialNumber("11900000014\0\r\n")
    check parsed.ok
    check parsed.value == "11900000014"

  test "preserves leading zeroes":
    let parsed = parseBoardSerialNumber("0011900000014\0")
    check parsed.ok
    check parsed.value == "0011900000014"

  test "rejects empty or non-digit values":
    check not parseBoardSerialNumber("\0\n").ok
    check not parseBoardSerialNumber("11900A000014\0").ok
    check not parseBoardSerialNumber("11900\0000014\0").ok
    check not parseBoardSerialNumber(" 11900000014\0").ok
