import std/unittest

import se050_nim/secure_memory

suite "secure memory clearing":
  test "clears a byte sequence in place":
    var data = @[0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8]

    secureZero(data)

    check data == @[0'u8, 0'u8, 0'u8, 0'u8]

  test "clears a fixed byte array in place":
    var data: array[4, uint8] = [1'u8, 2'u8, 3'u8, 4'u8]

    secureZero(data)

    check data == [0'u8, 0'u8, 0'u8, 0'u8]

  test "clears a mutable string without changing its length":
    var data = "private material"
    let originalLength = data.len

    secureZero(data)

    check data.len == originalLength
    for value in data:
      check value == '\0'
