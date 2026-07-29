import std/unittest

import se050_nim/binary_encoding

suite "strict Base64 encoding":
  test "encodes and decodes RFC 4648 vectors":
    check encodeBase64(@[]) == ""
    check encodeBase64(@[0x66'u8]) == "Zg=="
    check encodeBase64(@[0x66'u8, 0x6F'u8]) == "Zm8="
    check encodeBase64(@[0x66'u8, 0x6F'u8, 0x6F'u8]) == "Zm9v"

    let decoded = decodeBase64("AAECAwQFBgcICQ==")
    check decoded.ok
    check decoded.value == @[0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]

  test "rejects malformed and non-canonical input":
    check not decodeBase64("A").ok
    check not decodeBase64("A===").ok
    check not decodeBase64("Zh==").ok
    check not decodeBase64("Zm9=").ok
    check not decodeBase64("Zm 8=").ok
