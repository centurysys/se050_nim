import std/base64
import std/strutils
import std/unittest

import se050_nim

proc bytesFromHex(text: string): seq[uint8] =
  doAssert (text.len mod 2) == 0
  var offset = 0
  while offset < text.len:
    result.add(uint8(parseHexInt(text[offset .. offset + 1])))
    offset += 2

proc bytesFromBase64(text: string): seq[uint8] =
  let decoded = decode(text)
  result = newSeq[uint8](decoded.len)
  for i, value in decoded:
    result[i] = uint8(ord(value))

const
  P256Pkcs8Pem = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy3sAkkrVYE3ATOP5
5+y7NyCycXe+jobXgjfD59+Qx5mhRANCAASJ2d96kCiFAs5uEPwc0nJnPmp6I701
KMJUonnqRKesw5cG/EqJ9AZll/LjLQWrP9jjGJJcJVsm0+67fuNTrqD5
-----END PRIVATE KEY-----
"""

  P256Sec1Pem = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMt7AJJK1WBNwEzj+efsuzcgsnF3vo6G14I3w+ffkMeZoAoGCCqGSM49
AwEHoUQDQgAEidnfepAohQLObhD8HNJyZz5qeiO9NSjCVKJ56kSnrMOXBvxKifQG
ZZfy4y0Fqz/Y4xiSXCVbJtPuu37jU66g+Q==
-----END EC PRIVATE KEY-----
"""

  P256PublicPem = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEidnfepAohQLObhD8HNJyZz5qeiO9
NSjCVKJ56kSnrMOXBvxKifQGZZfy4y0Fqz/Y4xiSXCVbJtPuu37jU66g+Q==
-----END PUBLIC KEY-----
"""

  P384Pkcs8Pem = """-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDASu49VbEQhKA5BwaP3
xJ3WUYqSY1jgYx6T7xqlxnOdYJ+GIUzSfnIJ9jj6UFFQxYihZANiAATtY5e3CuHG
PxRRm9eWjBplQbgw6ztMqEJ9zQKv8Ml5j6lgQhR6LFA0KikAVptvXuDmtJg3ed4K
4HQfa6DMQrL5fZuaQzfsA8aG+OU4Y9GilgoQsC6Iu3Bpq9oIiAL7WJU=
-----END PRIVATE KEY-----
"""

  P384SupportedPkcs8Pem = """-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBvL/J7b4MYvNVNJUU8
raZEUibwMwYyUAkKtRbkNUGUTfpCTMz6ucbsnZaQew5j9SihZANiAATGZbukg2ZS
hY/z6gg/U5e8j5VBy+Z+hDYTFJHnQFPRRfqzdYcGwyq6b1kbvDY6sha61Ee7gVGD
aJr27HFNkPpkFdfN/FFD5/TD1W1cgq3lmfAFhXL6wirXN23xAl701WY=
-----END PRIVATE KEY-----
"""

  P521Pkcs8Pem = """-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAXljZhw1cuf+vnGmY
NjAOWt3bOVSp0e/myR5wPDCTxYAk7S5YZxzfc3YD47oZboWDd0HWj2zwke7EnNKt
7rMz072hgYkDgYYABACz0QCaqHWHfQJ4a4FKPxP6yFQ/tTlcof4w5+zcLRUtsARE
2/w3VH8CHvrElh+fzbtCbKfjbwFxl492Ty865T8aawCgHWpOFIFidC14H22DvxfL
aqDiNgzhRiVb+3tzJas1jJnAzubQHvPPVo2stOBgVVBPyAsZ6l201IY+iC7R1BEr
LQ==
-----END PRIVATE KEY-----
"""

  P384PublicKeyHex =
    "04c665bba4836652858ff3ea083f5397bc8f9541cbe67e8436131491e74053d1" &
    "45fab3758706c32aba6f591bbc363ab216bad447bb815183689af6ec714d90fa" &
    "6415d7cdfc5143e7f4c3d56d5c82ade599f0058572fac22ad7376df1025ef4d" &
    "566"

  P384SpkiDerHex =
    "3076301006072a8648ce3d020106052b81040022036200" &
    P384PublicKeyHex

  P521PublicKeyHex =
    "0400b3d1009aa875877d02786b814a3f13fac8543fb5395ca1fe30e7ecdc2d" &
    "152db00444dbfc37547f021efac4961f9fcdbb426ca7e36f0171978f764f2f3" &
    "ae53f1a6b00a01d6a4e148162742d781f6d83bf17cb6aa0e2360ce146255bfb" &
    "7b7325ab358c99c0cee6d01ef3cf568dacb4e06055504fc80b19ea5db4d4863" &
    "e882ed1d4112b2d"

  P521SpkiDerHex =
    "30819b301006072a8648ce3d020106052b8104002303818600" &
    P521PublicKeyHex

  P256Pkcs8DerHex =
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b" &
    "0201010420cb7b00924ad5604dc04ce3f9e7ecbb3720b27177be8e86d78237" &
    "c3e7df90c799a1440342000489d9df7a90288502ce6e10fc1cd272673e6a7a" &
    "23bd3528c254a279ea44a7acc39706fc4a89f4066597f2e32d05ab3fd8e318" &
    "925c255b26d3eebb7ee353aea0f9"

  P256PublicKeyHex =
    "0489d9df7a90288502ce6e10fc1cd272673e6a7a23bd3528c254a279ea44a7" &
    "acc39706fc4a89f4066597f2e32d05ab3fd8e318925c255b26d3eebb7ee353" &
    "aea0f9"

  P256SpkiDerHex =
    "3059301306072a8648ce3d020106082a8648ce3d030107034200" &
    P256PublicKeyHex

  MatchingCertificateDerBase64 =
    "MIIBijCCATGgAwIBAgIUZmvOJWdaKMkR8D+/WgtZmgaoMCswCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQbWF0Y2hpbmcuZXhhbXBsZTAeFw0yNjA4MDUwNDU4MzJaFw0zNjA4MDIwNDU4MzJaMBsxGTAXBgNVBAMMEG1hdGNoaW5nLmV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASJ2d96kCiFAs5uEPwc0nJnPmp6I701KMJUonnqRKesw5cG/EqJ9AZll/LjLQWrP9jjGJJcJVsm0+67fuNTrqD5o1MwUTAdBgNVHQ4EFgQU1xZJjNfpuwgHKuNSfELaf3BbUt4wHwYDVR0jBBgwFoAU1xZJjNfpuwgHKuNSfELaf3BbUt4wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB65Cbj6KKrerIB0RvHP7JdYketWYZGmk3quqoAPI0cCwIgVpT404CCvpqkzQBygL1ZE+Ulct/sRzpSJDELpvAj2HI="

  OtherP256CertificateDerBase64 =
    "MIIBhTCCASugAwIBAgIURftoL3F8tzeGu9Gf75byVH3ZBe8wCgYIKoZIzj0EAwIwGDEWMBQGA1UEAwwNb3RoZXIuZXhhbXBsZTAeFw0yNjA4MDUwNDU4MzJaFw0zNjA4MDIwNDU4MzJaMBgxFjAUBgNVBAMMDW90aGVyLmV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATx09KA8oElZNdQp0HLwkC8t2e6i+lE7PmymdJoer0czzmC10YSC0GRmXeKV+0BgQgdp7In0QEUCp1LbI43kwW1o1MwUTAdBgNVHQ4EFgQUVCB/WyOCliPklOSjCQH4yFMQaGcwHwYDVR0jBBgwFoAUVCB/WyOCliPklOSjCQH4yFMQaGcwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBpBniUCH7da/kSMO92rt26Z1avCma3z46jZ+WvzKrkSgIhAKYVXMqOjICBbshd8xQuk1xH72OrAtdIUWeZEm0AJsKb"

  MatchingP384CertificateDerBase64 =
    "MIIB0TCCAVigAwIBAgIUeqx3HLrg07LxywTzog5A91/lexkwCgYIKoZIzj0EAwMwIDEeMBwGA1UEAwwVbWF0Y2hpbmctcDM4NC5leGFtcGxlMB4XDTI2MDgwNTA3MTkxMFoXDTM2MDgwMjA3MTkxMFowIDEeMBwGA1UEAwwVbWF0Y2hpbmctcDM4NC5leGFtcGxlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAExmW7pINmUoWP8+oIP1OXvI+VQcvmfoQ2ExSR50BT0UX6s3WHBsMqum9ZG7w2OrIWutRHu4FRg2ia9uxxTZD6ZBXXzfxRQ+f0w9VtXIKt5ZnwBYVy+sIq1zdt8QJe9NVmo1MwUTAdBgNVHQ4EFgQUJo+/TECa6e9Xa2jcMP8GgQFnfM4wHwYDVR0jBBgwFoAUJo+/TECa6e9Xa2jcMP8GgQFnfM4wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNnADBkAjBuIwWCbr/g8b20P/WYRhg9W7ePyE7p9g+swiz3hd8+XYoUAnGoKkZsbC8RqH+Gme8CMFkaEg0E5RJ77VNu5jzxAOMsVtR5UDmraVn17WP4MjsfZW1922lsjAWNa04u20yjsw=="

  OtherP384CertificateDerBase64 =
    "MIIBzTCCAVKgAwIBAgIUdA330ByP0Z8Xqm+8PSGGwehK0KYwCgYIKoZIzj0EAwMwHTEbMBkGA1UEAwwSb3RoZXItcDM4NC5leGFtcGxlMB4XDTI2MDgwNTA3MTkxMFoXDTM2MDgwMjA3MTkxMFowHTEbMBkGA1UEAwwSb3RoZXItcDM4NC5leGFtcGxlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7WOXtwrhxj8UUZvXlowaZUG4MOs7TKhCfc0Cr/DJeY+pYEIUeixQNCopAFabb17g5rSYN3neCuB0H2ugzEKy+X2bmkM37APGhvjlOGPRopYKELAuiLtwaavaCIgC+1iVo1MwUTAdBgNVHQ4EFgQUv40Gl4R4xFRCBnz+pL/p2D/2VqkwHwYDVR0jBBgwFoAUv40Gl4R4xFRCBnz+pL/p2D/2VqkwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEA9wTGhZZ2HYYOYlIoju9P47wWPMYMN2RYX/fJGe+wiH5kQ8n81b1cpmn9hxOB3v6RAjEA33b9dtzgufwN6nfIu3keegqKakdqeyQXP4sg1b51wem/zqisw2PcmmUGN4i5NeAT"

suite "external TLS EC private-key recognition":
  test "recognizes P-256 without changing the existing P-256 API":
    let parsed = parseEcPrivateKey(P256Pkcs8Pem)

    check parsed.ok
    if parsed.ok:
      check parsed.value.curve == eecP256
      check parsed.value.bits == 256
      check parsed.value.curveName in ["prime256v1", "secp256r1", "P-256"]
      check parsed.value.publicKey == bytesFromHex(P256PublicKeyHex)
      check parsed.value.publicKeySpkiDer == bytesFromHex(P256SpkiDerHex)

  test "recognizes P-384 and returns its 97-byte uncompressed public point":
    let parsed = parseEcPrivateKey(P384SupportedPkcs8Pem)

    check parsed.ok
    if parsed.ok:
      check parsed.value.curve == eecP384
      check parsed.value.bits == 384
      check parsed.value.curveName in ["secp384r1", "P-384"]
      check parsed.value.publicKey.len == 97
      check parsed.value.publicKey == bytesFromHex(P384PublicKeyHex)
      check parsed.value.publicKeySpkiDer == bytesFromHex(P384SpkiDerHex)

  test "recognizes P-521 with 66-byte coordinates":
    let parsed = parseEcPrivateKey(P521Pkcs8Pem)

    check parsed.ok
    if parsed.ok:
      check parsed.value.curve == eecP521
      check parsed.value.bits == 521
      check parsed.value.curveName in ["secp521r1", "P-521"]
      check parsed.value.publicKey.len == 133
      check parsed.value.publicKey == bytesFromHex(P521PublicKeyHex)
      check parsed.value.publicKeySpkiDer == bytesFromHex(P521SpkiDerHex)


suite "external TLS P-384 private-key preparation":
  test "parses P-384 and returns only public metadata":
    let parsed = parseP384PrivateKey(P384SupportedPkcs8Pem)

    check parsed.ok
    if parsed.ok:
      check parsed.value.bits == 384
      check parsed.value.curveName in ["secp384r1", "P-384"]
      check @(parsed.value.publicKey) == bytesFromHex(P384PublicKeyHex)
      check parsed.value.publicKeySpkiDer == bytesFromHex(P384SpkiDerHex)

  test "rejects a P-256 key through the P-384-specific API":
    let parsed = parseP384PrivateKey(P256Pkcs8Pem)

    check not parsed.ok
    if not parsed.ok:
      check parsed.error.kind == seInvalidArgument
      check parsed.error.message.contains("not a P-384 key")

  test "matches a certificate containing the P-384 private key public key":
    let matched = validateP384PrivateKeyCertificateMatch(
      P384SupportedPkcs8Pem,
      bytesFromBase64(MatchingP384CertificateDerBase64)
    )

    check matched.ok
    if matched.ok:
      check matched.value.bits == 384
      check @(matched.value.publicKey) == bytesFromHex(P384PublicKeyHex)
      check matched.value.publicKeySpkiDer == bytesFromHex(P384SpkiDerHex)

  test "rejects a certificate for a different P-384 key":
    let matched = validateP384PrivateKeyCertificateMatch(
      P384SupportedPkcs8Pem,
      bytesFromBase64(OtherP384CertificateDerBase64)
    )

    check not matched.ok
    if not matched.ok:
      check matched.error.kind == seInvalidArgument
      check matched.error.message.contains("does not match")

  test "rejects a malformed certificate":
    let matched = validateP384PrivateKeyCertificateMatch(
      P384SupportedPkcs8Pem,
      bytesFromHex("30030101ff")
    )

    check not matched.ok
    if not matched.ok:
      check matched.error.kind in {seCryptoError, seInvalidResponse}


suite "external TLS P-256 private-key parsing":
  test "parses PKCS#8 PEM and returns only public metadata":
    let parsed = parseP256PrivateKey(P256Pkcs8Pem)

    check parsed.ok
    if parsed.ok:
      check parsed.value.bits == 256
      check parsed.value.curveName in ["prime256v1", "secp256r1", "P-256"]
      check @(parsed.value.publicKey) == bytesFromHex(P256PublicKeyHex)
      check parsed.value.publicKeySpkiDer == bytesFromHex(P256SpkiDerHex)

  test "accepts type-specific SEC1 PEM for the same P-256 key":
    let parsed = parseP256PrivateKey(P256Sec1Pem)

    check parsed.ok
    if parsed.ok:
      check @(parsed.value.publicKey) == bytesFromHex(P256PublicKeyHex)
      check parsed.value.publicKeySpkiDer == bytesFromHex(P256SpkiDerHex)

  test "accepts PKCS#8 DER without a subprocess":
    let parsed = parseP256PrivateKey(bytesFromHex(P256Pkcs8DerHex))

    check parsed.ok
    if parsed.ok:
      check parsed.value.bits == 256
      check @(parsed.value.publicKey) == bytesFromHex(P256PublicKeyHex)
      check parsed.value.publicKeySpkiDer == bytesFromHex(P256SpkiDerHex)

  test "rejects an unsupported EC curve before any SE050 operation":
    let parsed = parseP256PrivateKey(P384Pkcs8Pem)

    check not parsed.ok
    if not parsed.ok:
      check parsed.error.kind == seInvalidArgument
      check parsed.error.message.contains("not a P-256 key") or
        parsed.error.message.contains("unsupported group")

  test "rejects a public-only key":
    let parsed = parseP256PrivateKey(P256PublicPem)

    check not parsed.ok
    if not parsed.ok:
      check parsed.error.kind == seInvalidArgument
      check parsed.error.message.contains("private-key validation") or
        parsed.error.message.contains("pairwise validation")

  test "rejects malformed and trailing input":
    let malformed = parseP256PrivateKey("not a private key")
    check not malformed.ok
    if not malformed.ok:
      check malformed.error.kind == seCryptoError

    let trailing = parseP256PrivateKey(P256Pkcs8Pem & "unexpected")
    check not trailing.ok
    if not trailing.ok:
      check trailing.error.kind == seInvalidResponse
      check trailing.error.message.contains("trailing")

  test "rejects an empty input":
    let parsed = parseP256PrivateKey("")

    check not parsed.ok
    if not parsed.ok:
      check parsed.error.kind == seInvalidArgument
  test "matches a certificate containing the private key public key":
    let matched = validateP256PrivateKeyCertificateMatch(
      P256Pkcs8Pem,
      bytesFromBase64(MatchingCertificateDerBase64)
    )

    check matched.ok
    if matched.ok:
      check matched.value.bits == 256
      check @(matched.value.publicKey) == bytesFromHex(P256PublicKeyHex)
      check matched.value.publicKeySpkiDer == bytesFromHex(P256SpkiDerHex)

  test "rejects a certificate for a different P-256 key":
    let matched = validateP256PrivateKeyCertificateMatch(
      P256Pkcs8Pem,
      bytesFromBase64(OtherP256CertificateDerBase64)
    )

    check not matched.ok
    if not matched.ok:
      check matched.error.kind == seInvalidArgument
      check matched.error.message.contains("does not match")

  test "rejects a malformed certificate before any SE050 operation":
    let matched = validateP256PrivateKeyCertificateMatch(
      P256Pkcs8Pem,
      bytesFromHex("30030101ff")
    )

    check not matched.ok
    if not matched.ok:
      check matched.error.kind in {seCryptoError, seInvalidResponse}

  test "end-to-end import rejects an invalid profile before transport access":
    var profile = testTlsIdentityProfile(0'u16, tisSlotA)
    profile.keyRole = "invalid-role"

    let se: Se050Transport = nil
    let imported = se.importP256TlsIdentity(
      profile,
      P256Pkcs8Pem,
      bytesFromBase64(MatchingCertificateDerBase64)
    )

    check not imported.ok
    check imported.error.kind == seInvalidArgument
    check imported.error.message == "TLS identity profile is invalid"

  test "end-to-end import rejects a mismatched certificate before transport access":
    let profile = testTlsIdentityProfile(0'u16, tisSlotA)
    let se: Se050Transport = nil
    let imported = se.importP256TlsIdentity(
      profile,
      P256Pkcs8Pem,
      bytesFromBase64(OtherP256CertificateDerBase64)
    )

    check not imported.ok
    check imported.error.kind == seInvalidArgument
    check imported.error.message.contains("does not match")

