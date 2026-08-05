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
      check parsed.error.message.contains("256-bit P-256") or
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

