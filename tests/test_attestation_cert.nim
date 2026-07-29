import std/unittest

import se050_nim

suite "SE050 attestation certificate DER validation":
  test "accepts one complete short DER sequence":
    let certificate = @[
      0x30'u8, 0x03'u8,
      0x02'u8, 0x01'u8, 0x01'u8
    ]

    let validated = validateAttestationCertificateDer(certificate)

    check validated.ok

  test "accepts an extended DER sequence length":
    var certificate = @[0x30'u8, 0x81'u8, 0x80'u8]
    for _ in 0 ..< 128:
      certificate.add(0x00'u8)

    let validated = validateAttestationCertificateDer(certificate)

    check validated.ok

  test "rejects a non-sequence value":
    let certificate = @[0x31'u8, 0x00'u8]

    let validated = validateAttestationCertificateDer(certificate)

    check not validated.ok
    check validated.error.kind == seInvalidResponse

  test "rejects a truncated DER sequence":
    let certificate = @[
      0x30'u8, 0x03'u8,
      0x02'u8, 0x01'u8
    ]

    let validated = validateAttestationCertificateDer(certificate)

    check not validated.ok
    check validated.error.kind == seInvalidResponse

  test "rejects bytes after the DER sequence":
    let certificate = @[
      0x30'u8, 0x03'u8,
      0x02'u8, 0x01'u8, 0x01'u8,
      0x00'u8
    ]

    let validated = validateAttestationCertificateDer(certificate)

    check not validated.ok
    check validated.error.kind == seInvalidResponse
