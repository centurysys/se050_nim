import std/unittest

import se050_nim

suite "SE050 TLS identity OpenSSL Provider references":
  test "identity 0 keeps the expected provider URIs":
    check opensslProviderKeyUri(
      testTlsIdentityProfile(0'u16, tisSlotA)
    ) == "nxp:0x30000200"
    check opensslProviderKeyUri(
      testTlsIdentityProfile(0'u16, tisSlotB)
    ) == "nxp:0x30000201"
    check opensslProviderKeyUri(
      productionTlsIdentityProfile(0'u16, tisSlotA)
    ) == "nxp:0x20000200"
    check opensslProviderKeyUri(
      productionTlsIdentityProfile(0'u16, tisSlotB)
    ) == "nxp:0x20000201"

  test "identity-numbered slots map directly to NXP provider key IDs":
    check opensslProviderKeyUri(
      testTlsIdentityProfile(1'u16, tisSlotA)
    ) == "nxp:0x30000202"
    check opensslProviderKeyUri(
      testTlsIdentityProfile(1'u16, tisSlotB)
    ) == "nxp:0x30000203"
    check opensslProviderKeyUri(
      productionTlsIdentityProfile(7'u16, tisSlotA)
    ) == "nxp:0x2000020E"
    check opensslProviderKeyUri(
      productionTlsIdentityProfile(7'u16, tisSlotB)
    ) == "nxp:0x2000020F"

  test "raw object IDs use an uppercase eight-digit hex URI":
    check opensslProviderKeyUri(0x12345678'u32) == "nxp:0x12345678"
    check opensslProviderKeyUri(0x00000001'u32) == "nxp:0x00000001"

  test "mutated TLS identity profiles are rejected":
    var profile = testTlsIdentityProfile(1'u16, tisSlotA)
    profile.keyObjectId = 0x30000203'u32

    expect ValueError:
      discard opensslProviderKeyUri(profile)

  test "wraps an uncompressed P-256 public key as SubjectPublicKeyInfo DER":
    var raw = @[0x04'u8]
    for i in 0 ..< 64:
      raw.add(uint8(i))

    let der = p256PublicKeyToSpkiDer(raw)
    check der.len == 91
    check der[0] == 0x30'u8
    check der[1] == 0x59'u8
    check der[23] == 0x03'u8
    check der[24] == 0x42'u8
    check der[25] == 0x00'u8
    check der[26 .. ^1] == raw

  test "rejects invalid P-256 public key encodings":
    expect ValueError:
      discard p256PublicKeyToSpkiDer(newSeq[uint8](64))

    var compressed = newSeq[uint8](65)
    compressed[0] = 0x02'u8
    expect ValueError:
      discard p256PublicKeyToSpkiDer(compressed)


  test "wraps an uncompressed P-384 public key as SubjectPublicKeyInfo DER":
    var raw = @[0x04'u8]
    for i in 0 ..< 96:
      raw.add(uint8(i))

    let der = p384PublicKeyToSpkiDer(raw)
    check der.len == 120
    check der[0] == 0x30'u8
    check der[1] == 0x76'u8
    check der[2 .. 3] == @[0x30'u8, 0x10'u8]
    check der[13 .. 19] == @[
      0x06'u8, 0x05'u8, 0x2B'u8, 0x81'u8, 0x04'u8, 0x00'u8, 0x22'u8
    ]
    check der[20 .. 22] == @[0x03'u8, 0x62'u8, 0x00'u8]
    check der[23 .. ^1] == raw

  test "rejects invalid P-384 public key encodings":
    expect ValueError:
      discard p384PublicKeyToSpkiDer(newSeq[uint8](96))

    var compressed = newSeq[uint8](97)
    compressed[0] = 0x03'u8
    expect ValueError:
      discard p384PublicKeyToSpkiDer(compressed)

  test "dispatches managed TLS public-key SPKI conversion by curve":
    var p256 = newSeq[uint8](65)
    p256[0] = 0x04'u8
    check ecPublicKeyToSpkiDer(ecCurveP256, p256) ==
      p256PublicKeyToSpkiDer(p256)

    var p384 = newSeq[uint8](97)
    p384[0] = 0x04'u8
    check ecPublicKeyToSpkiDer(ecCurveP384, p384) ==
      p384PublicKeyToSpkiDer(p384)
