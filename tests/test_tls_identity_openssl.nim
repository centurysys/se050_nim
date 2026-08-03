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
