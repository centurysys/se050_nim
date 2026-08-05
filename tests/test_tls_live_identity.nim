import std/unittest

import se050_nim

suite "SE050 TLS live identity validation":
  test "rejects an invalid profile before accessing the transport":
    var profile = testTlsIdentityProfile(0'u16, tisSlotA)
    profile.keyRole = "invalid-role"

    let se: Se050Transport = nil
    let inspected = se.inspectTlsIdentity(profile)

    check not inspected.ok
    check inspected.error.kind == seInvalidArgument
    check inspected.error.message == "TLS identity profile is invalid"

  test "imported validation rejects an invalid profile before accessing transport":
    var profile = testTlsIdentityProfile(0'u16, tisSlotA)
    profile.keyRole = "invalid-role"

    let se: Se050Transport = nil
    let inspected = se.inspectImportedTlsIdentity(profile)

    check not inspected.ok
    check inspected.error.kind == seInvalidArgument
    check inspected.error.message == "TLS identity profile is invalid"

