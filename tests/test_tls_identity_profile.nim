import std/options
import std/unittest

import se050_nim

suite "SE050 TLS client identity profiles":
  test "identity 0 keeps the original fixed development objects":
    let slotA = testTlsIdentityProfile(0'u16, tisSlotA)
    let slotB = testTlsIdentityProfile(0'u16, tisSlotB)
    let compatA = testTlsIdentityProfile(tisSlotA)

    check slotA.kind == tipTest
    check slotA.name == "test"
    check slotA.identity == 0'u16
    check slotA.isDefaultIdentity()
    check slotA.slot == tisSlotA
    check slotA.slot.slotName() == "A"
    check slotA.keyRole == TlsIdentityKeyRole
    check slotA.keyObjectId == TlsIdentityTestSlotAObjectId
    check slotA.curve == ecCurveP256
    check slotA.expectedKeyType() == Se050TypeEcKeyPairNistP256
    check slotA.isDeletable()
    check not slotA.isProduction()
    check slotA.isValid()
    check compatA.keyObjectId == slotA.keyObjectId

    check slotB.identity == 0'u16
    check slotB.slot == tisSlotB
    check slotB.slot.slotName() == "B"
    check slotB.keyObjectId == TlsIdentityTestSlotBObjectId
    check slotB.isValid()

  test "identity 0 keeps the original fixed customer objects":
    let slotA = productionTlsIdentityProfile(0'u16, tisSlotA)
    let slotB = productionTlsIdentityProfile(0'u16, tisSlotB)
    let compatA = productionTlsIdentityProfile(tisSlotA)

    check slotA.kind == tipProduction
    check slotA.name == "production"
    check slotA.identity == 0'u16
    check slotA.slot == tisSlotA
    check slotA.keyRole == TlsIdentityKeyRole
    check slotA.keyObjectId == TlsIdentityProductionSlotAObjectId
    check slotA.curve == ecCurveP256
    check slotA.expectedKeyType() == Se050TypeEcKeyPairNistP256
    check slotA.isDeletable()
    check slotA.isProduction()
    check slotA.isValid()
    check compatA.keyObjectId == slotA.keyObjectId

    check slotB.identity == 0'u16
    check slotB.slot == tisSlotB
    check slotB.keyObjectId == TlsIdentityProductionSlotBObjectId
    check slotB.isDeletable()
    check slotB.isValid()

  test "identity 1 uses the next A/B pair":
    let testA = testTlsIdentityProfile(1'u16, tisSlotA)
    let testB = testTlsIdentityProfile(1'u16, tisSlotB)
    let prodA = productionTlsIdentityProfile(1'u16, tisSlotA)
    let prodB = productionTlsIdentityProfile(1'u16, tisSlotB)

    check testA.identity == 1'u16
    check testA.keyObjectId == 0x30000202'u32
    check testB.keyObjectId == 0x30000203'u32
    check prodA.keyObjectId == 0x20000202'u32
    check prodB.keyObjectId == 0x20000203'u32
    check testB.keyObjectId == testA.keyObjectId + 1'u32
    check prodB.keyObjectId == prodA.keyObjectId + 1'u32

  test "TLS policy is SIGN plus READ plus DELETE for every slot":
    let profiles = [
      testTlsIdentityProfile(0'u16, tisSlotA),
      testTlsIdentityProfile(2'u16, tisSlotB),
      productionTlsIdentityProfile(0'u16, tisSlotA),
      productionTlsIdentityProfile(2'u16, tisSlotB)
    ]

    for profile in profiles:
      check policyHeader(profile.keyPolicy()) == TlsIdentityPolicyHeader
      check policyHeader(profile.keyPolicy()) == 0x10240000'u32

  test "test and production keep matching area-relative indices across identities":
    let testA = testTlsIdentityProfile(5'u16, tisSlotA)
    let testB = testTlsIdentityProfile(5'u16, tisSlotB)
    let prodA = productionTlsIdentityProfile(5'u16, tisSlotA)
    let prodB = productionTlsIdentityProfile(5'u16, tisSlotB)

    check (testA.keyObjectId and 0x0000FFFF'u32) == (prodA.keyObjectId and 0x0000FFFF'u32)
    check (testB.keyObjectId and 0x0000FFFF'u32) == (prodB.keyObjectId and 0x0000FFFF'u32)
    check testA.keyObjectId == 0x3000020A'u32
    check testB.keyObjectId == 0x3000020B'u32

  test "TLS identity objects do not collide with firmware KEX objects":
    let profiles = [
      testTlsIdentityProfile(0'u16, tisSlotA),
      testTlsIdentityProfile(0'u16, tisSlotB),
      testTlsIdentityProfile(1'u16, tisSlotA),
      testTlsIdentityProfile(1'u16, tisSlotB),
      productionTlsIdentityProfile(0'u16, tisSlotA),
      productionTlsIdentityProfile(0'u16, tisSlotB)
    ]

    for profile in profiles:
      check profile.keyObjectId != KittingTestFirmwareKexObjectId
      check profile.keyObjectId != KittingProductionFirmwareKexObjectId

  test "resolves profiles from fixed identity object IDs":
    let testA = tlsIdentityProfileForObjectId(0x30000200'u32)
    check testA.isSome
    check testA.get().kind == tipTest
    check testA.get().identity == 0'u16
    check testA.get().slot == tisSlotA

    let testB1 = tlsIdentityProfileForObjectId(0x30000203'u32)
    check testB1.isSome
    check testB1.get().kind == tipTest
    check testB1.get().identity == 1'u16
    check testB1.get().slot == tisSlotB

    let productionA1 = tlsIdentityProfileForObjectId(0x20000202'u32)
    check productionA1.isSome
    check productionA1.get().kind == tipProduction
    check productionA1.get().identity == 1'u16
    check productionA1.get().slot == tisSlotA

    check tlsIdentityProfileForObjectId(0x300001FF'u32).isNone
    check tlsIdentityProfileForObjectId(0x10000200'u32).isNone

  test "invalid identities are rejected":
    check isValidIdentity(0'u16)
    check isValidIdentity(1'u16)

    var profile = testTlsIdentityProfile(0'u16, tisSlotA)
    profile.identity = TlsIdentityMaxIdentity + 1'u16
    check not profile.isValid()

  test "mutated fixed profiles are rejected":
    var profile = testTlsIdentityProfile(2'u16, tisSlotA)
    profile.keyObjectId = testTlsIdentityProfile(2'u16, tisSlotB).keyObjectId
    check not profile.isValid()

    profile = productionTlsIdentityProfile(1'u16, tisSlotA)
    profile.name = "test"
    check not profile.isValid()

    profile = productionTlsIdentityProfile(1'u16, tisSlotB)
    profile.curve = ecCurveX25519
    check not profile.isValid()
