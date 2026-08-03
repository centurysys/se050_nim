import std/options
import std/unittest

import se050_nim

suite "SE050 TLS client identity profiles":
  test "test slots use the fixed development objects":
    let slotA = testTlsIdentityProfile(tisSlotA)
    let slotB = testTlsIdentityProfile(tisSlotB)

    check slotA.kind == tipTest
    check slotA.name == "test"
    check slotA.slot == tisSlotA
    check slotA.slot.slotName() == "A"
    check slotA.keyRole == TlsIdentityKeyRole
    check slotA.keyObjectId == TlsIdentityTestSlotAObjectId
    check slotA.curve == ecCurveP256
    check slotA.expectedKeyType() == Se050TypeEcKeyPairNistP256
    check slotA.isDeletable()
    check not slotA.isProduction()
    check slotA.isValid()

    check slotB.kind == tipTest
    check slotB.slot == tisSlotB
    check slotB.slot.slotName() == "B"
    check slotB.keyObjectId == TlsIdentityTestSlotBObjectId
    check slotB.isValid()

  test "production slots use the fixed customer objects":
    let slotA = productionTlsIdentityProfile(tisSlotA)
    let slotB = productionTlsIdentityProfile(tisSlotB)

    check slotA.kind == tipProduction
    check slotA.name == "production"
    check slotA.slot == tisSlotA
    check slotA.keyRole == TlsIdentityKeyRole
    check slotA.keyObjectId == TlsIdentityProductionSlotAObjectId
    check slotA.curve == ecCurveP256
    check slotA.expectedKeyType() == Se050TypeEcKeyPairNistP256
    check slotA.isDeletable()
    check slotA.isProduction()
    check slotA.isValid()

    check slotB.kind == tipProduction
    check slotB.slot == tisSlotB
    check slotB.keyObjectId == TlsIdentityProductionSlotBObjectId
    check slotB.isDeletable()
    check slotB.isValid()

  test "TLS policy is SIGN plus READ plus DELETE for every slot":
    let profiles = [
      testTlsIdentityProfile(tisSlotA),
      testTlsIdentityProfile(tisSlotB),
      productionTlsIdentityProfile(tisSlotA),
      productionTlsIdentityProfile(tisSlotB)
    ]

    for profile in profiles:
      check policyHeader(profile.keyPolicy()) == TlsIdentityPolicyHeader
      check policyHeader(profile.keyPolicy()) == 0x10240000'u32

  test "test and production keep matching area-relative A/B indices":
    check (
      TlsIdentityTestSlotAObjectId and 0x0000FFFF'u32
    ) == (
      TlsIdentityProductionSlotAObjectId and 0x0000FFFF'u32
    )
    check (
      TlsIdentityTestSlotBObjectId and 0x0000FFFF'u32
    ) == (
      TlsIdentityProductionSlotBObjectId and 0x0000FFFF'u32
    )

    check TlsIdentityTestSlotBObjectId == TlsIdentityTestSlotAObjectId + 1'u32
    check (
      TlsIdentityProductionSlotBObjectId ==
      TlsIdentityProductionSlotAObjectId + 1'u32
    )

  test "TLS identity objects do not collide with firmware KEX objects":
    check TlsIdentityTestSlotAObjectId != KittingTestFirmwareKexObjectId
    check TlsIdentityTestSlotBObjectId != KittingTestFirmwareKexObjectId
    check (
      TlsIdentityProductionSlotAObjectId !=
      KittingProductionFirmwareKexObjectId
    )
    check (
      TlsIdentityProductionSlotBObjectId !=
      KittingProductionFirmwareKexObjectId
    )

  test "resolves every fixed profile from its object ID":
    let testA = tlsIdentityProfileForObjectId(TlsIdentityTestSlotAObjectId)
    check testA.isSome
    check testA.get().kind == tipTest
    check testA.get().slot == tisSlotA

    let testB = tlsIdentityProfileForObjectId(TlsIdentityTestSlotBObjectId)
    check testB.isSome
    check testB.get().kind == tipTest
    check testB.get().slot == tisSlotB

    let productionA = tlsIdentityProfileForObjectId(
      TlsIdentityProductionSlotAObjectId
    )
    check productionA.isSome
    check productionA.get().kind == tipProduction
    check productionA.get().slot == tisSlotA

    let productionB = tlsIdentityProfileForObjectId(
      TlsIdentityProductionSlotBObjectId
    )
    check productionB.isSome
    check productionB.get().kind == tipProduction
    check productionB.get().slot == tisSlotB

    check tlsIdentityProfileForObjectId(0x30000202'u32).isNone

  test "mutated fixed profiles are rejected":
    var profile = testTlsIdentityProfile(tisSlotA)

    profile.keyObjectId = TlsIdentityTestSlotBObjectId
    check not profile.isValid()

    profile = productionTlsIdentityProfile(tisSlotA)
    profile.name = "test"
    check not profile.isValid()

    profile = productionTlsIdentityProfile(tisSlotB)
    profile.curve = ecCurveX25519
    check not profile.isValid()
