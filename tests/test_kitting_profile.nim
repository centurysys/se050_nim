import std/unittest

import se050_nim

suite "SE050 kitting profiles":
  test "test profile uses the disposable development object":
    let profile = testKittingProfile()

    check profile.kind == kpTest
    check profile.name == "test"
    check profile.keyRole == KittingKeyRoleFirmwareKex
    check profile.keyObjectId == KittingTestFirmwareKexObjectId
    check profile.curve == ecCurveP256
    check profile.expectedKeyType() == Se050TypeEcKeyPairNistP256
    check profile.isDeletable()
    check not profile.isProduction()
    check profile.isValid()

  test "production profile uses the customer object":
    let profile = productionKittingProfile()

    check profile.kind == kpProduction
    check profile.name == "production"
    check profile.keyRole == KittingKeyRoleFirmwareKex
    check profile.keyObjectId == KittingProductionFirmwareKexObjectId
    check profile.curve == ecCurveP256
    check profile.expectedKeyType() == Se050TypeEcKeyPairNistP256
    check not profile.isDeletable()
    check profile.isProduction()
    check profile.isValid()

  test "test policy differs from production only by delete permission":
    let testHeader = policyHeader(testKittingProfile().keyPolicy())
    let productionHeader = policyHeader(productionKittingProfile().keyPolicy())

    check testHeader != productionHeader
    check (testHeader xor productionHeader) == 0x00040000'u32
    check productionHeader == policyHeader(oneTimeDeviceKeyPolicy())

  test "profile constants match the intended platform objects":
    check BoardSerialNumberPath == "/proc/device-tree/board/serialno"
    check Se050AttestationKeyObjectId == 0xF0000012'u32
    check Se050AttestationCertificateObjectId == 0xF0000013'u32
    check KittingCsvFormatVersion == 1'u16
    check KittingFreshnessLength == 16
    check KittingAppletMajor == 7'u8
    check KittingAppletMinor == 2'u8

  test "invalid profile mutations are rejected":
    var profile = testKittingProfile()

    profile.keyObjectId = KittingProductionFirmwareKexObjectId
    check not profile.isValid()

    profile = productionKittingProfile()
    profile.name = "test"
    check not profile.isValid()
