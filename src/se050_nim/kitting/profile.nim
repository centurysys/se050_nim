# =============================================================================
# SE050 kitting profile
# =============================================================================
#
# Product-level constants shared by the factory kitting exporter and the
# verification path. Keeping these values in one module prevents the test and
# production tools from silently drifting to different object IDs or policies.
#
# This module defines only the fixed firmware key-agreement profile values.
# Attestation, certificate validation, kitting records, CSV handling, and local
# verification are implemented by sibling modules. Firmware envelope handling
# remains a higher-layer responsibility.

import std/options

import ../keys

# =============================================================================
# Constants
# =============================================================================

const
  BoardSerialNumberPath* = "/proc/device-tree/board/serialno"

  KittingCsvFormatVersion* = 1'u16
  KittingKeyRoleFirmwareKex* = "firmware-kex"
  KittingFreshnessLength* = 16
  KittingNonceLength* = 16

  # The target applet currently used by Athena is 7.2.0. The exact
  # Read-with-Attestation APDU encoding is added only after it is verified
  # against this applet generation.
  KittingAppletMajor* = 7'u8
  KittingAppletMinor* = 2'u8

  # Keep the same area-relative index for test and production. This makes the
  # selected profile visible in the high byte while preserving the logical key
  # assignment documented by the project.
  KittingTestFirmwareKexObjectId* = 0x30000100'u32
  KittingProductionFirmwareKexObjectId* = 0x20000100'u32

  DevelopmentObjectStart = 0x30000000'u32
  DevelopmentObjectEnd = 0x3000FFFF'u32
  CustomerObjectStart = 0x20000000'u32
  CustomerObjectEnd = 0x2000FFFF'u32

# =============================================================================
# Types
# =============================================================================

type
  KittingProfileKind* = enum
    kpTest,
    kpProduction

  KittingProfile* = object
    ## Fixed settings for one factory kitting mode.
    kind*: KittingProfileKind
    name*: string
    keyRole*: string
    keyObjectId*: uint32
    curve*: EcCurveKind

# =============================================================================
# Public API
# =============================================================================

proc kittingProfile*(kind: KittingProfileKind): KittingProfile =
  ## Returns the fixed profile for test or production provisioning.
  case kind
  of kpTest:
    result = KittingProfile(
      kind: kpTest,
      name: "test",
      keyRole: KittingKeyRoleFirmwareKex,
      keyObjectId: KittingTestFirmwareKexObjectId,
      curve: ecCurveP256
    )
  of kpProduction:
    result = KittingProfile(
      kind: kpProduction,
      name: "production",
      keyRole: KittingKeyRoleFirmwareKex,
      keyObjectId: KittingProductionFirmwareKexObjectId,
      curve: ecCurveP256
    )

proc testKittingProfile*(): KittingProfile =
  ## Returns the repeatable development profile.
  result = kittingProfile(kpTest)

proc productionKittingProfile*(): KittingProfile =
  ## Returns the one-time factory production profile.
  result = kittingProfile(kpProduction)

proc kittingProfileForName*(name: string): Option[KittingProfile] =
  ## Resolves one of the fixed kitting profiles from its CSV name.
  case name
  of "test":
    result = some(testKittingProfile())
  of "production":
    result = some(productionKittingProfile())
  else:
    result = none(KittingProfile)

proc kittingProfileForObjectId*(objectId: uint32): Option[KittingProfile] =
  ## Resolves one of the fixed kitting profiles from its Secure Object ID.
  if objectId == KittingTestFirmwareKexObjectId:
    return some(testKittingProfile())

  if objectId == KittingProductionFirmwareKexObjectId:
    return some(productionKittingProfile())

  result = none(KittingProfile)

proc isProduction*(profile: KittingProfile): bool =
  result = profile.kind == kpProduction

proc isDeletable*(profile: KittingProfile): bool =
  ## Reports the intended lifecycle of the generated key object.
  result = profile.kind == kpTest

proc keyPolicy*(profile: KittingProfile): EcKeyPolicy =
  ## Returns the key policy associated with the selected profile.
  case profile.kind
  of kpTest:
    result = testDeviceKeyPolicy()
  of kpProduction:
    result = oneTimeDeviceKeyPolicy()

proc expectedKeyType*(profile: KittingProfile): uint8 =
  ## Returns the SecureObjectType expected after key generation.
  result = expectedKeyPairType(profile.curve)

proc isValid*(profile: KittingProfile): bool =
  ## Checks invariants that must hold before a profile is used for provisioning.
  if profile.keyRole != KittingKeyRoleFirmwareKex:
    return false

  if profile.curve != ecCurveP256:
    return false

  case profile.kind
  of kpTest:
    result =
      profile.name == "test" and
      profile.keyObjectId >= DevelopmentObjectStart and
      profile.keyObjectId <= DevelopmentObjectEnd
  of kpProduction:
    result =
      profile.name == "production" and
      profile.keyObjectId >= CustomerObjectStart and
      profile.keyObjectId <= CustomerObjectEnd

static:
  doAssert KittingFreshnessLength == 16
  doAssert KittingNonceLength == 16
  doAssert KittingTestFirmwareKexObjectId >= DevelopmentObjectStart
  doAssert KittingTestFirmwareKexObjectId <= DevelopmentObjectEnd
  doAssert KittingProductionFirmwareKexObjectId >= CustomerObjectStart
  doAssert KittingProductionFirmwareKexObjectId <= CustomerObjectEnd
  doAssert (
    (KittingTestFirmwareKexObjectId and 0x0000FFFF'u32) ==
    (KittingProductionFirmwareKexObjectId and 0x0000FFFF'u32)
  )
