# =============================================================================
# SE050 TLS client identity profile
# =============================================================================
#
# Product-level constants for reusable X.509/mTLS client identity keys.
# Cloud-specific settings such as AWS IoT Thing names, Azure IoT Hub device
# identities, endpoints, MQTT topics, and certificate enrollment are
# intentionally outside this module.
#
# TLS identity keys differ from the firmware KEX production key in lifecycle:
# certificates and their signing keys must be rotatable. Production TLS keys
# therefore retain DELETE permission and use explicit A/B slots.

import std/options

import ./keys

# =============================================================================
# Constants
# =============================================================================

const
  TlsIdentityKeyRole* = "tls-client-identity"

  # Keep the same area-relative indices for test and production. The area byte
  # selects the lifecycle domain while 0x0200/0x0201 identify TLS slots A/B.
  TlsIdentityTestSlotAObjectId* = 0x30000200'u32
  TlsIdentityTestSlotBObjectId* = 0x30000201'u32
  TlsIdentityProductionSlotAObjectId* = 0x20000200'u32
  TlsIdentityProductionSlotBObjectId* = 0x20000201'u32

  # Minimal permissions for a rotatable TLS client signing key:
  #   SIGN   0x10000000
  #   READ   0x00200000  (public-key read)
  #   DELETE 0x00040000  (A/B certificate/key rotation)
  #
  # WRITE and GEN are deliberately absent so an existing identity key cannot
  # be silently overwritten or regenerated in place.
  TlsIdentityPolicyHeader* = 0x10240000'u32

  DevelopmentObjectStart = 0x30000000'u32
  DevelopmentObjectEnd = 0x3000FFFF'u32
  CustomerObjectStart = 0x20000000'u32
  CustomerObjectEnd = 0x2000FFFF'u32

# =============================================================================
# Types
# =============================================================================

type
  TlsIdentityProfileKind* = enum
    tipTest,
    tipProduction

  TlsIdentitySlot* = enum
    tisSlotA,
    tisSlotB

  TlsIdentityProfile* = object
    ## Fixed settings for one TLS client identity slot.
    kind*: TlsIdentityProfileKind
    name*: string
    slot*: TlsIdentitySlot
    keyRole*: string
    keyObjectId*: uint32
    curve*: EcCurveKind

# =============================================================================
# Internal helpers
# =============================================================================

proc objectIdFor(kind: TlsIdentityProfileKind, slot: TlsIdentitySlot): uint32 =
  case kind
  of tipTest:
    case slot
    of tisSlotA:
      result = TlsIdentityTestSlotAObjectId
    of tisSlotB:
      result = TlsIdentityTestSlotBObjectId
  of tipProduction:
    case slot
    of tisSlotA:
      result = TlsIdentityProductionSlotAObjectId
    of tisSlotB:
      result = TlsIdentityProductionSlotBObjectId

# =============================================================================
# Public API
# =============================================================================

proc slotName*(slot: TlsIdentitySlot): string =
  case slot
  of tisSlotA:
    result = "A"
  of tisSlotB:
    result = "B"

proc tlsIdentityProfile*(
    kind: TlsIdentityProfileKind,
    slot: TlsIdentitySlot
): TlsIdentityProfile =
  ## Returns the fixed TLS client identity profile for one A/B slot.
  result = TlsIdentityProfile(
    kind: kind,
    name: (if kind == tipTest: "test" else: "production"),
    slot: slot,
    keyRole: TlsIdentityKeyRole,
    keyObjectId: objectIdFor(kind, slot),
    curve: ecCurveP256
  )

proc testTlsIdentityProfile*(slot: TlsIdentitySlot): TlsIdentityProfile =
  ## Returns a disposable development-area TLS identity profile.
  result = tlsIdentityProfile(tipTest, slot)

proc productionTlsIdentityProfile*(slot: TlsIdentitySlot): TlsIdentityProfile =
  ## Returns a customer-area TLS identity profile intended for production use.
  result = tlsIdentityProfile(tipProduction, slot)

proc tlsIdentityProfileForObjectId*(
    objectId: uint32
): Option[TlsIdentityProfile] =
  ## Resolves one of the four fixed TLS identity profiles by Secure Object ID.
  case objectId
  of TlsIdentityTestSlotAObjectId:
    result = some(testTlsIdentityProfile(tisSlotA))
  of TlsIdentityTestSlotBObjectId:
    result = some(testTlsIdentityProfile(tisSlotB))
  of TlsIdentityProductionSlotAObjectId:
    result = some(productionTlsIdentityProfile(tisSlotA))
  of TlsIdentityProductionSlotBObjectId:
    result = some(productionTlsIdentityProfile(tisSlotB))
  else:
    result = none(TlsIdentityProfile)

proc isProduction*(profile: TlsIdentityProfile): bool =
  result = profile.kind == tipProduction

proc isDeletable*(profile: TlsIdentityProfile): bool =
  ## TLS identity keys are intentionally rotatable in both profiles.
  result = true

proc keyPolicy*(profile: TlsIdentityProfile): EcKeyPolicy =
  ## Returns the minimum policy required by a rotatable TLS client key.
  ##
  ## The profile argument records lifecycle intent even though test and
  ## production currently use the same signed policy semantics.
  discard profile
  result = customEcKeyPolicy(TlsIdentityPolicyHeader)

proc expectedKeyType*(profile: TlsIdentityProfile): uint8 =
  ## Returns the SecureObjectType expected after P-256 key generation.
  result = expectedKeyPairType(profile.curve)

proc isValid*(profile: TlsIdentityProfile): bool =
  ## Checks all fixed invariants before a profile is used for provisioning.
  if profile.keyRole != TlsIdentityKeyRole:
    return false

  if profile.curve != ecCurveP256:
    return false

  if profile.keyObjectId != objectIdFor(profile.kind, profile.slot):
    return false

  case profile.kind
  of tipTest:
    result =
      profile.name == "test" and
      profile.keyObjectId >= DevelopmentObjectStart and
      profile.keyObjectId <= DevelopmentObjectEnd
  of tipProduction:
    result =
      profile.name == "production" and
      profile.keyObjectId >= CustomerObjectStart and
      profile.keyObjectId <= CustomerObjectEnd

static:
  doAssert TlsIdentityTestSlotAObjectId >= DevelopmentObjectStart
  doAssert TlsIdentityTestSlotAObjectId <= DevelopmentObjectEnd
  doAssert TlsIdentityTestSlotBObjectId >= DevelopmentObjectStart
  doAssert TlsIdentityTestSlotBObjectId <= DevelopmentObjectEnd
  doAssert TlsIdentityProductionSlotAObjectId >= CustomerObjectStart
  doAssert TlsIdentityProductionSlotAObjectId <= CustomerObjectEnd
  doAssert TlsIdentityProductionSlotBObjectId >= CustomerObjectStart
  doAssert TlsIdentityProductionSlotBObjectId <= CustomerObjectEnd
  doAssert (
    (TlsIdentityTestSlotAObjectId and 0x0000FFFF'u32) ==
    (TlsIdentityProductionSlotAObjectId and 0x0000FFFF'u32)
  )
  doAssert (
    (TlsIdentityTestSlotBObjectId and 0x0000FFFF'u32) ==
    (TlsIdentityProductionSlotBObjectId and 0x0000FFFF'u32)
  )
  doAssert TlsIdentityTestSlotBObjectId == TlsIdentityTestSlotAObjectId + 1'u32
  doAssert (
    TlsIdentityProductionSlotBObjectId ==
    TlsIdentityProductionSlotAObjectId + 1'u32
  )
