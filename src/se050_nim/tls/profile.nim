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
# therefore retain DELETE permission and use explicit per-identity A/B slots.

import std/options

import ../keys

# =============================================================================
# Constants
# =============================================================================

const
  TlsIdentityKeyRole* = "tls-client-identity"

  TlsIdentityDefaultIdentity* = 0'u16
  TlsIdentityRelativeIndexBase* = 0x0200'u32
  TlsIdentitySlotStride* = 2'u32

  DevelopmentObjectStart = 0x30000000'u32
  DevelopmentObjectEnd = 0x3000FFFF'u32
  CustomerObjectStart = 0x20000000'u32
  CustomerObjectEnd = 0x2000FFFF'u32

  TlsIdentityTestAreaBaseObjectId* = DevelopmentObjectStart
  TlsIdentityProductionAreaBaseObjectId* = CustomerObjectStart

  TlsIdentityMaxIdentity* =
    uint16((0x0000FFFF'u32 - TlsIdentityRelativeIndexBase) div TlsIdentitySlotStride)

  # Compatibility aliases for identity 0.
  TlsIdentityTestSlotAObjectId* =
    TlsIdentityTestAreaBaseObjectId + TlsIdentityRelativeIndexBase
  TlsIdentityTestSlotBObjectId* =
    TlsIdentityTestAreaBaseObjectId + TlsIdentityRelativeIndexBase + 1'u32
  TlsIdentityProductionSlotAObjectId* =
    TlsIdentityProductionAreaBaseObjectId + TlsIdentityRelativeIndexBase
  TlsIdentityProductionSlotBObjectId* =
    TlsIdentityProductionAreaBaseObjectId + TlsIdentityRelativeIndexBase + 1'u32

  # Minimal permissions for a rotatable TLS client signing key:
  #   SIGN   0x10000000
  #   READ   0x00200000  (public-key read)
  #   DELETE 0x00040000  (A/B certificate/key rotation)
  #
  # WRITE and GEN are deliberately absent so an existing identity key cannot
  # be silently overwritten or regenerated in place.
  TlsIdentityPolicyHeader* = 0x10240000'u32

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
    identity*: uint16
    slot*: TlsIdentitySlot
    keyRole*: string
    keyObjectId*: uint32
    curve*: EcCurveKind

# =============================================================================
# Internal helpers
# =============================================================================

proc slotOffset(slot: TlsIdentitySlot): uint32 =
  case slot
  of tisSlotA:
    result = 0'u32
  of tisSlotB:
    result = 1'u32

proc areaBaseObjectId(kind: TlsIdentityProfileKind): uint32 =
  case kind
  of tipTest:
    result = TlsIdentityTestAreaBaseObjectId
  of tipProduction:
    result = TlsIdentityProductionAreaBaseObjectId

proc isValidIdentity*(identity: uint16): bool =
  result = identity <= TlsIdentityMaxIdentity

proc objectIdFor*(
    kind: TlsIdentityProfileKind,
    identity: uint16,
    slot: TlsIdentitySlot
): uint32 =
  result =
    areaBaseObjectId(kind) +
    TlsIdentityRelativeIndexBase +
    uint32(identity) * TlsIdentitySlotStride +
    slot.slotOffset()

# =============================================================================
# Public API
# =============================================================================

proc slotName*(slot: TlsIdentitySlot): string =
  case slot
  of tisSlotA:
    result = "A"
  of tisSlotB:
    result = "B"

proc identityName*(identity: uint16): string =
  result = $identity

proc tlsIdentityProfile*(
    kind: TlsIdentityProfileKind,
    identity: uint16,
    slot: TlsIdentitySlot
): TlsIdentityProfile =
  ## Returns the fixed TLS client identity profile for one identity/slot pair.
  result = TlsIdentityProfile(
    kind: kind,
    name: (if kind == tipTest: "test" else: "production"),
    identity: identity,
    slot: slot,
    keyRole: TlsIdentityKeyRole,
    keyObjectId: objectIdFor(kind, identity, slot),
    curve: ecCurveP256
  )

proc tlsIdentityProfile*(
    kind: TlsIdentityProfileKind,
    slot: TlsIdentitySlot
): TlsIdentityProfile =
  ## Compatibility overload: identity 0.
  result = tlsIdentityProfile(kind, TlsIdentityDefaultIdentity, slot)

proc testTlsIdentityProfile*(identity: uint16, slot: TlsIdentitySlot): TlsIdentityProfile =
  ## Returns a disposable development-area TLS identity profile.
  result = tlsIdentityProfile(tipTest, identity, slot)

proc testTlsIdentityProfile*(slot: TlsIdentitySlot): TlsIdentityProfile =
  ## Compatibility overload: identity 0.
  result = testTlsIdentityProfile(TlsIdentityDefaultIdentity, slot)

proc productionTlsIdentityProfile*(identity: uint16, slot: TlsIdentitySlot): TlsIdentityProfile =
  ## Returns a customer-area TLS identity profile intended for production use.
  result = tlsIdentityProfile(tipProduction, identity, slot)

proc productionTlsIdentityProfile*(slot: TlsIdentitySlot): TlsIdentityProfile =
  ## Compatibility overload: identity 0.
  result = productionTlsIdentityProfile(TlsIdentityDefaultIdentity, slot)

proc isValid*(profile: TlsIdentityProfile): bool =
  ## Checks all fixed invariants before a profile is used for provisioning.
  if profile.keyRole != TlsIdentityKeyRole:
    return false

  if not profile.identity.isValidIdentity():
    return false

  if profile.curve != ecCurveP256:
    return false

  if profile.keyObjectId != objectIdFor(profile.kind, profile.identity, profile.slot):
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

proc tlsIdentityProfileForObjectId*(
    objectId: uint32
): Option[TlsIdentityProfile] =
  ## Resolves one TLS identity profile by Secure Object ID.
  let kind =
    if objectId >= DevelopmentObjectStart and objectId <= DevelopmentObjectEnd:
      some(tipTest)
    elif objectId >= CustomerObjectStart and objectId <= CustomerObjectEnd:
      some(tipProduction)
    else:
      none(TlsIdentityProfileKind)

  if kind.isNone:
    return none(TlsIdentityProfile)

  let relativeIndex = objectId and 0x0000FFFF'u32
  if relativeIndex < TlsIdentityRelativeIndexBase:
    return none(TlsIdentityProfile)

  let delta = relativeIndex - TlsIdentityRelativeIndexBase
  let identity32 = delta div TlsIdentitySlotStride
  if identity32 > uint32(TlsIdentityMaxIdentity):
    return none(TlsIdentityProfile)

  let slot = if (delta mod TlsIdentitySlotStride) == 0'u32: tisSlotA else: tisSlotB
  let profile = tlsIdentityProfile(kind.get(), uint16(identity32), slot)
  if profile.isValid() and profile.keyObjectId == objectId:
    result = some(profile)
  else:
    result = none(TlsIdentityProfile)

proc isProduction*(profile: TlsIdentityProfile): bool =
  result = profile.kind == tipProduction

proc isDefaultIdentity*(profile: TlsIdentityProfile): bool =
  result = profile.identity == TlsIdentityDefaultIdentity

proc isDeletable*(profile: TlsIdentityProfile): bool =
  ## TLS identity keys are intentionally rotatable in both profiles.
  discard profile
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

static:
  doAssert TlsIdentityTestSlotAObjectId == objectIdFor(tipTest, 0'u16, tisSlotA)
  doAssert TlsIdentityTestSlotBObjectId == objectIdFor(tipTest, 0'u16, tisSlotB)
  doAssert TlsIdentityProductionSlotAObjectId == objectIdFor(tipProduction, 0'u16, tisSlotA)
  doAssert TlsIdentityProductionSlotBObjectId == objectIdFor(tipProduction, 0'u16, tisSlotB)
  doAssert objectIdFor(tipTest, 1'u16, tisSlotA) == 0x30000202'u32
  doAssert objectIdFor(tipTest, 1'u16, tisSlotB) == 0x30000203'u32
  doAssert objectIdFor(tipProduction, 1'u16, tisSlotA) == 0x20000202'u32
  doAssert objectIdFor(tipProduction, 1'u16, tisSlotB) == 0x20000203'u32
