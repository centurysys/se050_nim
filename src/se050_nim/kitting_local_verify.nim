# =============================================================================
# Local SE050 kitting record verification
# =============================================================================
#
# Offline verification proves that a CSV record is cryptographically valid and
# that its public key was attested by a trusted SE050. This module adds the
# final local-device checks required before the running unit accepts that
# record as its own:
#
#   * board serial number
#   * live SE050 UID
#   * live Secure Object type and persistence
#   * live public key
#
# The I2C reads remain in the CLI layer. Keeping the comparisons pure makes the
# trust decision reusable and unit-testable.

import std/options
import std/strformat
import std/strutils

import ./errors
import ./uid
import ./board_identity
import ./kitting_profile
import ./kitting_record
import ./kitting_verify

# =============================================================================
# Constants
# =============================================================================

const
  Se050PersistentObjectIndicator = 0x01'u8

# =============================================================================
# Types
# =============================================================================

type
  LocalKittingVerification* = object
    verified*: VerifiedKittingRecord
    boardSerialNumber*: string
    liveSe050Uid*: seq[uint8]
    liveObjectType*: uint8
    liveTransientIndicator*: Option[uint8]
    livePublicKey*: seq[uint8]

# =============================================================================
# Internal helpers
# =============================================================================

proc localFailure(
    message: string
): SE[LocalKittingVerification] =
  result = fail[LocalKittingVerification](
    seKittingValidationFailed,
    message
  )

# =============================================================================
# Public API
# =============================================================================

proc verifyLocalKittingIdentity*(
    verified: VerifiedKittingRecord,
    boardSerialNumber: string,
    liveSe050Uid: openArray[uint8],
    liveObjectType: uint8,
    liveTransientIndicator: Option[uint8],
    livePublicKey: openArray[uint8]
): SE[LocalKittingVerification] =
  ## Confirms that an offline-verified CSV record belongs to the current unit.
  let serial = parseBoardSerialNumber(boardSerialNumber)
  if not serial.ok:
    return localFailure(
      &"local board serial number is invalid: {serial.error.message}"
    )

  if serial.value != verified.record.serialNumber:
    return localFailure(
      &"local board serial number {serial.value} does not match CSV serial {verified.record.serialNumber}"
    )

  if liveSe050Uid.len != Se050UidLength:
    return localFailure(
      &"live SE050 UID must be {Se050UidLength} bytes; got {liveSe050Uid.len}"
    )

  if @liveSe050Uid != verified.record.se050Uid:
    return localFailure(
      "live SE050 UID does not match the attested CSV record"
    )

  let profile = verified.record.profile()
  let expectedObjectType = profile.expectedKeyType()
  if liveObjectType != expectedObjectType:
    return localFailure(
      &"live object type 0x{liveObjectType.toHex(2)} does not match {profile.name} profile type 0x{expectedObjectType.toHex(2)}"
    )

  if liveObjectType != verified.semantics.attributes.objectType:
    return localFailure(
      &"live object type 0x{liveObjectType.toHex(2)} does not match signed type 0x{verified.semantics.attributes.objectType.toHex(2)}"
    )

  if liveTransientIndicator.isNone:
    return localFailure(
      "live Secure Object persistence indicator is missing"
    )

  if liveTransientIndicator.get() != Se050PersistentObjectIndicator:
    return localFailure(
      &"live Secure Object is not persistent: indicator 0x{liveTransientIndicator.get().toHex(2)}"
    )

  if livePublicKey.len != verified.record.publicKey.len:
    return localFailure(
      &"live public key length {livePublicKey.len} does not match CSV length {verified.record.publicKey.len}"
    )

  if @livePublicKey != verified.record.publicKey:
    return localFailure(
      "live public key does not match the attested CSV record"
    )

  result = ok(LocalKittingVerification(
    verified: verified,
    boardSerialNumber: serial.value,
    liveSe050Uid: @liveSe050Uid,
    liveObjectType: liveObjectType,
    liveTransientIndicator: liveTransientIndicator,
    livePublicKey: @livePublicKey
  ))
