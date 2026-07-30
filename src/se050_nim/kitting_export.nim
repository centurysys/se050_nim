# =============================================================================
# SE050 kitting CSV export helpers
# =============================================================================
#
# Pure merge logic shared by the factory exporter and its unit tests. Live
# SE050 access, certificate verification, and atomic file replacement remain in
# the dedicated exporter executable.

import std/strformat

import ./errors
import ./kitting_record

# =============================================================================
# Types
# =============================================================================

type
  KittingCsvMergeDisposition* = enum
    kcmdAdded,
    kcmdUnchanged

  KittingCsvMergeResult* = object
    records*: seq[KittingRecord]
    disposition*: KittingCsvMergeDisposition
    recordCount*: int

# =============================================================================
# Public API
# =============================================================================

proc sameKittingRecordKey*(a, b: KittingRecord): bool =
  ## Returns true when two records occupy the same logical CSV slot.
  result =
    a.serialNumber == b.serialNumber and
    a.profileKind == b.profileKind and
    a.keyRole == b.keyRole

proc sameKittingDeviceKey*(a, b: KittingRecord): bool =
  ## Returns true when two records identify the same attested device key.
  result =
    a.sameKittingRecordKey(b) and
    a.se050Uid == b.se050Uid and
    a.keyObjectId == b.keyObjectId and
    a.publicKey == b.publicKey

proc mergeKittingRecord*(
    existing: openArray[KittingRecord],
    incoming: KittingRecord
): SE[KittingCsvMergeResult] =
  ## Adds one record or accepts an already registered identical device key.
  ##
  ## A matching serial/profile/role with a different UID, object ID, or public
  ## key is a conflict and is never overwritten automatically.
  result.value.records = @existing

  for current in existing:
    if not current.sameKittingRecordKey(incoming):
      continue

    if not current.sameKittingDeviceKey(incoming):
      return fail[KittingCsvMergeResult](
        seKittingValidationFailed,
        &"kitting CSV already contains a different key for serial {incoming.serialNumber}, profile {incoming.profile().name}, role {incoming.keyRole}"
      )

    result.value.disposition = kcmdUnchanged
    result.value.recordCount = existing.len
    result.ok = true
    return

  result.value.records.add(incoming)
  result.value.disposition = kcmdAdded
  result.value.recordCount = result.value.records.len
  result.ok = true
