# =============================================================================
# SE050 production kitting object guard
# =============================================================================
#
# Application-level guard for the fixed production firmware KEX Object ID.
# This prevents generic tools from accidentally consuming the irreversible
# production slot with an unrelated object or policy.
#
# This module is an accident-prevention layer, not the SE050 security boundary.
# Raw library primitives intentionally remain available to the dedicated
# production kitting path. The final protection is the policy stored with the
# Secure Object inside the SE050.

import std/options
import std/strformat
import std/strutils

import ./kitting_profile

# =============================================================================
# Types
# =============================================================================

type
  KittingObjectMutationKind* = enum
    ## Generic object mutations that must not target the reserved production
    ## firmware KEX Object ID.
    komCreate,
    komGenerate,
    komWrite,
    komDelete

# =============================================================================
# Internal helpers
# =============================================================================

proc commandName(mutation: KittingObjectMutationKind): string =
  case mutation
  of komCreate:
    result = "create"
  of komGenerate:
    result = "keygen"
  of komWrite:
    result = "write"
  of komDelete:
    result = "delete"

# =============================================================================
# Public API
# =============================================================================

proc isProductionKittingObjectId*(objectId: uint32): bool =
  ## Returns true only for the fixed production firmware KEX Object ID.
  result = objectId == KittingProductionFirmwareKexObjectId

proc productionKittingMutationError*(
    objectId: uint32,
    mutation: KittingObjectMutationKind
): Option[string] =
  ## Rejects generic mutation of the production firmware KEX Object ID.
  ##
  ## Read-only operations are intentionally outside this guard. The dedicated
  ## production kitting implementation may use raw library primitives after it
  ## has fixed and verified the production profile.
  if not objectId.isProductionKittingObjectId():
    return none(string)

  result = some(
    &"{mutation.commandName()} refused: 0x{objectId.toHex(8)} is reserved " &
    "for the production firmware KEX key; use the dedicated kitting exporter"
  )

static:
  doAssert KittingProductionFirmwareKexObjectId == 0x20000100'u32
