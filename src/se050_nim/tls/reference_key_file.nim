# =============================================================================
# SE050 TLS OpenSSL reference-key file export
# =============================================================================
#
# This module connects validated live TLS identities to the pure NXP reference
# key encoder. The final file is installed atomically without overwriting an
# existing path and is created with private-key-style 0600 permissions.
#
# The current implementation is intentionally limited to the existing P-256,
# internally generated TLS identity profile. Multi-algorithm and imported-key
# support will extend the identity validation model before using this path.

import std/os
import std/posix_utils
import std/strformat

import ../errors
import ../objects
import ../transport
import ./profile
import ./live_identity
import ./reference_key

# =============================================================================
# Internal helpers
# =============================================================================

proc pathAlreadyExists(path: string): bool =
  ## Includes broken symbolic links so an existing pathname is never replaced.
  result = fileExists(path) or dirExists(path) or symlinkExists(path)

proc validateReferenceKeyOutputPath(path: string): SE[void] =
  if path.len == 0:
    return fail[void](
      seInvalidArgument,
      "reference key output path is empty"
    )

  let directory = parentDir(path)
  if directory.len > 0 and not dirExists(directory):
    return fail[void](
      seInvalidArgument,
      &"reference key output directory does not exist: {directory}"
    )

  if path.pathAlreadyExists():
    return fail[void](
      seInvalidArgument,
      &"reference key output already exists: {path}"
    )

  result = ok()

proc writeReferenceKeyPemAtomic(path: string, pem: string): SE[void] =
  ## Installs a complete 0600 file without ever replacing an existing path.
  ##
  ## mkstemp creates the temporary file with mode 0600. A same-directory hard
  ## link then publishes that inode at the requested pathname atomically. The
  ## hard-link operation fails if another writer creates the destination first,
  ## unlike rename-based replacement which could overwrite that writer's file.
  let checked = validateReferenceKeyOutputPath(path)
  if not checked.ok:
    return checked

  var temporaryPath = ""
  var temporaryFile: File = nil

  try:
    let created = mkstemp(path & ".tmp.")
    temporaryPath = created[0]
    temporaryFile = created[1]

    temporaryFile.write(pem)
    close(temporaryFile)
    temporaryFile = nil

    createHardlink(temporaryPath, path)

    # The final path now references the complete inode. Removal of the temporary
    # name is cleanup only; the requested output remains valid if cleanup fails.
    discard tryRemoveFile(temporaryPath)
    result = ok()
  except CatchableError as error:
    if temporaryFile != nil:
      close(temporaryFile)
      temporaryFile = nil

    if temporaryPath.len > 0:
      discard tryRemoveFile(temporaryPath)

    if path.pathAlreadyExists():
      result = fail[void](
        seInvalidArgument,
        &"reference key output already exists: {path}"
      )
    else:
      result = fail[void](
        seInvalidArgument,
        &"cannot write reference key file {path}: {error.msg}"
      )

# =============================================================================
# Public API
# =============================================================================

proc writeP256ReferenceKeyFile*(
    objectId: uint32,
    publicKey: openArray[uint8],
    outputPath: string
): SE[void] =
  ## Writes one P-256 NXP reference-key PEM without SE050 access.
  ##
  ## This is the file-output counterpart of encodeP256ReferenceKeyPem(). It is
  ## useful when callers already possess validated object metadata.
  var pem: string
  try:
    pem = encodeP256ReferenceKeyPem(objectId, publicKey)
  except ValueError as error:
    return fail[void](
      seInvalidArgument,
      &"cannot encode P-256 reference key: {error.msg}"
    )

  result = writeReferenceKeyPemAtomic(outputPath, pem)

proc writeTlsReferenceKeyFile*(
    se: Se050Transport,
    profile: TlsIdentityProfile,
    outputPath: string
): SE[TlsIdentityLiveInfo] =
  ## Validates one live TLS identity and writes its OpenSSL reference-key PEM.
  ##
  ## Existing paths are never overwritten. The returned live information is the
  ## exact identity state that was validated and used to create the file, so a
  ## CLI caller does not need to inspect the SE050 object a second time.
  let outputChecked = validateReferenceKeyOutputPath(outputPath)
  if not outputChecked.ok:
    return fail[TlsIdentityLiveInfo](
      outputChecked.error.kind,
      outputChecked.error.message,
      outputChecked.error.sw
    )

  if not profile.isValid():
    return fail[TlsIdentityLiveInfo](
      seInvalidArgument,
      "TLS identity profile is invalid"
    )

  let exists = se.objectExists(
    objectId = profile.keyObjectId,
    selectFirst = true
  )
  if not exists.ok:
    return fail[TlsIdentityLiveInfo](
      exists.error.kind,
      exists.error.message,
      exists.error.sw
    )

  if not exists.value:
    return fail[TlsIdentityLiveInfo](
      seTlsIdentityValidationFailed,
      &"TLS identity {profile.name} identity {profile.identity} slot {profile.slot.slotName()} does not exist"
    )

  let inspected = se.inspectTlsIdentity(profile)
  if not inspected.ok:
    return fail[TlsIdentityLiveInfo](
      inspected.error.kind,
      inspected.error.message,
      inspected.error.sw
    )

  let written = writeP256ReferenceKeyFile(
    objectId = inspected.value.profile.keyObjectId,
    publicKey = inspected.value.publicKey,
    outputPath = outputPath
  )
  if not written.ok:
    return fail[TlsIdentityLiveInfo](
      written.error.kind,
      written.error.message,
      written.error.sw
    )

  result = ok(inspected.value)
