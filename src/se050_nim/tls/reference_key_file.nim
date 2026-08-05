# =============================================================================
# SE050 TLS OpenSSL reference-key file export
# =============================================================================
#
# This module connects validated live TLS identities to the pure NXP reference
# key encoder. The final file is installed atomically without overwriting an
# existing path and is created with private-key-style 0600 permissions.
#
# Internally generated and externally imported TLS identities use separate
# public export entry points. P-256 and P-384 share the NXP reference-key
# suffix layout but retain their own SEC1 named-curve and public-key encoding.

import std/os
import std/posix_utils
import std/strformat

import ../errors
import ../keys
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

proc writeP384ReferenceKeyFile*(
    objectId: uint32,
    publicKey: openArray[uint8],
    outputPath: string
): SE[void] =
  ## Writes one P-384 NXP reference-key PEM without SE050 access.
  var pem: string
  try:
    pem = encodeP384ReferenceKeyPem(objectId, publicKey)
  except ValueError as error:
    return fail[void](
      seInvalidArgument,
      &"cannot encode P-384 reference key: {error.msg}"
    )

  result = writeReferenceKeyPemAtomic(outputPath, pem)

proc writeEcReferenceKeyFile(
    curve: EcCurveKind,
    objectId: uint32,
    publicKey: openArray[uint8],
    outputPath: string
): SE[void] =
  case curve
  of ecCurveP256:
    result = writeP256ReferenceKeyFile(
      objectId = objectId,
      publicKey = publicKey,
      outputPath = outputPath
    )
  of ecCurveP384:
    result = writeP384ReferenceKeyFile(
      objectId = objectId,
      publicKey = publicKey,
      outputPath = outputPath
    )
  else:
    result = fail[void](
      seInvalidArgument,
      &"OpenSSL reference-key export does not support curve {curveName(curve)}"
    )

proc writeTlsReferenceKeyFileForOrigin(
    se: Se050Transport,
    profile: TlsIdentityProfile,
    outputPath: string,
    imported: bool
): SE[TlsIdentityLiveInfo] =
  ## Shared implementation for the explicit internal/imported public APIs.
  ##
  ## `imported` is deliberately private to this module. Public callers cannot
  ## weaken origin validation by supplying an arbitrary expected origin.
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

  let inspected =
    if imported:
      se.inspectImportedTlsIdentity(profile)
    else:
      se.inspectTlsIdentity(profile)

  if not inspected.ok:
    return fail[TlsIdentityLiveInfo](
      inspected.error.kind,
      inspected.error.message,
      inspected.error.sw
    )

  let written = writeEcReferenceKeyFile(
    curve = inspected.value.profile.curve,
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

proc writeTlsReferenceKeyFile*(
    se: Se050Transport,
    profile: TlsIdentityProfile,
    outputPath: string
): SE[TlsIdentityLiveInfo] =
  ## Validates an internally generated TLS identity and writes its reference key.
  ##
  ## Existing behavior remains strict: signed origin must be internal.
  result = writeTlsReferenceKeyFileForOrigin(
    se = se,
    profile = profile,
    outputPath = outputPath,
    imported = false
  )

proc writeImportedTlsReferenceKeyFile*(
    se: Se050Transport,
    profile: TlsIdentityProfile,
    outputPath: string
): SE[TlsIdentityLiveInfo] =
  ## Validates an externally imported TLS identity and writes its reference key.
  ##
  ## The file format is identical to the internally generated path, but the
  ## signed SE050 object origin is required to be external.
  result = writeTlsReferenceKeyFileForOrigin(
    se = se,
    profile = profile,
    outputPath = outputPath,
    imported = true
  )
