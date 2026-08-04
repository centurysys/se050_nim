import std/os
import std/strutils
import std/tempfiles
import std/unittest

import se050_nim

proc sampleP256PublicKey(): seq[uint8] =
  result = newSeq[uint8](65)
  result[0] = 0x04'u8
  for i in 1 ..< result.len:
    result[i] = uint8(i)

proc removeTestDirectory(directory: string) =
  if dirExists(directory):
    for kind, path in walkDir(directory):
      case kind
      of pcFile, pcLinkToFile:
        discard tryRemoveFile(path)
      of pcDir, pcLinkToDir:
        discard
    removeDir(directory)

suite "TLS OpenSSL reference-key file export":
  test "writes a 0600 P-256 reference-key PEM":
    let directory = createTempDir("se050-refkey-", "")
    defer:
      removeTestDirectory(directory)

    let outputPath = directory / "device.key"
    let publicKey = sampleP256PublicKey()
    let written = writeP256ReferenceKeyFile(
      objectId = 0x20000200'u32,
      publicKey = publicKey,
      outputPath = outputPath
    )

    require written.ok
    check fileExists(outputPath)
    check readFile(outputPath) == encodeP256ReferenceKeyPem(
      0x20000200'u32,
      publicKey
    )
    check getFilePermissions(outputPath) == {fpUserRead, fpUserWrite}

  test "refuses to overwrite an existing output file":
    let directory = createTempDir("se050-refkey-", "")
    defer:
      removeTestDirectory(directory)

    let outputPath = directory / "device.key"
    writeFile(outputPath, "keep-me\n")

    let written = writeP256ReferenceKeyFile(
      objectId = 0x20000200'u32,
      publicKey = sampleP256PublicKey(),
      outputPath = outputPath
    )

    check not written.ok
    check written.error.kind == seInvalidArgument
    check written.error.message.contains("already exists")
    check readFile(outputPath) == "keep-me\n"

  test "rejects a missing output directory without leaving a file":
    let directory = createTempDir("se050-refkey-", "")
    defer:
      removeTestDirectory(directory)

    let missingDirectory = directory / "missing"
    let outputPath = missingDirectory / "device.key"
    let written = writeP256ReferenceKeyFile(
      objectId = 0x20000200'u32,
      publicKey = sampleP256PublicKey(),
      outputPath = outputPath
    )

    check not written.ok
    check written.error.kind == seInvalidArgument
    check written.error.message.contains("directory does not exist")
    check not fileExists(outputPath)

  test "rejects invalid public-key data without creating output":
    let directory = createTempDir("se050-refkey-", "")
    defer:
      removeTestDirectory(directory)

    let outputPath = directory / "device.key"
    let written = writeP256ReferenceKeyFile(
      objectId = 0x20000200'u32,
      publicKey = newSeq[uint8](64),
      outputPath = outputPath
    )

    check not written.ok
    check written.error.kind == seInvalidArgument
    check written.error.message.contains("cannot encode P-256 reference key")
    check not fileExists(outputPath)

  test "live export rejects an invalid profile before transport access":
    let directory = createTempDir("se050-refkey-", "")
    defer:
      removeTestDirectory(directory)

    let outputPath = directory / "device.key"
    var profile = testTlsIdentityProfile(0'u16, tisSlotA)
    profile.keyRole = "invalid-role"

    let se: Se050Transport = nil
    let written = se.writeTlsReferenceKeyFile(profile, outputPath)

    check not written.ok
    check written.error.kind == seInvalidArgument
    check written.error.message == "TLS identity profile is invalid"
    check not fileExists(outputPath)
