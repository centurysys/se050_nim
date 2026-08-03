# =============================================================================
# Verify P-256 ECDSA/SHA-256 signing with an SE050 development key
# =============================================================================
#
# Build:
#   nim c examples/p256_sign_digest.nim
#
# Run:
#   ./examples/p256_sign_digest 0 0x130
#
# Behavior:
#   - uses only dev object IDs: 0x30000000..0x3000FFFF
#   - refuses to overwrite an existing object
#   - creates a P-256 key with a disposable signing development policy
#   - hashes a fixed test message on the host
#   - signs the SHA-256 digest inside SE050
#   - writes the message, digest, DER signature, raw public key, and SPKI DER
#
# Host verification:
#   openssl pkey -pubin -inform DER \
#     -in p256_sign_pub.der -out p256_sign_pub.pem
#   openssl dgst -sha256 -verify p256_sign_pub.pem \
#     -signature p256_sign_signature.der p256_sign_message.bin
#
# Expected result:
#   Verified OK

import std/[os, strformat, strutils]

import se050_nim

const
  DevObjectBase = 0x30000000'u32
  DefaultDevIndex = 0x130'u32
  TestMessage = "se050_nim ECDSA signing test\n"

  # SubjectPublicKeyInfo prefix for an uncompressed NIST P-256 public point:
  #   id-ecPublicKey + prime256v1 + BIT STRING header.
  P256SpkiPrefix = [
    0x30'u8, 0x59'u8,
    0x30'u8, 0x13'u8,
    0x06'u8, 0x07'u8, 0x2A'u8, 0x86'u8, 0x48'u8, 0xCE'u8,
    0x3D'u8, 0x02'u8, 0x01'u8,
    0x06'u8, 0x08'u8, 0x2A'u8, 0x86'u8, 0x48'u8, 0xCE'u8,
    0x3D'u8, 0x03'u8, 0x01'u8, 0x07'u8,
    0x03'u8, 0x42'u8, 0x00'u8
  ]

proc usage(programName: string) =
  echo &"Usage: {programName} <bus> [dev-index]"
  echo ""
  echo &"  dev-index  0x0000..0xFFFF, default: 0x{DefaultDevIndex.toHex(4)}"
  echo ""
  echo &"Example: {programName} 0 0x130"

proc parseU32Text(s: string): uint32 =
  var t = s.strip()
  if t.len == 0:
    raise newException(ValueError, "empty integer")

  var base = 10'u32
  if t.startsWith("0x") or t.startsWith("0X"):
    t = t[2 .. ^1]
    base = 16'u32

  if t.len == 0:
    raise newException(ValueError, "empty integer")

  var acc: uint64 = 0
  for c in t:
    var digit: uint32
    if c >= '0' and c <= '9':
      digit = uint32(ord(c) - ord('0'))
    elif base == 16 and c >= 'a' and c <= 'f':
      digit = uint32(ord(c) - ord('a') + 10)
    elif base == 16 and c >= 'A' and c <= 'F':
      digit = uint32(ord(c) - ord('A') + 10)
    else:
      raise newException(ValueError, &"invalid integer: {s}")

    if digit >= base:
      raise newException(ValueError, &"invalid integer: {s}")

    acc = acc * uint64(base) + uint64(digit)
    if acc > uint64(uint32.high):
      raise newException(ValueError, &"integer out of uint32 range: {s}")

  result = uint32(acc)

proc devObjectId(index: uint32): uint32 =
  if index > 0xFFFF'u32:
    raise newException(ValueError, "dev-index must be 0x0000..0xFFFF")
  result = DevObjectBase or index

proc bytesToString(data: openArray[uint8]): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc stringToBytes(data: string): seq[uint8] =
  result = newSeq[uint8](data.len)
  for i, c in data:
    result[i] = uint8(c)

proc writeBytes(path: string, data: openArray[uint8]) =
  writeFile(path, bytesToString(data))

proc requireOk[T](label: string, r: SE[T]): T =
  if not r.ok:
    echo label, " failed: ", r.error.kind, ": ", r.error.errorMessage()
    quit(1)
  result = r.value

proc requireVoidOk(label: string, r: SE[void]) =
  if not r.ok:
    echo label, " failed: ", r.error.kind, ": ", r.error.errorMessage()
    quit(1)

proc makeP256Spki(publicKey: openArray[uint8]): seq[uint8] =
  if publicKey.len != EcP256UncompressedPublicKeyLength or publicKey[0] != 0x04'u8:
    raise newException(ValueError, "SE050 public key is not an uncompressed P-256 point")

  result = @[]
  for b in P256SpkiPrefix:
    result.add(b)
  for b in publicKey:
    result.add(b)

proc main(): int =
  let args = commandLineParams()
  if args.len > 2 or (args.len >= 1 and args[0] in ["-h", "--help"]):
    usage(getAppFilename().lastPathPart())
    if args.len >= 1 and args[0] in ["-h", "--help"]:
      return 0
    return 2

  if args.len < 1:
    usage(getAppFilename().lastPathPart())
    return 2

  let bus = parseInt(args[0])
  let index = if args.len >= 2: parseU32Text(args[1]) else: DefaultDevIndex
  let objectId = devObjectId(index)

  if bus < 0:
    echo "bus must be >= 0"
    return 2

  let se = openSe050(bus)
  discard requireOk("GET_ATR", se.requestAtr())

  let exists = requireOk("objectExists", se.objectExists(objectId))
  if exists:
    echo &"object 0x{objectId.toHex(8)} already exists; refusing to overwrite"
    echo "choose another dev-index or delete this development object explicitly"
    return 2

  let keyPolicy = developmentSigningEcKeyPolicy()
  echo &"creating P-256 signing key: 0x{objectId.toHex(8)}"
  echo &"policy header: 0x{keyPolicy.policyHeader().toHex(8)}"
  requireVoidOk(
    "generateP256KeyPair",
    se.generateP256KeyPair(objectId, keyPolicy)
  )

  let typeInfo = requireOk("readObjectType", se.readObjectType(objectId))
  if typeInfo.objectType != Se050TypeEcKeyPairNistP256:
    echo &"unexpected key type: 0x{typeInfo.objectType.toHex(2)} ({objectTypeName(typeInfo.objectType)})"
    return 1

  let publicKey = requireOk("readPublicKey", se.readPublicKey(objectId))
  let message = stringToBytes(TestMessage)
  let digestArray = requireOk("sha256", sha256(message))
  let signature = requireOk("signDigest", se.signDigest(objectId, digestArray))
  let publicKeySpki = makeP256Spki(publicKey)

  writeBytes("p256_sign_message.bin", message)
  writeBytes("p256_sign_digest.bin", digestArray)
  writeBytes("p256_sign_signature.der", signature)
  writeBytes("p256_sign_pub_raw.bin", publicKey)
  writeBytes("p256_sign_pub.der", publicKeySpki)

  echo &"public key length: {publicKey.len}"
  echo &"digest length: {digestArray.len}"
  echo &"signature DER length: {signature.len}"
  echo "wrote: p256_sign_message.bin"
  echo "wrote: p256_sign_digest.bin"
  echo "wrote: p256_sign_signature.der"
  echo "wrote: p256_sign_pub_raw.bin"
  echo "wrote: p256_sign_pub.der"
  echo ""
  echo "Verify on the host:"
  echo "  openssl pkey -pubin -inform DER -in p256_sign_pub.der -out p256_sign_pub.pem"
  echo "  openssl dgst -sha256 -verify p256_sign_pub.pem -signature p256_sign_signature.der p256_sign_message.bin"

  result = 0

when isMainModule:
  try:
    quit(main())
  except CatchableError as e:
    echo "error: ", e.msg
    quit(1)
