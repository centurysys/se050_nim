# =============================================================================
# Create/reuse and attest one SE050 TLS client identity test key
# =============================================================================
#
# Build:
#   nim c examples/tls_identity_attestation.nim
#
# Run:
#   ./examples/tls_identity_attestation 0 A
#   ./examples/tls_identity_attestation 0 B
#
# Safety:
#   This example uses only the fixed development-area TLS identity slots
#   0x30000200/0x30000201. Existing objects are never overwritten or deleted.
#
# The example verifies:
#   - the live object is a persistent P-256 key pair
#   - the NXP device attestation certificate chains to the embedded NXP roots
#   - the ReadObject-with-Attestation ECDSA signature is valid
#   - signed object ID/type/origin/policy semantics match the TLS A/B profile
#   - the separately read live public key matches the attested public key

import std/[options, os, strformat, strutils]

import se050_nim

proc usage(programName: string) =
  echo &"Usage: {programName} <bus> [A|B]"
  echo ""
  echo &"Example: {programName} 0 A"

proc parseSlot(value: string): TlsIdentitySlot =
  case value.strip().toUpperAscii()
  of "A": tisSlotA
  of "B": tisSlotB
  else:
    raise newException(ValueError, &"invalid TLS identity slot: {value}")

proc requireOk[T](label: string, r: SE[T]): T =
  if not r.ok:
    echo label, " failed: ", r.error.kind, ": ", r.error.errorMessage()
    quit(1)
  result = r.value

proc requireVoidOk(label: string, r: SE[void]) =
  if not r.ok:
    echo label, " failed: ", r.error.kind, ": ", r.error.errorMessage()
    quit(1)

proc stringToBytes(data: string): seq[uint8] =
  result = newSeq[uint8](data.len)
  for i, c in data:
    result[i] = uint8(c)

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
  if bus < 0:
    echo "bus must be >= 0"
    return 2

  let slot = if args.len >= 2: parseSlot(args[1]) else: tisSlotA
  let profile = testTlsIdentityProfile(slot)

  if not profile.isValid():
    echo "invalid TLS identity profile"
    return 2

  let se = openSe050(bus)
  discard requireOk("GET_ATR", se.requestAtr())

  let exists = requireOk(
    "objectExists",
    se.objectExists(profile.keyObjectId, selectFirst = true)
  )

  var keyCreated = false
  if not exists:
    echo &"creating TLS identity test key: 0x{profile.keyObjectId.toHex(8)}"
    echo &"policy header: 0x{policyHeader(profile.keyPolicy()).toHex(8)}"
    requireVoidOk(
      "generateP256KeyPair",
      se.generateP256KeyPair(
        objectId = profile.keyObjectId,
        policy = profile.keyPolicy(),
        selectFirst = false
      )
    )
    keyCreated = true
  else:
    echo &"reusing existing object: 0x{profile.keyObjectId.toHex(8)}"

  let typeInfo = requireOk(
    "readObjectType",
    se.readObjectType(profile.keyObjectId, selectFirst = false)
  )
  if typeInfo.objectType != profile.expectedKeyType():
    echo &"unexpected object type: 0x{typeInfo.objectType.toHex(2)} ({objectTypeName(typeInfo.objectType)})"
    return 1

  if typeInfo.transientIndicator.isNone or
      typeInfo.transientIndicator.get() != 0x01'u8:
    echo "TLS identity object is not persistent"
    return 1

  let livePublicKey = requireOk(
    "readPublicKey",
    se.readPublicKey(profile.keyObjectId, selectFirst = false)
  )

  let certificate = requireOk(
    "readAttestationCertificate",
    se.readAttestationCertificate(selectFirst = false)
  )

  discard requireOk(
    "verifyCertificateChain",
    verifyCertificateChain(
      leafCertificateDer = certificate,
      trustAnchorsDer = nxpAttestationTrustAnchors(),
      intermediatesDer = nxpAttestationIntermediates()
    )
  )

  let freshness = requireOk(
    "getRandomBytes",
    se.getRandomBytes(
      TlsIdentityAttestationFreshnessLength,
      selectFirst = false
    )
  )

  let attested = requireOk(
    "readObjectWithAttestation",
    se.readObjectWithAttestation(
      objectId = profile.keyObjectId,
      freshness = freshness,
      selectFirst = false
    )
  )

  discard requireOk(
    "verifyAttestationSignature",
    verifyAttestationSignature(
      attested = attested,
      certificateDer = certificate
    )
  )

  let semantics = requireOk(
    "verifyTlsIdentityAttestationSemantics",
    verifyTlsIdentityAttestationSemantics(
      attested = attested,
      profile = profile
    )
  )

  if livePublicKey != semantics.publicKey:
    echo "live public key does not match the attested public key"
    return 1

  # Exercise the minimal TLS profile itself, not only its signed policy value.
  # Step 1 already verified the low-level ECDSA primitive; this confirms that
  # SIGN remains usable with the stricter SIGN + READ + DELETE TLS policy.
  let signMessage = stringToBytes("se050_nim TLS identity policy test\n")
  let signDigestValue = requireOk("sha256", sha256(signMessage))
  let signature = requireOk(
    "signDigest",
    se.signDigest(
      objectId = profile.keyObjectId,
      digest = signDigestValue,
      selectFirst = false
    )
  )

  let createdText = if keyCreated: "yes" else: "no"
  echo &"profile: {profile.name}"
  echo &"slot: {profile.slot.slotName()}"
  echo &"object id: 0x{profile.keyObjectId.toHex(8)}"
  echo &"key created: {createdText}"
  echo &"object type: 0x{semantics.attributes.objectType.toHex(2)}"
  echo &"persistent: yes (live ReadType)"
  echo &"origin: {objectOriginName(semantics.attributes.origin)} (signed)"
  echo &"policy header: 0x{semantics.attributes.policies[0].header.toHex(8)} (signed)"
  echo &"public key length: {semantics.publicKey.len} (signed and live-match)"
  echo &"ECDSA signature DER length: {signature.len} (TLS policy SIGN check)"
  echo "attestation certificate chain: verified"
  echo "attestation signature: verified"
  echo "TLS identity semantics: verified"

  result = 0

when isMainModule:
  try:
    quit(main())
  except CatchableError as e:
    echo "error: ", e.msg
    quit(1)
