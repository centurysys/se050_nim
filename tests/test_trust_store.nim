import std/strutils
import std/unittest

import se050_nim

const
  ExpectedRootSha256 =
    "04811915CE7DA2DA2ED18BF2135622AE49A4A81B2F69F8D433A73E3F24EC1B0B"
  ExpectedIntermediateSha256 =
    "F35796D8A794CEAE69DDEC2316A540A0D0A54B3CE8B16DE00B205F0D65AA40E7"

proc digestHex(digest: array[Sha256DigestLength, uint8]): string =
  for value in digest:
    result.add(value.toHex(2))

suite "embedded NXP attestation trust store":
  test "embeds the expected NXP certificates":
    let root = nxpAttestationRootDer()
    let intermediate = nxpAttestationIntermediateDer()

    require root.len > 0
    require intermediate.len > 0

    let rootDigest = certificateSha256(root)
    require rootDigest.ok
    check rootDigest.value.digestHex() == ExpectedRootSha256

    let intermediateDigest = certificateSha256(intermediate)
    require intermediateDigest.ok
    check intermediateDigest.value.digestHex() == ExpectedIntermediateSha256

  test "returns one fixed root and one fixed intermediate":
    let roots = nxpAttestationTrustAnchors()
    let intermediates = nxpAttestationIntermediates()

    check roots.len == 1
    check intermediates.len == 1
    check roots[0] == nxpAttestationRootDer()
    check intermediates[0] == nxpAttestationIntermediateDer()

  test "validates the intermediate against the embedded root":
    let verified = verifyCertificateChain(
      leafCertificateDer = nxpAttestationIntermediateDer(),
      trustAnchorsDer = nxpAttestationTrustAnchors(),
      intermediatesDer = @[]
    )

    require verified.ok
    check verified.value.trustAnchorCount == 1
    check verified.value.intermediateCount == 0
