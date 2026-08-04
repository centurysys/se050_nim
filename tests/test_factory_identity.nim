import std/strutils
import std/unittest

import se050_nim

suite "NXP factory-provisioned cloud identities":
  test "maps the documented ECC P-256 cloud identity objects":
    let identity0 = factoryCloudIdentityProfile(fciEccP256, 0'u8)
    check identity0.keyObjectId == 0xF0000100'u32
    check identity0.certificateObjectId == 0xF0000101'u32
    check identity0.opensslProviderKeyUri() == "nxp:0xF0000100"

    let identity1 = factoryCloudIdentityProfile(fciEccP256, 1'u8)
    check identity1.keyObjectId == 0xF0000102'u32
    check identity1.certificateObjectId == 0xF0000103'u32
    check identity1.opensslProviderKeyUri() == "nxp:0xF0000102"

  test "maps the documented RSA-2048 cloud identity objects":
    let identity0 = factoryCloudIdentityProfile(fciRsa2048, 0'u8)
    check identity0.keyObjectId == 0xF0000110'u32
    check identity0.certificateObjectId == 0xF0000111'u32
    check identity0.opensslProviderKeyUri() == "nxp:0xF0000110"

    let identity1 = factoryCloudIdentityProfile(fciRsa2048, 1'u8)
    check identity1.keyObjectId == 0xF0000112'u32
    check identity1.certificateObjectId == 0xF0000113'u32
    check identity1.opensslProviderKeyUri() == "nxp:0xF0000112"

  test "rejects an out-of-range factory identity number":
    expect ValueError:
      discard factoryCloudIdentityProfile(fciEccP256, 2'u8)

  test "rejects a mutated factory identity profile":
    var profile = factoryCloudIdentityProfile(fciEccP256, 0'u8)
    profile.keyObjectId = 0xF0000102'u32
    check not profile.isValid()

    expect ValueError:
      discard profile.opensslProviderKeyUri()

  test "encodes DER certificates as PEM":
    let der = @[0x30'u8, 0x03'u8, 0x02'u8, 0x01'u8, 0x01'u8]
    let pem = factoryCertificateDerToPem(der)
    check pem.startsWith("-----BEGIN CERTIFICATE-----\n")
    check pem.contains("MAMCAQE=")
    check pem.endsWith("-----END CERTIFICATE-----\n")

  test "encodes SubjectPublicKeyInfo DER as PEM":
    let der = @[0x30'u8, 0x03'u8, 0x02'u8, 0x01'u8, 0x01'u8]
    let pem = subjectPublicKeyInfoDerToPem(der)
    check pem.startsWith("-----BEGIN PUBLIC KEY-----\n")
    check pem.contains("MAMCAQE=")
    check pem.endsWith("-----END PUBLIC KEY-----\n")

  test "extracts SubjectPublicKeyInfo from an X.509 certificate":
    # The embedded NXP attestation root uses a P-521 public key.  This fixture
    # intentionally exercises the generic certificate extractor rather than
    # assuming that every EC certificate contains a P-256 key.
    let publicKey = extractCertificatePublicKeySpkiDer(nxpAttestationRootDer())
    require publicKey.ok
    check publicKey.value.len == 158
    check publicKey.value[0] == 0x30'u8
    check publicKey.value[1] == 0x81'u8
    check publicKey.value[2] == 0x9B'u8
