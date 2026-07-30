import std/strutils
import std/unittest

import se050_nim/attestation
import se050_nim/attestation_verify
import se050_nim/errors
import se050_nim/crypto_verify

const
  TestCertificateHex = "3082019e30820145a003020102021467514967cf990581208d0bd3c50114ce7d9716b5300a06082a8648ce3d04030230253123302106035504030c1a73653035302d6e696d2d6174746573746174696f6e2d74657374301e170d3236303732393036353835375a170d3336303732363036353835375a30253123302106035504030c1a73653035302d6e696d2d6174746573746174696f6e2d746573743059301306072a8648ce3d020106082a8648ce3d03010703420004a0be76fb6491692572fb817d9462d4b62139a3c8ec38a63aeed5162016c47e42c35a04b069eb85156c359d06170e6b5402a7f5f3bce193189f289bccc9293b2aa3533051301d0603551d0e04160414f6d38aefc9f68f30b39588fb8ed34ac121510342301f0603551d23041830168014f6d38aefc9f68f30b39588fb8ed34ac121510342300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034700304402207a7c14ea152c13cab669a2dcdbb0ced0251f49889982a2ae132a7cf05d931d4e022072e89fff46fb99e307200917c3b9dc1ab3f330d7910ac8b8a2531d364a8cc9b6"
  TestPublicKeyHex = "04a0be76fb6491692572fb817d9462d4b62139a3c8ec38a63aeed5162016c47e42c35a04b069eb85156c359d06170e6b5402a7f5f3bce193189f289bccc9293b2a"
  TestCommandHex = "8022000000001f4104300001004504f00000124601214710000102030405060708090a0b0c0d0e0f"
  TestResponseHex = "4141040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40421204005001b10d3d3fa75885042719d23e1f90431c0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c440200204f0c00000003000000000000f235"
  TestSignatureHex = "304402203e0842db2f82c8f89320588852f7a0d36e220872d271f1c0cd899a3f78db0e3202203221540b7be9ec81d2b17484ec7be5b1ff4f2d40b49e36ca8969a079c33581e0"
  TestCommandHashHex = "a82cbb2d1bba712d66fc5e7823ba1bc95637396b4c755dbf0282bbfcb1837a1e"

proc hexBytes(text: string): seq[uint8] =
  let compact = text.replace(" ", "").replace("\n", "")
  doAssert (compact.len mod 2) == 0
  result = newSeq[uint8](compact.len div 2)
  for i in 0 ..< result.len:
    result[i] = uint8(parseHexInt(compact[i * 2 .. i * 2 + 1]))

proc digestBytes(digest: array[Sha256DigestLength, uint8]): seq[uint8] =
  result = @[]
  result.add(digest)

proc testAttestation(): AttestedObjectRead =
  result = AttestedObjectRead(
    request: AttestationRequest(
      algorithm: Se050AttestationAlgorithmEcSha256,
      signedCommandApdu: hexBytes(TestCommandHex)
    ),
    response: AttestationResponse(
      signedResponseData: hexBytes(TestResponseHex),
      signature: hexBytes(TestSignatureHex)
    )
  )

suite "SE050 attestation signature verification":
  test "builds hash(command) plus encoded response TLVs":
    let verificationData = buildAttestationVerificationData(testAttestation())
    check verificationData.ok

    var expected = hexBytes(TestCommandHashHex)
    expected.add(hexBytes(TestResponseHex))
    check verificationData.value == expected

  test "verifies a complete Applet 7.2 attestation signature":
    let verified = verifyAttestationSignature(
      testAttestation(),
      hexBytes(TestCertificateHex)
    )
    check verified.ok
    check verified.value.certificatePublicKey == hexBytes(TestPublicKeyHex)
    check verified.value.commandSha256.digestBytes() == hexBytes(TestCommandHashHex)

  test "rejects a modified signed command":
    var attested = testAttestation()
    attested.request.signedCommandApdu[^1] =
      attested.request.signedCommandApdu[^1] xor 0x01'u8

    let verified = verifyAttestationSignature(
      attested,
      hexBytes(TestCertificateHex)
    )
    check not verified.ok
    check verified.error.kind == seSignatureInvalid

  test "rejects modified response TLVs":
    var attested = testAttestation()
    attested.response.signedResponseData[^1] =
      attested.response.signedResponseData[^1] xor 0x01'u8

    let verified = verifyAttestationSignature(
      attested,
      hexBytes(TestCertificateHex)
    )
    check not verified.ok
    check verified.error.kind == seSignatureInvalid

  test "rejects an unsupported attestation algorithm":
    var attested = testAttestation()
    attested.request.algorithm = 0x22'u8

    let verificationData = buildAttestationVerificationData(attested)
    check not verificationData.ok
