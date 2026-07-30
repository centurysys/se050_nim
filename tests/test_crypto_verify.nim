import std/strutils
import std/unittest

import se050_nim/errors
import se050_nim/crypto_verify

const
  TestCertificateHex = "3082019e30820145a003020102021467514967cf990581208d0bd3c50114ce7d9716b5300a06082a8648ce3d04030230253123302106035504030c1a73653035302d6e696d2d6174746573746174696f6e2d74657374301e170d3236303732393036353835375a170d3336303732363036353835375a30253123302106035504030c1a73653035302d6e696d2d6174746573746174696f6e2d746573743059301306072a8648ce3d020106082a8648ce3d03010703420004a0be76fb6491692572fb817d9462d4b62139a3c8ec38a63aeed5162016c47e42c35a04b069eb85156c359d06170e6b5402a7f5f3bce193189f289bccc9293b2aa3533051301d0603551d0e04160414f6d38aefc9f68f30b39588fb8ed34ac121510342301f0603551d23041830168014f6d38aefc9f68f30b39588fb8ed34ac121510342300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034700304402207a7c14ea152c13cab669a2dcdbb0ced0251f49889982a2ae132a7cf05d931d4e022072e89fff46fb99e307200917c3b9dc1ab3f330d7910ac8b8a2531d364a8cc9b6"
  TestPublicKeyHex = "04a0be76fb6491692572fb817d9462d4b62139a3c8ec38a63aeed5162016c47e42c35a04b069eb85156c359d06170e6b5402a7f5f3bce193189f289bccc9293b2a"
  TestSignatureHex = "304402203e0842db2f82c8f89320588852f7a0d36e220872d271f1c0cd899a3f78db0e3202203221540b7be9ec81d2b17484ec7be5b1ff4f2d40b49e36ca8969a079c33581e0"
  TestCommandHashHex = "a82cbb2d1bba712d66fc5e7823ba1bc95637396b4c755dbf0282bbfcb1837a1e"
  TestResponseHex = "4141040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40421204005001b10d3d3fa75885042719d23e1f90431c0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c440200204f0c00000003000000000000f235"

proc hexBytes(text: string): seq[uint8] =
  let compact = text.replace(" ", "").replace("\n", "")
  doAssert (compact.len mod 2) == 0
  result = newSeq[uint8](compact.len div 2)
  for i in 0 ..< result.len:
    result[i] = uint8(parseHexInt(compact[i * 2 .. i * 2 + 1]))

proc digestBytes(digest: array[Sha256DigestLength, uint8]): seq[uint8] =
  result = @[]
  result.add(digest)

suite "OpenSSL host crypto verification":
  test "computes standard SHA-256 vectors":
    let emptyDigest = sha256(newSeq[uint8]())
    check emptyDigest.ok
    check emptyDigest.value.digestBytes() == hexBytes(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    let abcDigest = sha256(@[uint8(ord('a')), uint8(ord('b')), uint8(ord('c'))])
    check abcDigest.ok
    check abcDigest.value.digestBytes() == hexBytes(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

  test "extracts an uncompressed P-256 public point from X.509":
    let publicKey = extractCertificateEcPublicKey(hexBytes(TestCertificateHex))
    check publicKey.ok
    check publicKey.value == hexBytes(TestPublicKeyHex)

  test "computes the certificate DER fingerprint":
    let fingerprint = certificateSha256(hexBytes(TestCertificateHex))
    check fingerprint.ok
    check fingerprint.value.digestBytes() == hexBytes(
      "b1e9045cfc217c62efee06bc940afc74f8380eb8aa91596a4f2aa7874c6ad5b1"
    )

  test "verifies ECDSA SHA-256 using the certificate public key":
    var message = hexBytes(TestCommandHashHex)
    message.add(hexBytes(TestResponseHex))

    let verified = verifyEcdsaSha256WithCertificate(
      hexBytes(TestCertificateHex),
      message,
      hexBytes(TestSignatureHex)
    )
    check verified.ok

  test "rejects modified signed data":
    var message = hexBytes(TestCommandHashHex)
    message.add(hexBytes(TestResponseHex))
    message[^1] = message[^1] xor 0x01'u8

    let verified = verifyEcdsaSha256WithCertificate(
      hexBytes(TestCertificateHex),
      message,
      hexBytes(TestSignatureHex)
    )
    check not verified.ok
    check verified.error.kind == seSignatureInvalid

  test "rejects trailing certificate bytes":
    var certificate = hexBytes(TestCertificateHex)
    certificate.add(0x00'u8)

    let publicKey = extractCertificateEcPublicKey(certificate)
    check not publicKey.ok
