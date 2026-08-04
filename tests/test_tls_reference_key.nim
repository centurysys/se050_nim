import std/strutils
import std/unittest

import se050_nim

proc bytesFromHex(text: string): seq[uint8] =
  doAssert (text.len mod 2) == 0
  var offset = 0
  while offset < text.len:
    result.add(uint8(parseHexInt(text[offset .. offset + 1])))
    offset += 2

const
  NxpReadmePublicKeyHex =
    "041C93088B2627BAEA03D1BEDB1BDF8ECC87EF95D29DFCFC3A826FC6E170A050" &
    "D4B71FF2A3ECF8921741604874F2DB3DB4BC2BF8FAE85472F672748C9E5FD3D6D4"

  # SEC1 DER corresponding to the EC reference-key example documented by NXP:
  # Object ID 0x7DCCBBAA, key-pair class 0x10, reserved index 0x00, and the
  # example prime256v1 public key above.
  NxpReadmeReferenceDerHex =
    "30770201010420" &
    "1000000000000000000000000000000000007DCCBBAAA5A6B5B6A5A6B5B61000" &
    "A00A06082A8648CE3D030107" &
    "A144034200" &
    NxpReadmePublicKeyHex

suite "NXP OpenSSL Provider P-256 reference keys":
  test "encodes the documented NXP EC reference-key layout":
    let publicKey = bytesFromHex(NxpReadmePublicKeyHex)
    let expected = bytesFromHex(NxpReadmeReferenceDerHex)
    let der = encodeP256ReferenceKeyDer(0x7DCCBBAA'u32, publicKey)

    check der.len == P256ReferenceKeyDerSize
    check der == expected

  test "stores the SE050 Object ID in big-endian order":
    var publicKey = newSeq[uint8](65)
    publicKey[0] = 0x04'u8

    let der = encodeP256ReferenceKeyDer(0x12345678'u32, publicKey)

    # SEC1 prefix is 7 bytes. Within the 32-byte reference value the Object ID
    # occupies bytes 18..21.
    check der[25 .. 28] == @[0x12'u8, 0x34'u8, 0x56'u8, 0x78'u8]

  test "PEM is canonical SEC1 with 64-character Base64 lines":
    let publicKey = bytesFromHex(NxpReadmePublicKeyHex)
    let der = encodeP256ReferenceKeyDer(0x7DCCBBAA'u32, publicKey)
    let pem = encodeP256ReferenceKeyPem(0x7DCCBBAA'u32, publicKey)
    let lines = pem.strip().splitLines()

    check pem.endsWith("\n")
    check lines.len == 5
    check lines[0] == "-----BEGIN EC PRIVATE KEY-----"
    check lines[1].len == 64
    check lines[2].len == 64
    check lines[3].len == 36
    check lines[4] == "-----END EC PRIVATE KEY-----"

    let decoded = decodeBase64(lines[1] & lines[2] & lines[3])
    check decoded.ok
    check decoded.value == der

  test "rejects invalid P-256 public key encodings":
    expect ValueError:
      discard encodeP256ReferenceKeyDer(
        0x20000200'u32,
        newSeq[uint8](64)
      )

    var compressed = newSeq[uint8](65)
    compressed[0] = 0x02'u8
    expect ValueError:
      discard encodeP256ReferenceKeyPem(
        0x20000200'u32,
        compressed
      )
