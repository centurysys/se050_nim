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


const
  P384GeneratorPublicKeyHex =
    "04" &
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38" &
    "5502F25DBF55296C3A545E3872760AB7" &
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0" &
    "0A60B1CE1D7E819D7A431D7C90EA0E5F"

  # Fixed SEC1 DER vector for a P-384 reference key using the NIST generator as
  # its public point. The 48-byte private field follows NXP's documented
  # key-length-independent suffix layout.
  P384ReferenceDerHex =
    "3081A40201010430" &
    "10000000000000000000000000000000000000000000000000000000000000000000" &
    "7DCCBBAAA5A6B5B6A5A6B5B61000" &
    "A00706052B81040022" &
    "A164036200" &
    P384GeneratorPublicKeyHex

suite "NXP OpenSSL Provider P-384 reference keys":
  test "encodes a fixed SEC1 P-384 reference-key vector":
    let publicKey = bytesFromHex(P384GeneratorPublicKeyHex)
    let expected = bytesFromHex(P384ReferenceDerHex)
    let der = encodeP384ReferenceKeyDer(0x7DCCBBAA'u32, publicKey)

    check der.len == P384ReferenceKeyDerSize
    check der == expected

  test "keeps the Object ID 14 bytes from the end of the private field":
    let publicKey = bytesFromHex(P384GeneratorPublicKeyHex)
    let der = encodeP384ReferenceKeyDer(0x12345678'u32, publicKey)

    # P-384 SEC1 prefix is 8 bytes. The 48-byte reference value stores its
    # Object ID at private-value bytes 34..37.
    check der[42 .. 45] == @[0x12'u8, 0x34'u8, 0x56'u8, 0x78'u8]

  test "uses secp384r1 parameters and a 97-byte public point":
    let publicKey = bytesFromHex(P384GeneratorPublicKeyHex)
    let der = encodeP384ReferenceKeyDer(0x7DCCBBAA'u32, publicKey)

    check der[56 .. 64] == bytesFromHex("A00706052B81040022")
    check der[65 .. 69] == bytesFromHex("A164036200")
    check der[70 .. ^1] == publicKey

  test "PEM is canonical SEC1 with 64-character Base64 lines":
    let publicKey = bytesFromHex(P384GeneratorPublicKeyHex)
    let der = encodeP384ReferenceKeyDer(0x7DCCBBAA'u32, publicKey)
    let pem = encodeP384ReferenceKeyPem(0x7DCCBBAA'u32, publicKey)
    let lines = pem.strip().splitLines()

    check pem.endsWith("\n")
    check lines.len == 6
    check lines[0] == "-----BEGIN EC PRIVATE KEY-----"
    check lines[1].len == 64
    check lines[2].len == 64
    check lines[3].len == 64
    check lines[4].len == 32
    check lines[5] == "-----END EC PRIVATE KEY-----"

    let decoded = decodeBase64(lines[1] & lines[2] & lines[3] & lines[4])
    check decoded.ok
    check decoded.value == der

  test "rejects invalid P-384 public key encodings":
    expect ValueError:
      discard encodeP384ReferenceKeyDer(
        0x20000200'u32,
        newSeq[uint8](96)
      )

    var compressed = newSeq[uint8](97)
    compressed[0] = 0x03'u8
    expect ValueError:
      discard encodeP384ReferenceKeyPem(
        0x20000200'u32,
        compressed
      )
