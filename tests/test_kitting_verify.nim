import std/strutils
import std/unittest

import se050_nim

const
  RootCertificateHex = "308201a130820148a003020102020203e9300a06082a8648ce3d04030230253123302106035504030c1a5345303530206b697474696e67207465737420726f6f742076333020170d3230303130313030303030305a180f32313230303130313030303030305a30253123302106035504030c1a5345303530206b697474696e67207465737420726f6f742076333059301306072a8648ce3d020106082a8648ce3d03010703420004156236fd39ecc492a0789a61cf254812f0015581f19ca5ac698ed739beffb33a8944e8540f0f18f0106d8331f03193f067410d1ca79a6c944a9fad66f94fe913a366306430120603551d130101ff040830060101ff020101301d0603551d0e0416041491d127a3faed05abd5727d9de59628f07ae5bca4301f0603551d2304183016801491d127a3faed05abd5727d9de59628f07ae5bca4300e0603551d0f0101ff040403020106300a06082a8648ce3d040302034700304402203902c7baff93f90b877f3771ce4767983c62409558c3c4991acb491e389e0f8d02206dbb42fc7435b8962e680db51ccca58471132005371d314aa2af4e714e02804c"
  IntermediateCertificateHex = "308201ab30820150a003020102020203ea300a06082a8648ce3d04030230253123302106035504030c1a5345303530206b697474696e67207465737420726f6f742076333020170d3230303130313030303030305a180f32313230303130313030303030305a302d312b302906035504030c225345303530206b697474696e67207465737420696e7465726d6564696174652076333059301306072a8648ce3d020106082a8648ce3d030107034200043978669afea3242d00be88ffbcb38dbb03bda240555e09db0970d6637b1c6bdeb24f84a5739f37635056fdc78e0afa75715f60b117fa8b71c81a55f5b71a02b3a366306430120603551d130101ff040830060101ff020100301d0603551d0e04160414afb8a30281d950e7fbef75de3fd5bb7ad56d5135301f0603551d2304183016801491d127a3faed05abd5727d9de59628f07ae5bca4300e0603551d0f0101ff040403020106300a06082a8648ce3d0403020349003046022100b455a9bd11a71d5047c305d50557cc10406d6e2f78d8d7ff98b544dcb0f43877022100f0e1f24796a462c3803521f04dd034af7e561d99d94b99a0e9430b229586e5fd"
  DeviceCertificateHex = "308201a63082014ca003020102020203eb300a06082a8648ce3d040302302d312b302906035504030c225345303530206b697474696e67207465737420696e7465726d6564696174652076333020170d3230303130313030303030305a180f32313230303130313030303030305a30273125302306035504030c1c5345303530206b697474696e672074657374206465766963652076333059301306072a8648ce3d020106082a8648ce3d0301070342000485c1ae852c4fd381a753cfee18fd949d7f3abd06b06fb747339bd1ef147a69e8b645c0bc43f4eb77408ff9888287d221f4bd32db707706525b0d832fb54932e2a360305e300c0603551d130101ff04023000301d0603551d0e04160414dd1ea1793340f754e590970f8601b73105f4bda9301f0603551d23041830168014afb8a30281d950e7fbef75de3fd5bb7ad56d5135300e0603551d0f0101ff040403020780300a06082a8648ce3d0403020348003045022100ce63491167b3291b185e83920be3e91c26956d84da855df4eeed57c9d141bea702200107f89f747962fe4c4e1b1839ffae8846006e84cd565c357ee8f06220c9e35e"
  WrongRootCertificateHex = "3082018e30820134a003020102020207d1300a06082a8648ce3d040302301b3119301706035504030c1053453035302077726f6e6720726f6f743020170d3230303130313030303030305a180f32313230303130313030303030305a301b3119301706035504030c1053453035302077726f6e6720726f6f743059301306072a8648ce3d020106082a8648ce3d03010703420004e0c33f2b26e755776900c58cc17e17cab4100ac8674d8411e2001053cc819ee91172dd5758c01b2a6c3941adf741a9c3e910e1170c7b0b31142e1bf93505878da366306430120603551d130101ff040830060101ff020101301d0603551d0e041604143cbf7ae08eff1e22c69eb7bca49cf23c9d3c17f3301f0603551d230418301680143cbf7ae08eff1e22c69eb7bca49cf23c9d3c17f3300e0603551d0f0101ff040403020186300a06082a8648ce3d0403020348003045022100f5ada7128c2b213736817b1a81c4dbb031f5e42c8c06e5ba27a20dad7bba52d90220664310a37f5eb9ec762fd2fd5aa52d55db2ffe289357f759bd8813ed78aa280c"
  TargetPublicKeyHex = "040ba846f162b1d4ee4aef1f71552d221aab55b1a16a4322192d338971d928a41d90aa3835d2fae33585c82d4a8d63811b4fa2e64a46a93bd132c3cb2b7c2035fe"
  UidHex = "202122232425262728292a2b2c2d2e2f3031"
  NonceHex = "000102030405060708090a0b0c0d0e0f"
  ContainerHex = "5335415400010028000000d1802200000000214104300001004504f000001246012147106d11001bf1a8796320a25c157677836b4141040ba846f162b1d4ee4aef1f71552d221aab55b1a16a4322192d338971d928a41d90aa3835d2fae33585c82d4a8d63811b4fa2e64a46a93bd132c3cb2b7c2035fe4212202122232425262728292a2b2c2d2e2f3031431c30000100290100000000000000000800000000042400000200000000440200204f0c00000003000000000000f23552483046022100ecde9deceaf7c71222ce08ca0f958df144ed8a7c1b9e570ce13342c2514e5ca8022100efe81f71da1b3a0ed1b34e06cb66f069e7d355aad9a62df67f2e7a1cd4d6947a"
  BadPolicyContainerHex = "5335415400010028000000cf802200000000214104300001004504f000001246012147106d11001bf1a8796320a25c157677836b4141040ba846f162b1d4ee4aef1f71552d221aab55b1a16a4322192d338971d928a41d90aa3835d2fae33585c82d4a8d63811b4fa2e64a46a93bd132c3cb2b7c2035fe4212202122232425262728292a2b2c2d2e2f3031431c30000100290100000000000000000800000000043c00000200000000440200204f0c00000003000000000000f23552463044022019f055562e444c0d4fb4fd2e60debc6b0ff1363e1540a95177909298a98238cd022075044fff8aa7f7755c4db7bc55abac2be1a3ae2d18ec4d6d4e9750bc253e496b"

proc hexBytes(text: string): seq[uint8] =
  let compact = text.strip()
  doAssert (compact.len mod 2) == 0

  result = newSeq[uint8](compact.len div 2)
  for index in 0 ..< result.len:
    result[index] = uint8(parseHexInt(compact[index * 2 .. index * 2 + 1]))

proc validRecord(): KittingRecord =
  result = KittingRecord(
    serialNumber: "11900000014",
    formatVersion: KittingCsvFormatVersion,
    profileKind: kpTest,
    createdAt: "2026-07-29T08:00:00Z",
    keyRole: KittingKeyRoleFirmwareKex,
    se050Uid: hexBytes(UidHex),
    keyObjectId: KittingTestFirmwareKexObjectId,
    nonce: hexBytes(NonceHex),
    publicKey: hexBytes(TargetPublicKeyHex),
    attestationCertificate: hexBytes(DeviceCertificateHex),
    attestationContainer: hexBytes(ContainerHex)
  )

suite "offline kitting record verification":
  let root = hexBytes(RootCertificateHex)
  let intermediate = hexBytes(IntermediateCertificateHex)
  let wrongRoot = hexBytes(WrongRootCertificateHex)

  test "accepts a fully trusted test-profile record":
    let verified = verifyKittingRecord(
      validRecord(),
      @[root],
      @[intermediate]
    )

    require verified.ok
    check verified.value.record.serialNumber == "11900000014"
    check verified.value.record.publicKey == hexBytes(TargetPublicKeyHex)
    check verified.value.certificateChain.trustAnchorCount == 1
    check verified.value.certificateChain.intermediateCount == 1
    check verified.value.semantics.profile.kind == kpTest
    check verified.value.semantics.attributes.origin ==
      Se050ObjectOriginInternal

  test "selects and verifies one record from a multi-device CSV":
    let csv = encodeKittingCsv(@[validRecord()])
    let verified = verifyKittingCsvRecord(
      csvText = csv,
      serialNumber = "11900000014",
      profileKind = kpTest,
      trustAnchorsDer = @[root],
      intermediatesDer = @[intermediate]
    )

    require verified.ok
    check verified.value.record.keyObjectId ==
      KittingTestFirmwareKexObjectId

  test "rejects a missing serial number":
    let csv = encodeKittingCsv(@[validRecord()])
    let verified = verifyKittingCsvRecord(
      csvText = csv,
      serialNumber = "11900000015",
      profileKind = kpTest,
      trustAnchorsDer = @[root],
      intermediatesDer = @[intermediate]
    )

    require not verified.ok
    check verified.error.message.contains("kitting CSV selection")

  test "rejects an untrusted device certificate":
    let verified = verifyKittingRecord(
      validRecord(),
      @[wrongRoot],
      @[intermediate]
    )

    require not verified.ok
    check verified.error.kind == seCertificateUntrusted
    check verified.error.message.contains("kitting certificate chain")

  test "rejects a modified attestation signature":
    var record = validRecord()
    record.attestationContainer[^1] =
      record.attestationContainer[^1] xor 0x01'u8

    let verified = verifyKittingRecord(
      record,
      @[root],
      @[intermediate]
    )

    require not verified.ok
    check verified.error.kind == seSignatureInvalid
    check verified.error.message.contains("kitting attestation signature")

  test "rejects a correctly signed generic development policy":
    var record = validRecord()
    record.attestationContainer = hexBytes(BadPolicyContainerHex)

    let verified = verifyKittingRecord(
      record,
      @[root],
      @[intermediate]
    )

    require not verified.ok
    check verified.error.kind == seKittingValidationFailed
    check verified.error.message.contains("generic development policy")

  test "rejects metadata that no longer matches the signed command":
    var record = validRecord()
    record.serialNumber = "11900000015"

    let verified = verifyKittingRecord(
      record,
      @[root],
      @[intermediate]
    )

    require not verified.ok
    check verified.error.message.contains("kitting record structure")
