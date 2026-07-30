# se050_nim APIガイド

`se050_nim`は、SE050 primitive、Attestation検証、キッティングrecord/CSV検証を提供します。Firmware envelope format、HKDF/AES-GCM、firmware updaterは上位projectへ分離します。

## Entry point

```nim
import se050_nim
```

トップレベルは次の機能群をre-exportします。

- `errors`, `transport`, `apdu`, `tlv`
- `uid`, `random`, `objects`, `keys`, `management`
- `attestation_cert`, `attestation`
- `crypto_verify`, `x509_verify`, `trust_store`
- `attestation_verify`, `attestation_attributes`, `kitting_attestation_verify`
- `binary_encoding`, `board_identity`
- `kitting_profile`, `kitting_record`, `kitting_csv`
- `kitting_verify`, `kitting_local_verify`, `kitting_export`

## Result形式

通常のエラーは例外ではなく`SE[T]`で返します。

```nim
let r = se.readUidHex()
if not r.ok:
  echo r.error.errorMessage()
  quit 1

echo r.value
```

`Se050Error.sw`が0以外ならAPDU status word由来です。

## Device / primitive

```nim
let se = openSe050(bus = 0, address = 0x48'u8, debug = false)
let atr = se.requestAtr()
let uid = se.readUidRaw()
let random = se.getRandomBytes(32)
```

主なAPI:

- `selectApplet()` / `requestAtr()`
- `readUidRaw()` / `readUidHex()`
- `getRandomBytes()` / `getRandomHex()`
- `getVersionInfo()`
- `objectExists()` / `readObjectType()` / `readObjectSize()` / `listObjectIds()`
- `deleteSecureObject()`

Raw APIには`se050ctl`のdev-range safety guardはありません。上位toolがObject ID policyを強制してください。

## EC key API

```nim
let created = se.generateP256KeyPair(
  0x30000120'u32,
  developmentEcKeyPolicy()
)
let publicKey = se.readPublicKey(0x30000120'u32)
let secret = se.deriveSharedSecret(0x30000120'u32, peerPublicKey)
```

Curve:

- `ecCurveP256`
- `ecCurveX25519`

Policy helper:

| API | Header | 用途 |
|---|---:|---|
| `developmentEcKeyPolicy()` | `0x043C0000` | 汎用development |
| `testDeviceKeyPolicy()` | `0x04240000` | 削除可能なproduction相当test |
| `deviceEcKeyPolicy()` | `0x04200000` | provision済みdevice key |
| `oneTimeDeviceKeyPolicy()` | `0x04200000` | one-time作成意図 |
| `customEcKeyPolicy()` | caller-defined | advanced use |

P-256公開鍵は65 bytes、shared secretは32 bytesです。

## Attestation certificate

```nim
let cert = se.readAttestationCertificate()
```

主なAPI:

- `readAttestationCertificate()`
- `extractAttestationCertificateDer()`
- `validateAttestationCertificateDer()`

`0xF0000013`のBinaryFile全体を読み、先頭DER SEQUENCEを返します。末尾のゼロ埋めは許可し、非ゼロtailは拒否します。

## ReadObject-with-Attestation

```nim
let attested = se.readObjectWithAttestation(
  objectId = 0x30000100'u32,
  freshness = freshness
)
```

主なAPI:

- `buildReadObjectWithAttestationRequest()`
- `parseReadObjectWithAttestationResponse()`
- `readObjectWithAttestation()`

`AttestedObjectRead`は署名対象command、送信APDU、raw response、object data、attributes、chip UID、timestamp、signatureを保持します。

## OpenSSL host verification

実行時にOpenSSL 3 `libcrypto.so.3`を動的loadします。

主なAPI:

- `sha256()`
- `certificateSha256()`
- `extractCertificateEcPublicKey()`
- `verifyEcdsaSha256WithCertificate()`
- `verifyCertificateChain()`
- `splitDerCertificateBundle()`
- `readDerCertificateBundleFile()`

C headerやOpenSSL development symlinkは不要です。

## Embedded NXP Trust Store

```nim
let roots = nxpAttestationTrustAnchors()
let intermediates = nxpAttestationIntermediates()
```

関連API:

- `nxpAttestationRootDer()`
- `nxpAttestationIntermediateDer()`
- `nxpAttestationTrustAnchors()`
- `nxpAttestationIntermediates()`

DERは`src/se050_nim/certs/`から`staticRead()`で組み込みます。

## Attestation signature / semantics

```nim
let signature = verifyAttestationSignature(attested, cert)
let semantics = verifyKittingAttestationSemantics(
  attested,
  testKittingProfile()
)
```

`verifyKittingAttestationSemantics()`はsigned fieldについて次を確認します。

- configured Object ID
- Attestation key ID `0xF0000012`
- ECDSA/SHA-256 algorithm
- 完全な65-byte P-256公開鍵
- SE050 UID、timestamp、private key size
- P-256 key-pair type
- internal origin
- owner/auth object
- exactly one Policyとexpected header

証明書chainと署名検証を先に成功させてからsemanticsを信頼してください。

## Board identity / Profile

```nim
let serial = readBoardSerialNumber()
let testProfile = testKittingProfile()
let productionProfile = productionKittingProfile()
```

主なAPI:

- `parseBoardSerialNumber()`
- `readBoardSerialNumber()`
- `kittingProfile()` / `kittingProfileForName()` / `kittingProfileForObjectId()`
- `keyPolicy()` / `expectedKeyType()` / `isDeletable()`

Board serial default pathは`/proc/device-tree/board/serialno`です。

## Kitting record / freshness

```nim
let freshness = deriveKittingFreshness(
  serialNumber,
  createdAt,
  testProfile,
  nonce
)
```

主なAPI:

- `validateKittingTimestamp()`
- `deriveKittingFreshness()`
- `createKittingRecord()`
- `encodeAttestationContainer()` / `decodeAttestationContainer()`
- `restoreKittingAttestation()`

`KittingRecord`はserial、format version、profile、UTC時刻、key role、SE050 UID、Object ID、nonce、公開鍵、個体証明書、Attestation containerを保持します。

## CSV

```nim
let text = encodeKittingCsv(records)
let records = decodeKittingCsv(text)
let one = findKittingRecord(
  records.value,
  serialNumber,
  kpTest
)
```

API:

- `encodeKittingCsv()`
- `decodeKittingCsv()`
- `findKittingRecord()`
- `KittingCsvHeader`

Binary fieldはstrict Base64です。Record selectionはserial/profile/key roleでexactly oneを要求します。

## Offline verification

```nim
let verified = verifyKittingCsvRecord(
  csvText = csvText,
  serialNumber = "11900000015",
  profileKind = kpTest,
  trustAnchorsDer = nxpAttestationTrustAnchors(),
  intermediatesDer = nxpAttestationIntermediates()
)
```

API:

- `verifyKittingRecord()`
- `verifyKittingCsvRecord()`
- `VerifiedKittingRecord`

これはI2Cへアクセスせず、record復元、freshness、証明書chain、Attestation署名、signed semanticsを検証します。将来のPC importer/DB登録処理から再利用できます。

## Local-device verification

```nim
let local = verifyLocalKittingIdentity(
  verified = verified.value,
  boardSerialNumber = serial,
  liveSe050Uid = uid,
  liveObjectType = objectType,
  liveTransientIndicator = persistence,
  livePublicKey = publicKey
)
```

オフライン検証済みrecordを、現在の基板serial、SE050 UID、P-256 object type、persistent属性、公開鍵と比較します。I2C read自体はCLI/呼び出し側で行い、このAPIはpure comparisonとしてunit test可能です。

## Exporter merge helper

- `sameKittingRecordKey()`
- `sameKittingDeviceKey()`
- `mergeKittingRecord()`

論理キー`serial + profile + role`が同じでUID/Object ID/public keyが異なるrecordは競合として拒否します。

## 推奨layering

```text
se050_nim:
  SE050 primitive + Attestation + reusable kitting verification

se050ctl:
  development/diagnostic CLI + local kitting verification

se050-kitting-export:
  current test factory exporter

future production kitting:
  irreversible customer-range key creation

fwkeys / fw-envelope:
  P-256 ECDH + HKDF + AES-GCM envelope

fw-update:
  firmware verification, decryption, A/B update
```
