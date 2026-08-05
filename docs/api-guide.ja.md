# se050_nim APIガイド

`se050_nim`は、SE050 primitive、Attestation、managed TLS identity、external key import、OpenSSL Reference Key、およびキッティングrecord/CSV検証を提供します。Firmware envelope format、HKDF/AES-GCM、firmware updaterは上位projectへ分離します。

## Entry point

```nim
import se050_nim
```

`src/se050_nim.nim`は次をre-exportします。

```text
errors, transport, apdu, tlv
uid, random, objects, keys, management
binary_encoding, crypto_verify, x509_verify
factory_identity, attestation, tls, kitting
```

`tls`はさらに`profile`, `live_identity`, `attestation_verify`, `external_key`, `openssl`, `reference_key`, `reference_key_file`をexportします。

## Result形式

通常のruntime errorは`SE[T]`で返します。

```nim
let uid = se.readUidHex()
if not uid.ok:
  echo uid.error.errorMessage()
  quit 1
```

`Se050Error.sw != 0`ならAPDU status word由来です。Host-side input validationの一部は`ValueError`を使うpure encoder/helperもあります。

## Transport / device primitive

```nim
let se = openSe050(bus = 0, address = 0x48'u8, debug = false)
discard se.requestAtr()
```

主なAPI:

- `selectApplet()` / `requestAtr()`
- `readUidRaw()` / `readUidHex()`
- `getRandomBytes()` / `getRandomHex()`
- `getVersionInfo()`
- `objectExists()` / `readObjectType()` / `readObjectSize()` / `listObjectIds()`
- `deleteSecureObject()`

Raw library APIには`se050ctl`のObject-range mutation guardはありません。上位provisioning layerが対象Object IDを制限してください。

## EC key API

Managed curve enum:

```nim
ecCurveP256
ecCurveX25519
ecCurveP384
```

主なlow-level API:

```nim
se.generateP256KeyPair(objectId, policy)
se.importP256KeyPair(objectId, privateScalar, publicKey, policy)
se.importP384KeyPair(objectId, privateScalar, publicKey, policy)
se.readPublicKey(objectId)
se.deriveSharedSecret(objectId, peerPublicKey)
```

P-256 private scalar/public pointは32/65 bytes、P-384は48/97 bytesです。P-256/P-384 public pointはuncompressed `0x04 || X || Y`です。

`importP256KeyPair()` / `importP384KeyPair()`はlow-level WriteECKey primitiveで、managed slot ownership、certificate match、curve state、origin validationは行いません。TLS用途では後述の`importP256TlsIdentity()` / `importP384TlsIdentity()`を使用してください。

## Sensitive memory / transport

`secure_memory.nim`は`secureZero()`を提供し、mutable string/seq/fixed array等をvolatile write loopでclearします。

ECDH shared secretやexternal key importのAPDUは`sensitive` transport pathを使い、debugでもraw T=1 TX/RX frameを表示しません。temporary APDU/frame/private-key bufferは処理後にclearします。

## EC curve management

`ReadECCurveList`関連:

- `readEcCurveList()`
- `ecCurveSetState()`
- `isEcCurveInstantiated()`
- `ecCurveName()`

このstateは現在のWeierstrass curve instantiationであり、silicon capabilityではありません。

P-384 provisioning:

- `buildCreateEcCurveApdu()`
- `buildSetEcCurveParamApdu()`
- `buildDeleteEcCurveApdu()`
- `buildNistP384ProvisioningApdus()`
- `provisionNistP384Curve()`

`provisionNistP384Curve()`はstandard secp384r1 A/B/G/N/PRIMEを使用し、既にsetならno-opです。Create成功後のparameter設定/final verification failureではbest-effort delete rollbackを行います。

## TLS identity profile

```nim
let p256 = testTlsIdentityProfile(0'u16, tisSlotA)
let p384 = testTlsIdentityProfile(0'u16, tisSlotB, ecCurveP384)
```

`TlsIdentityProfile`はprofile kind、identity number、A/B slot、Object ID、curveを保持します。Object IDはcurveをencodeしないため、non-default curveはprofile metadataとして明示的に保持します。

Object ID規則:

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
```

`profile.isValid()`が受け付けるmanaged TLS curveは現在P-256/P-384です。TLS Policyは`0x10240000` (`SIGN + READ + DELETE`)です。

## Internal / imported TLS identity validation

内部生成と外部importはorigin semanticsを混ぜません。

- `inspectTlsIdentity()`: `origin = internal`を要求
- `inspectImportedTlsIdentity()`: `origin = external`を要求
- `verifyTlsIdentityAttestationSemantics()`
- `verifyImportedTlsIdentityAttestationSemantics()`

curveごとにexpected key-pair type、private size、public point lengthを検証し、さらにpersistent、Object ID、Policy、Attestation certificate/signature、live/attested public key一致を確認します。

## External private-key parser / certificate match

`tls/external_key.nim`はOpenSSL 3 decoderを使い、real private keyをSE050へ書く前にhost-side validationを完了します。

主なAPI:

- `parseEcPrivateKey()` — P-256/P-384/P-521をrecognizeしpublic metadataを返す
- `parseP256PrivateKey()`
- `parseP384PrivateKey()`
- `validateP256PrivateKeyCertificateMatch()`
- `validateP384PrivateKeyCertificateMatch()`
- `importP256TlsIdentity()`
- `importP384TlsIdentity()`

public parse resultはcurve、bits、group name、uncompressed public point、SPKI DERを保持します。private scalarはpublic APIへ返しません。import workflow内部でfixed-width scalarを取り出し、WriteECKey後にclearします。

Managed importの順序:

```text
profile validation
-> private key decode/curve validation
-> certificate/public-key match
-> P-384 curve state check
-> target slot empty check
-> private scalar extraction
-> sensitive WriteECKey
-> imported-origin live Attestation validation
-> source/live public-key equality
```

既存Objectを上書きしません。新規import後のvalidation failureでは、このworkflow自身が作成したObjectだけをbest-effort rollbackします。

## OpenSSL public-key helpers

- `p256PublicKeyToSpkiDer()`
- `p384PublicKeyToSpkiDer()`
- `ecPublicKeyToSpkiDer()`
- `opensslProviderKeyUri()`

SPKI DERはcertificate/CSR public keyとのbyte比較に使用できます。

## NXP Reference Key

Pure encoder:

- `encodeP256ReferenceKeyDer()` / `encodeP256ReferenceKeyPem()`
- `encodeP384ReferenceKeyDer()` / `encodeP384ReferenceKeyPem()`

Reference Keyには実private scalarを含みません。SEC1 privateKey fieldへObject ID + NXP magic/class/indexをkey-widthに合わせてencodeします。

File API:

- `writeP256ReferenceKeyFile()`
- `writeP384ReferenceKeyFile()`
- `writeTlsReferenceKeyFile()` — internal origin
- `writeImportedTlsReferenceKeyFile()` — external origin

live TLS identityを検証してから、0600・atomic・non-overwriteでPEMをinstallします。

## OpenSSL host verification

実行時にOpenSSL 3 `libcrypto.so.3`を動的loadします。共通FFIは`openssl_ffi.nim`へ集約されています。

主な用途:

- SHA-256 / certificate fingerprint
- ECDSA verification
- X.509 parse / chain verification
- certificate public-key extraction/comparison
- OpenSSL 3 `OSSL_DECODER`によるexternal private-key decode

C headerやOpenSSL development symlinkはruntimeには不要です。

## Attestation / Trust Store

主なAPI:

- `readAttestationCertificate()`
- `readObjectWithAttestation()`
- `verifyAttestationSignature()`
- embedded NXP Root/Intermediate trust helpers

TLS/kittingとも、certificate chainとsignatureを検証したうえでsigned Object ID/type/origin/Policy等のsemanticsを評価します。

## Kitting

既存kitting APIは引き続きP-256 firmware KEX用です。

主なlayer:

```text
board serial / profile
-> freshness
-> attested record
-> CSV encode/decode
-> offline certificate/signature/semantic verification
-> local board/SE050/live-object comparison
```

代表API:

- `testKittingProfile()` / `productionKittingProfile()`
- `deriveKittingFreshness()`
- `createKittingRecord()`
- `encodeKittingCsv()` / `decodeKittingCsv()`
- `verifyKittingRecord()` / `verifyKittingCsvRecord()`
- `verifyLocalKittingIdentity()`
- `mergeKittingRecord()`

## 推奨layering

```text
se050_nim:
  SE050 primitive
  + Attestation
  + managed TLS identity / external key import
  + OpenSSL Reference Key
  + reusable kitting verification

se050ctl:
  diagnostic / explicit provisioning CLI
  + curve state/provisioning
  + TLS import/reference-key tooling

NXP OpenSSL Provider:
  OpenSSL runtime -> SE050 private-key operation boundary

ordinary application:
  normal certificate/key/CA filenames only

fwkeys / fw-envelope:
  P-256 ECDH + HKDF + AES-GCM envelope
```
