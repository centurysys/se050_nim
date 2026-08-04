# NXP factory-provisioned Cloud Identity

SE050のvariantによっては、NXPが工場でCloud接続用の秘密鍵とX.509証明書を事前provisioningしています。

このcredentialを利用すると、ユーザーがSE050内で新しい鍵を生成してCSRを作成し、CAから証明書を発行してもらう手順を省略できます。秘密鍵はfactory provisioning時からSE050内部にあり、filesystemへexportしません。

この機能は「最短でmTLS/Cloud接続を試したい」用途を主眼とします。自社PKI、certificate rotation、複数service identity、長期的なcertificate lifecycle管理が必要な場合は、`tls-keygen`で作成するmanaged TLS identityを使用してください。

## 既知のNXP factory Cloud Object

`se050_nim`はNXP SE050 configuration資料で定義される次のCloud connection credentialを認識します。

| Kind | Identity | Key Object | Certificate Object |
|---|---:|---:|---:|
| ECC P-256 | 0 | `0xF0000100` | `0xF0000101` |
| ECC P-256 | 1 | `0xF0000102` | `0xF0000103` |
| RSA-2048 | 0 | `0xF0000110` | `0xF0000111` |
| RSA-2048 | 1 | `0xF0000112` | `0xF0000113` |

SE050のvariant/configurationによって、すべてのObjectが存在するとは限りません。まず実機で確認します。

```sh
se050ctl factory-list -b 0
```

`factory-list`は既知Objectを変更せず、存在有無と`ReadType`結果だけを表示します。NXP Attestation key/certificate (`0xF0000012` / `0xF0000013`)もあわせて表示します。

## 最短の利用例

ECC identity 0が存在する場合、certificateをPEMで取り出します。

```sh
se050ctl factory-cert \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --format pem \
  --out device.crt
```

証明書は通常のOpenSSLで確認できます。

```sh
openssl x509 \
  -in device.crt \
  -noout \
  -subject \
  -issuer \
  -serial \
  -dates
```

秘密鍵は取り出しません。NXP OpenSSL Providerへ渡すURIだけを取得します。

```sh
KEY_URI=$(se050ctl factory-key-ref --kind ecc --identity 0)
echo "$KEY_URI"
```

例:

```text
nxp:0xF0000100
```

以後はNXP OpenSSL Providerから通常のprivate-key referenceとして使用できます。

```sh
openssl pkeyutl \
  -provider /usr/local/lib/libsssProvider.so \
  -provider default \
  -inkey "$KEY_URI" \
  -sign \
  -rawin \
  -digest sha256 \
  -in test.txt \
  -out signature.der
```

## Certificate public keyの取得

factory certificateに含まれるSubjectPublicKeyInfoをDERまたはPEMで取得できます。

```sh
se050ctl factory-pubkey \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --format pem \
  --out device-public.pem
```

このcommandはSE050 private keyを読みません。factory X.509 certificateをSE050から読み出し、OpenSSL `libcrypto.so.3`でcertificateのpublic keyを抽出します。ECC/RSAの両方に使用できます。

## RSA factory identity

搭載variantでRSA credentialが存在する場合は`--kind rsa`を指定します。

```sh
se050ctl factory-cert \
  -b 0 \
  --kind rsa \
  --identity 0 \
  --out device-rsa.crt

se050ctl factory-key-ref \
  --kind rsa \
  --identity 0
```

新規設計ではP-256の方が鍵・署名・certificateを小さくでき、security strengthもRSA-2048より高いため、利用可能ならECC factory identityを優先するのが自然です。RSA credentialは既存システム互換性が必要な場合に利用できます。

## Managed TLS identityとの使い分け

### Factory identity

```text
NXP factory
   ↓
SE050
 ├─ private key
 └─ X.509 certificate
   ↓
certificateをCloudへ登録
   ↓
NXP Providerからfactory keyを参照
```

利点:

- key generation不要
- CSR不要
- private-key file不要
- 最短でmTLS/Cloud onboardingを試せる

### Managed TLS identity

```text
se050ctl tls-keygen
   ↓
SE050内部でP-256鍵生成
   ↓
CSR
   ↓
自社CA / Cloud CA
   ↓
client certificate
```

こちらは次の用途に向きます。

- 自社PKI
- certificate/key rotation
- identity番号 + A/B slot
- サービスごとの独立鍵
- certificate lifecycleを自社で管理

## 実機確認

`tools/se050_factory_identity_test.sh`は、選択したfactory identityについてcertificate取得、public key抽出、NXP OpenSSL Providerによる署名、certificate public keyによる署名検証までをまとめて実行します。

```sh
./tools/se050_factory_identity_test.sh \
  --se050ctl ./se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --kind ecc \
  --identity 0
```

この試験が`factory identity test: PASS`になれば、次を実機で確認できます。

- factory certificateをSE050 BinaryFileから取得できる
- `factory-pubkey`のSubjectPublicKeyInfoがOpenSSLでcertificateから抽出した値と一致する
- NXP Providerがfactory key Objectを`nxp:0x...` URIで使用できる
- SE050内factory private keyによる署名をfactory certificate public keyで検証できる
- private-key fileを作成していない

certificateの有効期間は表示しますが、NXP CA chain、revocation、Cloud serviceへの登録可否はこのローカル試験の対象外です。

## 注意事項

factory credentialはNXPがprovisioningしたidentityです。そのcertificate chain、validity、revocation、Cloud側での受入可否は使用前に確認してください。

`factory-list` / `factory-cert` / `factory-pubkey` / `factory-key-ref`はread-onlyです。factory Objectを生成・上書き・削除するcommandは提供しません。既存の汎用`se050ctl keygen` / `delete`も`0xF0000000..0xFFFFFFFF`を変更対象にできません。

NXP factory Objectの定義とOpenSSL利用例は以下を参照してください。

- NXP AN12436: SE050 configurations
  https://www.nxp.com/docs/en/application-note/AN12436.pdf
- NXP Tech Blog: セキュアエレメントSE05xの使用方法 : OpenSSL経由でのSE050の使用
  https://community.nxp.com/t5/NXP-Tech-Blog/セキュアエレメントSE05xの使用方法-OpenSSL経由でのSE050の使用-日本語ブログ/ba-p/2154251
