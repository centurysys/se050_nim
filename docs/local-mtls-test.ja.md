# SE050 TLS identity ローカルmTLS試験

## 目的

AWS IoT Core / Azure IoT HubなどのCloud固有要素を入れる前に、SE050内の
TLS client private keyがNXP OpenSSL Provider経由で実際のTLS client
certificate authenticationに使用できることをローカル環境だけで確認する。

この試験では、ローカルCAとTLS serverの秘密鍵は一時的なsoftware keyを使う。
検証対象のTLS client private keyだけはSE050内に保持し、host filesystemへ
出力しない。

## セキュリティ境界

本プロジェクトではHost OSをtrusted environmentとして扱い、SE050 private
keyのnon-exportabilityを主要目的とする。NXP Providerが表示するPlain
communication channel警告は、この脅威モデルの下では許容する。

Host OS侵害後のSE050不正利用防止、Platform SCP03、Access Manager、Secure
Bootなどは本試験および現在のTLS identity機能の対象外とする。

## 前提

- OpenSSL 3.x
- NXP `libsssProvider.so`
- `se050ctl`
- 既存のTLS identity key
- `EX_SSS_BOOT_SSS_PORT`でNXP ProviderからSE050へ接続可能

例:

```text
EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
Provider=/usr/local/lib/libsssProvider.so
TLS identity=test / identity 0 / slot A
Object ID=0x30000200
```

## 自動試験

`tools/se050_local_mtls_test.sh` は次を順に実行する。

1. `se050ctl tls-key-info`で対象TLS identityをAttestation付きで検証
2. `tls-key-ref`でNXP Provider URIを取得
3. 一時ローカルCAを生成
4. `localhost`用server certificateを生成
5. SE050 key + NXP Providerでclient CSRを生成
6. ローカルCAでclient certificateを発行
7. server/client certificateのEKUとchainを検証
8. `openssl s_server -Verify`でclient certificateを必須化
9. `openssl s_client`からSE050 keyを使ってTLS 1.3 mTLS接続
10. 同じ構成でTLS 1.2 mTLS接続
11. client certificateなしのTLS 1.3接続が拒否されることをnegative controlで確認

SE050のSecure Objectを作成・削除・置換する処理は行わない。

実行例:

```text
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48

./tools/se050_local_mtls_test.sh \
  --se050ctl ./se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --profile test \
  --identity 0 \
  --slot A
```

成功時の最後の出力:

```text
TLS 1.3 mutual TLS: OK
TLS 1.2 mutual TLS: OK
TLS 1.3 without client certificate: rejected (expected)
client private key: SE050 only (nxp:0x30000200)
local mutual TLS test: PASS
```

一時生成物は表示された`workdir`に残す。client certificate、CSR、CA、server
certificateおよびOpenSSLのserver/client logを確認できる。client private key
fileは生成されない。

## この試験で確認できること

- SE050 TLS identity public/private key pairがX.509 client certificateと対応する
- CSR署名がSE050で実行される
- TLS handshake中のCertificateVerify署名をNXP Provider経由でSE050が実行できる（Provider logも確認）
- TLS serverがローカルCAによるclient certificate chainを検証できる
- TLS 1.3とTLS 1.2の双方でmTLS client authenticationが成立する
- private keyをfilesystemへ配置せずにTLS client authenticationできる

## この試験で確認しないこと

- AWS IoT Core / Azure IoT Hubへの実接続
- Cloud固有MQTT設定やPolicy
- SCP03やHost authentication
- 複数processからSE050へ同時アクセスする場合の排他
- certificate rotationのA/B切替
