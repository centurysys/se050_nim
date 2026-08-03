# SE050 TLS identityでAzure IoT Hubへ接続する

更新日: 2026-08-03

この文書は、`se050_nim`でSE050内部生成したP-256 TLS client identity鍵をNXP OpenSSL Provider経由で使用し、Azure IoT HubへX.509/mTLS接続するための手順と仕様適合性をまとめる。

## 1. 検証状態

本プロジェクトでは以下を実機確認済み。

- SE050内部でP-256 key pairを生成
- TLS identity Policy `SIGN + READ + DELETE` (`0x10240000`)
- NXP Attestationによるinternal origin / Object ID / object type / Policy / public key検証
- NXP OpenSSL Provider 1.1.5から`nxp:0x...` URIで既存Objectを参照
- Provider経由ECDSA/SHA-256署名
- Provider経由CSR生成
- CSR自己署名検証
- CSR public keyとSE050 live public keyのbyte-for-byte一致
- OpenSSL TLS 1.2 / TLS 1.3でローカルmTLS成功

Azureアカウントを用いたIoT Hub実接続は未実施。この文書のAzure側手順は2026-08-03時点のMicrosoft公式仕様との照合に基づく。

## 2. 結論

現在のSE050 TLS identity実装はAzure IoT HubのX.509 client authenticationに必要な暗号処理を満たす。

Azure IoT HubはTLS handshakeでX.509 client certificateを受け取り、CAまたはcertificate thumbprintを用いてdeviceを認証する。MicrosoftはproductionではCA-signed X.509 certificateを推奨している。またdevice private keyを内部生成・保護できるHSMの使用を推奨しており、SE050の設計と整合する。

重要なAzure固有条件は、device leaf certificateのCommon Nameを登録するDevice IDと一致させること。

```text
CN = deviceId
```

これはAWSとの大きな違いで、Azure IoT Hubでは認証上の必須条件。

## 3. 推奨構成

production標準はCA-signed device certificateとする。

```text
Azure IoT Hub
      ^
      | MQTT/TLS port 8883
      | X.509 CA-signed authentication
      |
OpenSSL 3 / MQTT application
      |
NXP libsssProvider.so
      |
SE050
  TLS identity N / slot A or B
  P-256 private key (non-exportable)

filesystem:
  device certificate / intermediate chain
  Azure server trust CA bundle

external PKI / manufacturing CA:
  issuing CA private key

not on filesystem of device:
  device private key
```

Azure用に別種類のSE050 keyを作る必要はない。AWSと同じP-256 TLS identityを使用できる。

## 4. CA-signedを標準とする理由

Azure IoT Hubは次の2方式をサポートする。

- X.509 CA-signed: production推奨
- X.509 self-signed + thumbprint: 主にtest/small deployment向け

CA-signedではrootまたはintermediate CAをIoT Hubへ登録・検証し、そのCA配下のdevice certificateを認証できる。多数deviceを1台ずつthumbprint登録する必要がない。

本プロジェクトではCA-signedを標準設計とする。

Microsoft-managed PKI / Azure Device Registry連携も2026年時点で存在するがpublic previewであり、production標準にはしない。既存のthird-party/customer CA方式をbaselineとする。

## 5. SE050 TLS identityの選択

例としてproduction identity 0 / slot Aを使用する。

```sh
se050ctl tls-key-info \
  -b 0 \
  --profile production \
  --identity 0 \
  --slot A
```

Provider URI:

```sh
KEY_URI=$(se050ctl tls-key-ref \
  --profile production \
  --identity 0 \
  --slot A)
```

期待例:

```text
nxp:0x20000200
```

## 6. Azure用CSR生成

AzureではCNとDevice IDの一致が必須なので、CSR生成前にDevice IDを決定する。

```sh
DEVICE_ID=my-device-001
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
PROVIDER=/usr/local/lib/libsssProvider.so
```

CSR:

```sh
openssl req -new \
  --provider "$PROVIDER" \
  --provider default \
  -key "$KEY_URI" \
  -subj "/CN=$DEVICE_ID" \
  -out device.csr
```

確認:

```sh
openssl req -in device.csr -noout -verify
openssl req -in device.csr -noout -subject -text
```

`subject=CN = my-device-001`となっていることを必ず確認する。

## 7. CAでdevice certificateを発行

Azure IoT Hub自身へCSRを渡してleaf certificateを発行する方式をbaselineとはしない。CSRはvendor/customer/PKI providerのCAへ渡して署名する。

最低限、device certificateはTLS client authentication用途として発行する。

例としてOpenSSL CAで署名する場合、extensionは次のような方向とする。

`device-ext.cnf`:

```ini
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
```

例:

```sh
openssl x509 -req \
  -in device.csr \
  -CA issuing-ca.crt \
  -CAkey issuing-ca.key \
  -CAcreateserial \
  -days 365 \
  -sha256 \
  -extfile device-ext.cnf \
  -out device.crt
```

実製品ではCA private keyをdeviceへ置かない。製造設備、HSM、customer PKI等で管理する。

証明書を確認する。

```sh
openssl x509 -in device.crt -noout -subject -issuer -text
```

CNが`DEVICE_ID`と一致していることを再確認する。

## 8. CA certificateをIoT Hubへ登録

CA-signed authenticationを使う場合、device certificateを発行したrootまたはintermediate CA certificateをIoT Hubへ登録する。

Azure CLI例:

```sh
HUB_NAME=my-hub
CA_NAME=my-device-issuing-ca

az iot hub certificate create \
  --hub-name "$HUB_NAME" \
  --name "$CA_NAME" \
  --path issuing-ca.crt
```

通常はCA private keyの所有を証明するProof of Possessionを完了させ、CA certificateをVerified状態にする。

まず状態とETagを取得する。

```sh
az iot hub certificate show \
  --hub-name "$HUB_NAME" \
  --name "$CA_NAME"
```

未検証の場合、verification codeを生成する。

```sh
az iot hub certificate generate-verification-code \
  --hub-name "$HUB_NAME" \
  --name "$CA_NAME" \
  --etag '<ETAG>'
```

返されたverification codeをCNにしたverification certificateをCA private keyで署名し、次でuploadする。

```sh
az iot hub certificate verify \
  --hub-name "$HUB_NAME" \
  --name "$CA_NAME" \
  --path verification.pem \
  --etag '<ETAG>'
```

PoP用verification certificateの作成方法はCAの運用方式に依存するため、このprojectではCA private key管理機能を実装しない。

Azure CLIには`certificate create --verified`も存在するが、production手順では組織のPKI/ownership verification方針に従うこと。

## 9. Device Identity登録

IoT Hubにはdevice identity自体を登録する必要がある。

```sh
az iot hub device-identity create \
  --hub-name "$HUB_NAME" \
  --device-id "$DEVICE_ID" \
  --auth-method x509_ca
```

ここで登録した`DEVICE_ID`と、device leaf certificateの`CN`が一致していなければ認証できない。

## 10. Device certificate chain

CA-signed deviceは接続時にcertificate chainを提示する。

intermediate CAを使用する構成では、client certificate fileを次のように作る。

```sh
cat device.crt intermediate-ca.crt > device-chain.pem
```

root CAは通常clientが送るchainへ含めない。IoT Hub側へ登録したCA chainと整合するようPKI設計する。

## 11. IoT Hub server CA

2026-08-03時点でMicrosoftはIoT Hub clientへ次のroot CAをtrustするよう案内している。

- DigiCert Global G2 root CA
- Microsoft RSA Root CA 2017

単一server/leaf certificate pinningは避け、更新可能なroot CA bundleを使用する。

## 12. EndpointとTLS version

production baselineではclassic device endpointを使用する。

```text
<hub-name>.azure-devices.net
port 8883
TLS 1.2
```

Azure IoT Hubは2025-08-31にTLS 1.0/1.1 supportを終了しており、TLS 1.2対応が必須。

2026年7月からTLS 1.3対応device endpointがpreviewとして提供されている。

```text
<hub-name>.device.azure-devices.net
```

ただしpreviewであり、今回のproduction標準には含めない。将来GA後に評価する。

P-256 client certificateを使う場合、TLS ClientHelloの`supported_groups`にそのcurveを含める必要がある。OpenSSL 3を使用した今回のローカルTLS 1.2/1.3試験ではP-256 client certificateによるhandshakeが成立している。

## 13. TLS layerだけの接続確認

CA登録とDevice Identity登録が完了した後、MQTT applicationの前にTLS layerを確認できる。

```sh
AZURE_HOST="$HUB_NAME.azure-devices.net"

openssl s_client \
  --provider "$PROVIDER" \
  --provider default \
  -tls1_2 \
  -connect "$AZURE_HOST:8883" \
  -servername "$AZURE_HOST" \
  -cert device-chain.pem \
  -key "$KEY_URI" \
  -CAfile azure-iot-ca-bundle.pem
```

Provider logに次が出ればSE050がTLS client signatureを実行している。

```text
sssprov-flw: Performing ECDSA sign using SE05x
```

`s_client`はMQTT CONNECTを生成しないため、この確認はTLS/mTLS layerまで。

## 14. MQTT接続パラメータ

Azure IoT HubへMQTTを直接使用する場合の主要値は次の通り。

```text
host:      <hub-name>.azure-devices.net
port:      8883
TLS:       TLS 1.2
ClientId:  <device-id>
Username:  <hub-hostname>/<device-id>/?api-version=2021-04-12
Password:  なし（X.509 authentication）
cert:      device-chain.pem
key:       nxp:0x20000200 等のProvider URI
server CA: Azure IoT Hub root CA bundle
```

publish topic例:

```text
devices/<device-id>/messages/events/
```

MQTT libraryがprivate-key filenameしか受け付けない場合、そのままではProvider URIを利用できない。OpenSSL 3 Provider / OSSL_STORE URIを扱える経路を使用するか、application側でSSL_CTXへcertificateとProvider keyを設定する必要がある。

SE050 private keyをPEMへexportするfallbackは設けない。

## 15. Self-signed + thumbprint方式

少台数のtest用途では、device certificateのthumbprintを登録する`x509_thumbprint`方式も利用できる。

ただしMicrosoftはCA-signedをproduction推奨としている。本projectもproduction標準はCA-signedとする。

またAzureのself-signed device authenticationはprimary/secondary certificateによるrotationを想定している。SE050側A/B slot設計との対応は可能だが、CA-signed方式とはCloud側rotation手順が異なるため別途扱う。

## 16. certificate rotation

CA-signed構成でもSE050のA/Bを使用できる。

```text
identity 0 / slot A  現在運用
       |
       +--> slot Bへ新規key生成
              |
              +--> CN=deviceIdでCSR生成
              +--> CAで新device certificate発行
              +--> BでIoT Hub接続確認
              +--> active identityをBへ変更
              +--> A certificateを失効/運用停止
              +--> A key削除
```

IoT Hubへ登録するDevice IDは変える必要がない。同じDevice IDに対して新しいCA-signed leaf certificateへrotationできるようPKI側の失効/更新手順を設計する。

## 17. Azure要件との適合表

| Azure IoT Hub要件 | 現在の実装 | 状態 |
| --- | --- | --- |
| X.509 client authentication | X.509 + OpenSSL Provider | 適合 |
| unique device private key | identityごとのSE050 P-256 key | 適合 |
| HSM内部private key生成 | SE050 internal generation | 適合 |
| CN=deviceId | CSR生成時に指定 | 文書化済み |
| CA-signed certificate | 外部CAがCSRへ署名 | 対応可能 |
| TLS 1.2 | Provider + OpenSSL | ローカル実証済み |
| P-256 client certificate | SE050 P-256 | 適合 |
| client private key non-export | SE050 internal key | 適合 |
| certificate rotation | identityごとのA/B slot | 設計済み |
| Azure account実接続 | 未実施 | 仕様適合確認のみ |

## 18. 今回の完了境界

この文書の範囲ではAzureアカウントを使用した実接続を完了条件としない。

- SE050/OpenSSL/mTLS経路: 実機確認済み
- AzureのX.509/TLS要件: 公式仕様と照合済み
- CA登録/PoP/Device Identity/MQTT parameters: 公式仕様に基づき文書化済み
- Azure IoT Hubへの実アカウント接続: 未実施

## 19. 公式資料

- Azure IoT Hub: Authenticate identities with third-party X.509 certificates
  https://learn.microsoft.com/en-us/azure/iot-hub/authenticate-authorize-x509
- Azure IoT Hub: TLS support
  https://learn.microsoft.com/en-us/azure/iot-hub/iot-hub-tls-support
- Azure IoT Hub: Use MQTT to communicate with Azure IoT Hub
  https://learn.microsoft.com/en-us/azure/iot-hub/iot-mqtt-connect-to-iot-hub
- Azure CLI: az iot hub device-identity
  https://learn.microsoft.com/en-us/cli/azure/iot/hub/device-identity
- Azure CLI: az iot hub certificate
  https://learn.microsoft.com/en-us/cli/azure/iot/hub/certificate
- Azure IoT Hub: X.509 certificates reference
  https://learn.microsoft.com/en-us/azure/iot-hub/reference-x509-certificates
