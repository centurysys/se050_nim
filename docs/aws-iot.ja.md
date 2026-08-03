# SE050 TLS identityでAWS IoT Coreへ接続する

更新日: 2026-08-03

この文書は、`se050_nim`でSE050内部生成したP-256 TLS client identity鍵をNXP OpenSSL Provider経由で使用し、AWS IoT CoreへX.509/mTLS接続するための手順と仕様適合性をまとめる。

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

AWSアカウントを用いたAWS IoT Core実接続は未実施。この文書のAWS側手順は2026-08-03時点のAWS公式仕様との照合に基づく。

## 2. 結論

現在のSE050 TLS identity実装はAWS IoT CoreのX.509 client authentication要件を満たす。

AWS IoT CoreはCSRの公開鍵としてECC NIST P-256/P-384/P-521を受け付け、P-256 client certificateをTLS 1.2 / TLS 1.3でサポートする。`se050_nim`が使用するNIST P-256はこの条件に一致する。

AWS IoT CoreはTLS client authentication時に、client certificate内の公開鍵に対応するprivate keyの所有をTLS署名で確認する。今回のローカルmTLS試験では、同じOpenSSL Provider経路でTLS 1.2 / TLS 1.3のclient authentication署名をSE050に実行させるところまで確認済み。

## 3. 推奨構成

```text
AWS IoT Core
     ^
     | MQTT/TLS port 8883
     | X.509 client authentication
     |
OpenSSL 3 / MQTT application
     |
NXP libsssProvider.so
     |
SE050
  TLS identity N / slot A or B
  P-256 private key (non-exportable)

filesystem:
  AWS-issued client certificate
  AWS server trust CA bundle

not on filesystem:
  client private key
```

AWS固有情報はSE050 Objectへ入れない。Thing名、endpoint、IoT Policy、MQTT topic等は上位アプリケーション設定として管理する。

## 4. AWS側で必要なもの

- AWS account / Region
- AWS IoT Thing（通常は作成を推奨）
- AWS IoT Policy
- AWS IoT certificate
- account固有の`iot:Data-ATS` endpoint
- server authentication用CA bundle

SE050 private keyをAWSへuploadする必要はない。AWSへ送るのはCSRだけでよい。

## 5. SE050 TLS identityの選択

例としてproduction identity 0 / slot Aを使用する。

```sh
se050ctl tls-key-info \
  -b 0 \
  --profile production \
  --identity 0 \
  --slot A
```

Provider URIを取得する。

```sh
KEY_URI=$(se050ctl tls-key-ref \
  --profile production \
  --identity 0 \
  --slot A)

echo "$KEY_URI"
```

期待例:

```text
nxp:0x20000200
```

## 6. CSR生成

Providerを設定する。

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
PROVIDER=/usr/local/lib/libsssProvider.so
```

CSRを生成する。

```sh
THING_NAME=my-device-001

openssl req -new \
  --provider "$PROVIDER" \
  --provider default \
  -key "$KEY_URI" \
  -subj "/CN=$THING_NAME" \
  -out device.csr
```

AWS IoT CoreではCSRのCNをThing名と一致させること自体は必須要件ではない。ここでは運用上分かりやすくするためThing名をCNに使用している。

CSRを確認する。

```sh
openssl req -in device.csr -noout -verify
openssl req -in device.csr -noout -text
```

## 7. AWS IoT certificate発行

AWS IoT Coreは`CreateCertificateFromCsr`でCSRからclient certificateを発行できる。このAPIはNIST P-256公開鍵を正式にサポートする。

AWS CLI例:

```sh
aws iot create-certificate-from-csr \
  --certificate-signing-request file://device.csr \
  --set-as-active \
  --certificate-pem-outfile device.crt \
  > certificate.json
```

`certificate.json`には`certificateArn`と`certificateId`が含まれる。private keyは返されない。

```sh
CERT_ARN=$(jq -r .certificateArn certificate.json)
CERT_ID=$(jq -r .certificateId certificate.json)
```

同じCSRを再送すると別certificateが発行されるため、retry時に重複発行しないよう製造処理側で管理する。

## 8. Thing作成

既存Thingを使用しない場合:

```sh
aws iot create-thing --thing-name "$THING_NAME"
```

AWS IoTにおいてcertificateとThingの関連付けはTLS client authenticationそのものの必須条件ではないが、device registry、Thing policy variables、運用管理のため通常は関連付ける。

```sh
aws iot attach-thing-principal \
  --thing-name "$THING_NAME" \
  --principal "$CERT_ARN"
```

## 9. IoT Policy

Certificateを認証に使用するだけではpublish/subscribe権限は付与されない。AWS IoT Policyをcertificateへattachする必要がある。

以下は特定Thing/client IDと特定topicだけを許可する最小例。

`iot-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iot:Connect",
      "Resource": "arn:aws:iot:REGION:ACCOUNT_ID:client/my-device-001"
    },
    {
      "Effect": "Allow",
      "Action": ["iot:Publish", "iot:Receive"],
      "Resource": "arn:aws:iot:REGION:ACCOUNT_ID:topic/devices/my-device-001/*"
    },
    {
      "Effect": "Allow",
      "Action": "iot:Subscribe",
      "Resource": "arn:aws:iot:REGION:ACCOUNT_ID:topicfilter/devices/my-device-001/*"
    }
  ]
}
```

作成・attach:

```sh
POLICY_NAME=se050-device-policy

aws iot create-policy \
  --policy-name "$POLICY_NAME" \
  --policy-document file://iot-policy.json

aws iot attach-policy \
  --policy-name "$POLICY_NAME" \
  --target "$CERT_ARN"
```

実製品ではtopic設計に合わせてResourceを絞ること。開発用であっても恒久的な`iot:*` / `*` policyは避ける。

## 10. ATS endpoint取得

AWSは`iot:Data-ATS` endpointの使用を推奨している。

```sh
AWS_IOT_ENDPOINT=$(aws iot describe-endpoint \
  --endpoint-type iot:Data-ATS \
  --query endpointAddress \
  --output text)

echo "$AWS_IOT_ENDPOINT"
```

例:

```text
abcdefghijk-ats.iot.ap-northeast-1.amazonaws.com
```

MQTT + X.509 client certificateの標準portは8883。port 443も利用できるがALPN `x-amzn-mqtt-ca`が必要になるため、最初の実装では8883を推奨する。

AWS IoT MQTT clientはSNIを送信する必要がある。通常のOpenSSL/libssl clientでhostnameを正しく設定すれば満たせる。

## 11. Server CA

ATS endpointではAmazon Trust Servicesのserver certificateが使われる。AWSは対応するAmazon Root CAをdevice trust storeへ搭載することを推奨している。

現在のAWS資料では主に以下が示されている。

- Amazon Root CA 1: RSA 2048
- Amazon Root CA 3: ECC P-256

将来のCA rotationへ対応できるよう、単一leaf/server certificateのpinningではなく更新可能なCA bundleとして管理する。

## 12. TLS layerだけの接続確認

AWS accountへcertificate登録後、MQTT applicationを作る前にTLS authenticationだけを切り分ける場合:

```sh
openssl s_client \
  --provider "$PROVIDER" \
  --provider default \
  -connect "$AWS_IOT_ENDPOINT:8883" \
  -servername "$AWS_IOT_ENDPOINT" \
  -cert device.crt \
  -key "$KEY_URI" \
  -CAfile aws-iot-ca-bundle.pem
```

TLS handshake中にNXP Providerから次のログが出れば、client CertificateVerify署名にSE050が使用されている。

```text
sssprov-flw: Performing ECDSA sign using SE05x
```

`s_client`はMQTT CONNECT packetを生成しないため、これはTLS/mTLS layerの確認でありMQTT protocolの接続確認ではない。

## 13. MQTT application設定

実際のMQTT clientでは最低限以下を指定する。

```text
host:        <iot:Data-ATS endpoint>
port:        8883
client ID:   Thing名（policy設計に合わせる）
client cert: device.crt
private key: nxp:0x20000200 等のProvider URI
server CA:   AWS ATS用trust bundle
username:    通常不要
password:    通常不要
```

MQTT libraryがprivate-key filenameしか受け付けない場合、そのままではProvider URIを利用できない。OpenSSL 3 Provider / OSSL_STORE URIを扱える経路を使用するか、application側でSSL_CTXへcertificateとProvider keyを設定する必要がある。

SE050 private keyをPEMへexportするfallbackは設けない。

## 14. certificate rotation

本プロジェクトのidentity A/B設計をそのまま使用できる。

```text
identity 0 / slot A  現在運用
       |
       +--> slot Bへ新規key生成
              |
              +--> BのCSRをAWSへ送信
              +--> 新certificate発行
              +--> Bで接続確認
              +--> active identityをBへ変更
              +--> A certificateをdeactivate/revoke
              +--> A key削除
```

AWSはdevice/clientごとにunique certificateを持ち、certificateをrotationできることを推奨しているため、このA/B設計と整合する。

## 15. AWS要件との適合表

| AWS IoT Core要件 | 現在の実装 | 状態 |
| --- | --- | --- |
| X.509 client authentication | X.509 + OpenSSL Provider | 適合 |
| CSR ECC NIST P-256 | SE050 P-256 | 適合 |
| private-key proof-of-possession | SE050 ECDSA SIGN | ローカルmTLS実証済み |
| TLS 1.2 | Provider + OpenSSL | ローカル実証済み |
| TLS 1.3 | Provider + OpenSSL | ローカル実証済み |
| client private key non-export | SE050 internal key | 適合 |
| certificate rotation | identityごとのA/B slot | 設計済み |
| AWS account実接続 | 未実施 | 仕様適合確認のみ |

## 16. 今回の完了境界

この文書の範囲では、AWSアカウントを使用した実接続を完了条件としない。

完了判断は次の通り。

- SE050/OpenSSL/mTLS経路: 実機確認済み
- AWSのP-256/X.509/TLS要件: 公式仕様と照合済み
- AWS certificate発行/Thing/Policy/endpoint手順: 公式CLI/API仕様に基づき文書化済み
- AWS IoT Coreへの実アカウント接続: 未実施

## 17. 公式資料

- AWS IoT Core: X.509 client certificates
  https://docs.aws.amazon.com/iot/latest/developerguide/x509-client-certs.html
- AWS IoT API: CreateCertificateFromCsr
  https://docs.aws.amazon.com/iot/latest/apireference/API_CreateCertificateFromCsr.html
- AWS CLI: create-certificate-from-csr
  https://docs.aws.amazon.com/cli/latest/reference/iot/create-certificate-from-csr.html
- AWS IoT Core: Attach a thing or policy to a client certificate
  https://docs.aws.amazon.com/iot/latest/developerguide/attach-to-cert.html
- AWS IoT Core: Device communication protocols
  https://docs.aws.amazon.com/iot/latest/developerguide/protocols.html
- AWS IoT Core: Server authentication
  https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html
- AWS CLI: describe-endpoint
  https://docs.aws.amazon.com/cli/latest/reference/iot/describe-endpoint.html
