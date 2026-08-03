# Connecting SE050 TLS identities to AWS IoT Core

Updated: 2026-08-03

This document records the AWS IoT Core connection procedure for P-256 TLS client identity keys generated inside SE050 and used through the NXP OpenSSL Provider.

## Validation status

The following path has been hardware-tested locally: SE050 internal P-256 key generation, signed attestation semantics, `nxp:0x...` Provider lookup, ECDSA/SHA-256 signing, CSR generation and verification, CSR/live public-key byte equality, and TLS 1.2/TLS 1.3 mutual TLS. A real AWS account connection has not been performed.

## Compatibility conclusion

AWS IoT Core accepts CSR public keys using ECC NIST P-256/P-384/P-521 and supports ECC NIST P-256 client keys with TLS 1.2 and TLS 1.3. The SE050 TLS identity implementation therefore meets the cryptographic requirements.

## Recommended flow

1. Select a production identity/slot and obtain the Provider URI.
2. Generate a CSR with OpenSSL and `libsssProvider.so`.
3. Call `CreateCertificateFromCsr` with the CSR and save only the returned certificate.
4. Create/choose an IoT Thing.
5. Attach the certificate principal to the Thing.
6. Attach a least-privilege AWS IoT Policy to the certificate.
7. Retrieve the `iot:Data-ATS` endpoint.
8. Connect with MQTT/TLS on port 8883, using the certificate file and the SE050 Provider URI as the private key.

## SE050 key and CSR

```sh
KEY_URI=$(se050ctl tls-key-ref --profile production --identity 0 --slot A)
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
PROVIDER=/usr/local/lib/libsssProvider.so
THING_NAME=my-device-001

openssl req -new   --provider "$PROVIDER"   --provider default   -key "$KEY_URI"   -subj "/CN=$THING_NAME"   -out device.csr

openssl req -in device.csr -noout -verify
```

AWS does not require the CSR CN to equal the Thing name; using the Thing name here is an operational convention.

## Issue an AWS IoT certificate

```sh
aws iot create-certificate-from-csr   --certificate-signing-request file://device.csr   --set-as-active   --certificate-pem-outfile device.crt   > certificate.json

CERT_ARN=$(jq -r .certificateArn certificate.json)
```

The command returns a certificate, not a private key. Reusing a CSR creates another distinct certificate, so provisioning should prevent accidental duplicate issuance.

## Thing and policy

```sh
aws iot create-thing --thing-name "$THING_NAME"
aws iot attach-thing-principal --thing-name "$THING_NAME" --principal "$CERT_ARN"
aws iot attach-policy --policy-name se050-device-policy --target "$CERT_ARN"
```

The certificate authenticates the client; an AWS IoT Policy is still required for Connect/Publish/Subscribe authorization.

## ATS endpoint

```sh
AWS_IOT_ENDPOINT=$(aws iot describe-endpoint   --endpoint-type iot:Data-ATS   --query endpointAddress   --output text)
```

Use MQTT/TLS port 8883 for the simplest X.509 path. MQTT on port 443 requires ALPN `x-amzn-mqtt-ca`. MQTT clients must send SNI.

## Server trust

AWS recommends ATS endpoints and an updateable trust store containing supported Amazon Root CAs. Current documentation identifies Amazon Root CA 1 (RSA 2048) and Amazon Root CA 3 (ECC P-256) among the active ATS roots. Avoid pinning an individual server certificate.

## TLS-layer diagnostic

```sh
openssl s_client   --provider "$PROVIDER"   --provider default   -connect "$AWS_IOT_ENDPOINT:8883"   -servername "$AWS_IOT_ENDPOINT"   -cert device.crt   -key "$KEY_URI"   -CAfile aws-iot-ca-bundle.pem
```

This tests TLS/mTLS only; `s_client` does not send MQTT CONNECT.

## MQTT application parameters

```text
host:        iot:Data-ATS endpoint
port:        8883
client ID:   Thing/client ID allowed by the IoT Policy
certificate: device.crt
private key: nxp:0x20000200 (example Provider URI)
server CA:   AWS ATS trust bundle
username:    normally none
password:    normally none
```

Do not add a fallback that exports the SE050 private key to PEM. If an MQTT library accepts only a key filename, integrate through an OpenSSL 3 Provider/OSSL_STORE-capable path or configure the SSL context directly.

## Rotation

Use the existing per-identity A/B scheme: generate B, create a new CSR/certificate, test B, switch the active identity, deactivate/revoke A, then delete the old A key.

## Status matrix

| Requirement | Implementation | Status |
| --- | --- | --- |
| X.509 client authentication | OpenSSL + NXP Provider | compatible |
| ECC NIST P-256 CSR | SE050 P-256 | compatible |
| TLS 1.2 / TLS 1.3 | local mTLS | hardware-tested |
| non-exportable private key | SE050 internal key | compatible |
| rotation | identity A/B | designed |
| real AWS account connection | not performed | specification-validated only |

## Official references

- https://docs.aws.amazon.com/iot/latest/developerguide/x509-client-certs.html
- https://docs.aws.amazon.com/iot/latest/apireference/API_CreateCertificateFromCsr.html
- https://docs.aws.amazon.com/cli/latest/reference/iot/create-certificate-from-csr.html
- https://docs.aws.amazon.com/iot/latest/developerguide/attach-to-cert.html
- https://docs.aws.amazon.com/iot/latest/developerguide/protocols.html
- https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html
- https://docs.aws.amazon.com/cli/latest/reference/iot/describe-endpoint.html
