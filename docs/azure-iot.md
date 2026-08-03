# Connecting SE050 TLS identities to Azure IoT Hub

Updated: 2026-08-03

This document records the Azure IoT Hub connection procedure for P-256 TLS client identity keys generated inside SE050 and used through the NXP OpenSSL Provider.

## Validation status

The SE050/OpenSSL path has been hardware-tested locally through TLS 1.2 and TLS 1.3 mutual TLS. A real Azure IoT Hub account connection has not been performed.

## Compatibility conclusion

Azure IoT Hub supports X.509 client authentication and recommends CA-signed X.509 certificates for production. Microsoft explicitly recommends hardware secure modules that internally generate and protect device private keys. The SE050 implementation matches this model.

The Azure-specific requirement that must be observed is:

```text
leaf certificate CN = registered deviceId
```

## Recommended production flow

1. Select a production identity/slot.
2. Generate a CSR with `CN=deviceId` using the SE050 Provider key URI.
3. Have the vendor/customer PKI CA sign the CSR as a TLS client certificate.
4. Register and verify the issuing/root CA with IoT Hub.
5. Register a device identity with authentication method `x509_ca`.
6. Connect to `<hub>.azure-devices.net:8883` using TLS 1.2, the device certificate chain, and the SE050 key URI.

Microsoft-managed PKI through Azure Device Registry exists as a newer preview feature, but this document keeps the established third-party/customer CA path as the production baseline.

## CSR

```sh
DEVICE_ID=my-device-001
KEY_URI=$(se050ctl tls-key-ref --profile production --identity 0 --slot A)
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
PROVIDER=/usr/local/lib/libsssProvider.so

openssl req -new   --provider "$PROVIDER"   --provider default   -key "$KEY_URI"   -subj "/CN=$DEVICE_ID"   -out device.csr

openssl req -in device.csr -noout -verify -subject
```

## Issue the device certificate

The CSR is signed by an external/vendor/customer CA; IoT Hub is not used as the baseline leaf-certificate issuer.

A suitable leaf profile includes `CA:FALSE`, `digitalSignature`, and `extendedKeyUsage=clientAuth`. Keep the CA private key outside the device.

## Register the CA

```sh
HUB_NAME=my-hub
CA_NAME=my-device-issuing-ca

az iot hub certificate create   --hub-name "$HUB_NAME"   --name "$CA_NAME"   --path issuing-ca.crt
```

Complete proof-of-possession when required: inspect the certificate/ETag, call `az iot hub certificate generate-verification-code`, sign a verification certificate with the CA private key using the returned code as CN, then upload it with `az iot hub certificate verify`.

## Register the device identity

```sh
az iot hub device-identity create   --hub-name "$HUB_NAME"   --device-id "$DEVICE_ID"   --auth-method x509_ca
```

The registered device ID and leaf certificate CN must match.

## Certificate chain

If an intermediate CA signs the device certificate, present the leaf plus required intermediates to IoT Hub, for example:

```sh
cat device.crt intermediate-ca.crt > device-chain.pem
```

## Server trust and TLS

For classic IoT Hub endpoints Microsoft currently instructs devices to trust:

- DigiCert Global G2 root CA
- Microsoft RSA Root CA 2017

Baseline endpoint:

```text
<hub>.azure-devices.net:8883
TLS 1.2
```

TLS 1.0/1.1 support ended on 2025-08-31. A TLS 1.3-capable device endpoint `<hub>.device.azure-devices.net` is available in preview as of 2026-07, but is not the production baseline in this document.

## TLS-layer diagnostic

```sh
AZURE_HOST="$HUB_NAME.azure-devices.net"

openssl s_client   --provider "$PROVIDER"   --provider default   -tls1_2   -connect "$AZURE_HOST:8883"   -servername "$AZURE_HOST"   -cert device-chain.pem   -key "$KEY_URI"   -CAfile azure-iot-ca-bundle.pem
```

This validates TLS/mTLS only; an MQTT CONNECT packet is still required for a real MQTT session.

## MQTT parameters

```text
host:      <hub>.azure-devices.net
port:      8883
TLS:       1.2
ClientId:  <device-id>
Username:  <hub-hostname>/<device-id>/?api-version=2021-04-12
Password:  none for X.509 authentication
cert:      device-chain.pem
key:       nxp:0x20000200 (example Provider URI)
server CA: Azure IoT Hub root CA bundle
publish:   devices/<device-id>/messages/events/
```

Do not export the SE050 private key as a PEM fallback. The MQTT application must use an OpenSSL 3 Provider-capable key-loading path or configure its SSL context directly.

## Rotation

Use the existing identity A/B layout: generate B, create a new `CN=deviceId` CSR, issue a new CA-signed leaf certificate, test B, switch active identity, revoke/retire the old certificate, then delete A.

## Status matrix

| Requirement | Implementation | Status |
| --- | --- | --- |
| X.509 client authentication | OpenSSL + NXP Provider | compatible |
| unique protected device key | SE050 identity key | compatible |
| `CN=deviceId` | CSR subject | documented |
| CA-signed leaf | external CA signs SE050 CSR | supported |
| TLS 1.2 | local mTLS | hardware-tested |
| P-256 client key | SE050 P-256 | compatible |
| non-exportable private key | SE050 internal key | compatible |
| rotation | identity A/B | designed |
| real Azure account connection | not performed | specification-validated only |

## Official references

- https://learn.microsoft.com/en-us/azure/iot-hub/authenticate-authorize-x509
- https://learn.microsoft.com/en-us/azure/iot-hub/iot-hub-tls-support
- https://learn.microsoft.com/en-us/azure/iot-hub/iot-mqtt-connect-to-iot-hub
- https://learn.microsoft.com/en-us/cli/azure/iot/hub/device-identity
- https://learn.microsoft.com/en-us/cli/azure/iot/hub/certificate
- https://learn.microsoft.com/en-us/azure/iot-hub/reference-x509-certificates
