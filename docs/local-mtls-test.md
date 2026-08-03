# SE050 TLS identity local mutual-TLS test

## Purpose

Before adding AWS IoT Core, Azure IoT Hub, or other cloud-specific pieces,
verify locally that an SE050 TLS client private key can perform real TLS client
certificate authentication through the NXP OpenSSL Provider.

The local CA and TLS server use temporary software keys. Only the TLS client
private key under test remains inside the SE050 and is never written to the host
filesystem.

## Security boundary

This project treats the host OS as a trusted environment and primarily relies
on SE050 for private-key non-exportability. The NXP Provider Plain communication
channel warning is accepted under this threat model.

Protection against SE050 misuse after host compromise, Platform SCP03, Access
Manager, Secure Boot, and related host-hardening measures are outside the scope
of this test and the current TLS identity feature.

## Prerequisites

- OpenSSL 3.x
- NXP `libsssProvider.so`
- `se050ctl`
- an existing TLS identity key
- working SE050 access through `EX_SSS_BOOT_SSS_PORT`

Example:

```text
EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
Provider=/usr/local/lib/libsssProvider.so
TLS identity=test / identity 0 / slot A
Object ID=0x30000200
```

## Automated test

`tools/se050_local_mtls_test.sh` performs the following sequence:

1. Validate the selected TLS identity with `se050ctl tls-key-info` and attestation
2. Resolve its NXP Provider key URI with `tls-key-ref`
3. Create a temporary local CA
4. Create a `localhost` server certificate
5. Create the client CSR using the SE050 key through the NXP Provider
6. Issue the client certificate with the local CA
7. Verify server/client certificate chains and EKUs
8. Require a client certificate with `openssl s_server -Verify`
9. Connect with `openssl s_client` using the SE050 key over TLS 1.3
10. Repeat the mutual-TLS connection over TLS 1.2
11. Run a negative control and confirm TLS 1.3 rejects a client with no certificate

The script never creates, deletes, or replaces an SE050 Secure Object.

Example:

```text
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48

./tools/se050_local_mtls_test.sh \
  --se050ctl ./se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --profile test \
  --identity 0 \
  --slot A
```

Expected final lines:

```text
TLS 1.3 mutual TLS: OK
TLS 1.2 mutual TLS: OK
TLS 1.3 without client certificate: rejected (expected)
client private key: SE050 only (nxp:0x30000200)
local mutual TLS test: PASS
```

Temporary artifacts remain in the printed `workdir` for inspection, including
the client CSR/certificate, CA/server certificates, and OpenSSL logs. No client
private-key file is generated.

## What this proves

- The X.509 client certificate corresponds to the SE050 TLS identity key pair
- CSR signing executes in the SE050
- TLS CertificateVerify signing executes in the SE050 through the NXP Provider (and is confirmed in the Provider log)
- The TLS server validates the locally issued client certificate chain
- Mutual TLS works with both TLS 1.3 and TLS 1.2
- TLS client authentication works without a private-key file on the host

## Out of scope

- Actual AWS IoT Core / Azure IoT Hub connectivity
- Cloud-specific MQTT parameters and policies
- SCP03 and host authentication
- Multi-process SE050 arbitration
- A/B certificate rotation
