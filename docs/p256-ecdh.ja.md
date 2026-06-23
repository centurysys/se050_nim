# P-256 ECDH メモ

この文書は、`se050_nim` を使う firmware envelope 用の実用的な鍵共有方針をまとめたものです。

## 判断

Firmware envelope の SE050-backed key agreement primitive として、P-256 ECDH を使います。

確認済みの経路は次の形です。

```text
SE050 device P-256 private key
  x
external peer P-256 public key
  -> 32-byte ECDH shared secret
  -> 上位envelopeライブラリで HKDF-SHA256
  -> AES-256-GCM wrap/open key
```

raw ECDH shared secret をそのまま AES key として使わないでください。

## 公開鍵形式

`readPublicKey` は、P-256 public key を 65-byte の非圧縮pointとして返します。

```text
0x04 || X(32) || Y(32)
```

`se050ctl derive --peer-public` も、P-256ではこの形式を期待します。

## Shared secret サイズ

P-256 ECDH の shared secret は 32 bytes です。

両方向で同じ値になる必要があります。

```text
A private x B public == B private x A public
```

## Smoke test

```sh
./se050ctl delete -b 0 --area dev --index 0x110 || true
./se050ctl delete -b 0 --area dev --index 0x111 || true

./se050ctl keygen -b 0 --area dev --index 0x110 --curve p256
./se050ctl keygen -b 0 --area dev --index 0x111 --curve p256

./se050ctl info -b 0 --area dev --index 0x110
./se050ctl info -b 0 --area dev --index 0x111

./se050ctl pubkey -b 0 --area dev --index 0x110 --out p256_a_pub.bin
./se050ctl pubkey -b 0 --area dev --index 0x111 --out p256_b_pub.bin

./se050ctl derive -b 0 --area dev --index 0x110 \
  --peer-public p256_b_pub.bin \
  --out p256_secret_ab.bin

./se050ctl derive -b 0 --area dev --index 0x111 \
  --peer-public p256_a_pub.bin \
  --out p256_secret_ba.bin

ls -l p256_a_pub.bin p256_b_pub.bin p256_secret_ab.bin p256_secret_ba.bin
sha256sum p256_secret_ab.bin p256_secret_ba.bin
cmp p256_secret_ab.bin p256_secret_ba.bin
```

期待サイズ:

```text
p256_a_pub.bin        65 bytes
p256_b_pub.bin        65 bytes
p256_secret_ab.bin    32 bytes
p256_secret_ba.bin    32 bytes
```

`sha256sum` は両方同じdigestになり、`cmp` は成功するはずです。

## Firmware envelope のレイヤ構成

`se050_nim` は ECDH derive までで止めます。次のレイヤが以下を扱います。

```text
shared_secret = SE050 P-256 ECDH(device_private, server_ephemeral_public)
wrap_key      = HKDF-SHA256(shared_secret, salt, info/aad)
release_cek   = AES-256-GCM-open(wrapped_release_cek, wrap_key, nonce, aad, tag)
```

上位の envelope project で決めるもの:

- envelope JSON/CBOR format
- server ephemeral public key encoding
- salt/info/aad layout
- AES-GCM nonce/tag layout
- release CEK handling
- firmware body encryption/decryption
- firmware signature verification

## Envelope 内の公開鍵field案

P-256では、server ephemeral public key も同じ非圧縮形式で保持します。

```json
{
  "alg": "P256-ECDH-HKDF-SHA256+A256GCM",
  "server_ephemeral_public_format": "p256-uncompressed",
  "server_ephemeral_public": "04...",
  "salt": "...",
  "aad": "...",
  "nonce": "...",
  "wrapped_release_cek": "...",
  "tag": "..."
}
```

Envelope library は、`deriveSharedSecret` を呼ぶ前に、decode後のpublic keyが正確に 65 bytes で、先頭が `0x04` であることを検証します。

## X25519 の扱い

`X25519 + Ed25519` で揃う設計は綺麗なので調査しました。しかし、テストした SE050 applet 経路では次の結果でした。

- X25519 key generation は成功
- object type は `0x69 EC_KEY_PAIR_MONT_DH_25519`
- public key export は成功し、32 bytesを返す
- derive は `SW=0x6985` で失敗

試した peer-public encoding:

- `TAG_2` 直下の raw 32-byte public key
- curve-prefixed `0x41 || public_key`
- nested value TLV `TAG_2 = 42 22 83 20 <public_key>`

いずれも derive は `SW=0x6985` でした。そのため、別の applet/middleware 経路で成功が確認できるまでは、X25519 derive は製品本線から外します。

## Production note

`se050ctl` が作る開発用鍵は、意図的に削除可能です。Production device key は、別の provisioning/kitting tool で、production policyを使って、おそらく `customer` range に作成します。
