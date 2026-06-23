# se050_nim examples

このディレクトリには、`se050_nim` ライブラリを直接使う小さな実行例を置きます。
`se050ctl` の代替ではなく、ライブラリ利用方法を示すためのサンプルです。

## ビルド

リポジトリのルートから実行します。

```sh
nim c examples/read_uid.nim
nim c examples/random_bytes.nim
nim c examples/object_info.nim
nim c examples/p256_keygen_pubkey.nim
nim c examples/p256_derive_secret.nim
nim c examples/p256_keygen_explicit_policy.nim
```

既存の `examples/config.nims` により、`../src` が Nim の module search path に追加されます。

## サンプル実行

```sh
# /dev/i2c-0 の SE050 UID を読む
./examples/read_uid 0

# 32 bytes の乱数を生成する
./examples/random_bytes 0 32

# 内蔵 UID object を確認する
./examples/object_info 0 0x7FFF0206

# dev index 0x110 に P-256 key pair を生成し、公開鍵を書き出す
./examples/p256_keygen_pubkey 0 0x110 p256_110_pub.bin

# dev key pair 2組を生成または再利用し、P-256 ECDH を双方向で確認する
./examples/p256_derive_secret 0 0x110 0x111

# EC key policy を明示的に渡して P-256 key pair を生成する
./examples/p256_keygen_explicit_policy 0 0x120 development p256_120_pub.bin
```

## 明示policy指定のサンプル

`p256_keygen_explicit_policy.nim` は、policy指定付き key generation API の使い方を示すサンプルです。
通常は `development` policy を使います。この場合、作成したobjectは `se050ctl` で削除可能なままです。

`device` / `one-time` policy は、WRITE / GEN / DELETE 権限を意図的に含みません。
そのため、development range に作成した場合でも、`se050ctl` では削除できないobjectになる可能性があります。
このサンプルでは、これらのpolicyを使う場合に `--allow-sticky` を必須にしています。

```sh
./examples/p256_keygen_explicit_policy 0 0x121 device p256_121_pub.bin --allow-sticky
```

sticky policy mode は、消せなくなってもよい development object ID でだけ使ってください。

## 安全方針

書き込みを行うサンプルは、development object range だけを使います。

```text
0x30000000..0x3000FFFF
```

vendor / customer / NXP / internal range には書き込みません。
production provisioning は、one-time / no-delete policy を扱う別ツールとして実装する想定です。

## X25519

テスト済み環境では、X25519 の key generation と public key export は動作しましたが、X25519 derive は SE050 applet 7.2.0 の確認経路では成功していません。
そのため、examples は実機確認済みの P-256 ECDH を中心にしています。
