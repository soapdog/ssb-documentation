# Cryptography

## Keys and identities

The first thing a user needs to participate in Scuttlebutt is an identity. An identity is an Ed25519 key pair and typically represents a person, a device, a server or a bot. It’s normal for a person to have several Scuttlebutt identities.

Upon starting for the first time, Scuttlebutt clients will automatically generate an Ed25519 key pair and save it in the user’s home folder under `.ssb/secret`.

![The Scuttlebutt identity is a long-term Ed25519 key pair.](img/identity_keypair.png)

Because identities are long and random, no coordination or permission is required to create a new one, which is essential to the network’s design.

Later, a user can choose to give themselves a nickname or avatar to make themselves easier to refer to. Over time nicknames may change but identities stay the same. If a user loses their secret key or has it stolen they will need to generate a new identity and tell people to use their new one instead.

The public key of an identity is presented to users and transmitted in some parts of the network protocol using this format:

![@FCX/tsDLpubCPKKfIrw4gc+SQkHcaD17s7GI6i/ziWY=.ed25519 where everything but the @ prefix and .ed25519 suffix is the public-key, base64-encoded.](img/format_public_key.png)

Throughout the protocol all instances of base64 are the variant that uses `+` and `/`. The final padding `=` is also required.

The beginning `@` sign signifies that this represents a public key rather than a message or blob, which start with `%` and `&`. Each identity has an associated [feed](#feeds), which is a list of all the messages posted by that identity. This is why the identity is also called a _feed ID_.

## Cryptographic primitives

The Scuttlebutt protocol relies on NaCl/libsodium's cryptobox primitives. This guide uses the following:

`nacl_scalarmult(n, p)`

This is [Libsodium's scalar multiplication function](https://doc.libsodium.org/advanced/scalar_multiplication), which takes two scalars (usually public and/or secret keys). It has the useful property that, given two key pairs `(pk1, sk1)` and `(pk2, sk2)`, `nacl_scalarmult(sk1, pk2) == nacl_scalarmult(sk2, pk1)`, which allows shared secret derivation between peers who know each other's public key. More on this later.

`nacl_auth(msg, key)` and `assert_nacl_auth_verify(authenticator, msg, key)`

This functions are [Libsodium's message authentication function](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption). The former takes a message and returns a 32-bytes authenticator, that acts as a detacted signature of the message. The latter verifies this authenticator is indeed valid for the given message and key; and errors if they don't.

`nacl_secret_box(msg, nonce, key)` and `assert_nacl_secretbox_open(ciphertext, nonce, key)`

These function are based on [Libsodium's crypto\_secretbox\_easy and crypto\_secretbox\_open\_easy function](https://doc.libsodium.org/secret-key_cryptography/secretbox), which use symmetric cryptography to, respectively, encrypt+authenticate, and verify+decrypt a message using a nonce and a shared secret.

`nacl_sign_detached(msg, key)` and `assert_nacl_sign_verify_detached(sig, msg, key)`

The former is computed from [Libsodium's signature functions](https://doc.libsodium.org/public-key_cryptography/public-key_signatures). Unlike the usual Libsodium/NaCl functions, they work with signatures in independent buffers, rather than concatenated with the msg.

`pk_to_curve25519(ed25519_pk)` and `sk_to_curve25519(ed25519_sk)`

These functions convert Ed25519 keys (used for cryptobox) to Curve25519 (aka X25519) keys, used for signing. They are [implemented by Libsodium as `crypto_sign_ed25519_pk_to_curve25519` and `crypto_sign_ed25519_sk_to_curve25519`](https://doc.libsodium.org/advanced/ed25519-curve25519), respectively.