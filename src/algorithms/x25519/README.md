# X25519

The CLI accepts `X25519 -g`, `X25519 -c PUBLIC_KEY` and
`X25519 -d PRIVATE_KEY`. Keys are 32-byte hexadecimal strings in RFC 7748
encoding. Encryption and decryption preserve stdin bytes exactly, including
newlines and trailing zero bytes. Ciphertext is binary.

`core.py` implements RFC 7748 X25519 using scalar clamping and the Montgomery
ladder over the field modulo 2^255 - 19. Encryption generates a new ephemeral
key pair and derives a shared secret using the recipient's public key.
Decryption derives the same secret using the recipient's private key and the
ephemeral public key stored in the ciphertext. All-zero shared secrets are
rejected.

`cipher.py` uses HKDF-SHA256 (extract and expand) to derive a 16-byte AES key
and a separate 32-byte HMAC key. The HKDF salt is SHA256 of the protocol label,
ephemeral public key and recipient public key; the info is the protocol label
`my_pgp X25519 AES128-CTR HMAC-SHA256 v1`.

AES-128-CTR uses the existing project AES implementation. Its random 16-byte
initial counter is incremented as a big-endian integer. HMAC-SHA256 authenticates
the entire header and encrypted message, and is verified before decryption.
Random generation, SHA256 and HMAC use Python's standard library, not PyNaCl.

## Binary Format

| Field | Bytes |
| --- | --- |
| Version marker `X25\x01` | 4 |
| Ephemeral X25519 public key | 32 |
| Initial AES counter | 16 |
| Encrypted message | Same length as plaintext |
| HMAC-SHA256 tag | 32 |

This is a project-specific hybrid format, not libsodium SealedBox or PGP.
Previously generated SealedBox files must be encrypted again. The Ed25519 key
pair printed in the assignment is not a raw X25519 pair; use keys generated
with `X25519 -g`.

This implementation is educational, not audited or constant-time. Python's
integer arithmetic and conditional ladder swaps can leak timing information.
It must not be used to protect real secrets. Message authentication detects
tampering, but does not establish the sender's identity.