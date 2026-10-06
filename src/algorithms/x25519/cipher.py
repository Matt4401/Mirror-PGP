import hashlib
import hmac
import secrets

from src.algorithms.aes.core import aes_encrypt_block
from src.algorithms.aes.keys import keys_expansion


def derive_keys(
    shared_secret: bytes, ephemeral_public: bytes, recipient_public: bytes
) -> tuple[bytes, bytes]:
    context = b"my_pgp X25519 AES128-CTR HMAC-SHA256 v1"
    salt = hashlib.sha256(context + ephemeral_public + recipient_public).digest()
    extracted = hmac.digest(salt, shared_secret, "sha256")
    first = hmac.digest(extracted, context + b"\x01", "sha256")
    second = hmac.digest(extracted, first + context + b"\x02", "sha256")
    material = first + second
    return material[:16], material[16:48]


def aes_ctr(message: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(nonce) != 16:
        raise ValueError("AES counter must be exactly 16 bytes")
    key_schedule = keys_expansion(key)
    counter = int.from_bytes(nonce, "big")
    block_count = (len(message) + 15) // 16
    if counter + block_count > 2**128:
        raise ValueError("AES counter would overflow")
    output = bytearray()
    for offset in range(0, len(message), 16):
        stream = aes_encrypt_block(counter.to_bytes(16, "big"), key_schedule)
        block = message[offset:offset + 16]
        output.extend(value ^ mask for value, mask in zip(block, stream))
        counter += 1
    return bytes(output)


def encrypt_message(
    message: bytes, shared_secret: bytes, ephemeral_public: bytes,
    recipient_public: bytes,
) -> bytes:
    encryption_key, authentication_key = derive_keys(
        shared_secret, ephemeral_public, recipient_public
    )
    nonce = secrets.token_bytes(16)
    header = b"X25\x01" + ephemeral_public + nonce
    payload = header + aes_ctr(message, encryption_key, nonce)
    return payload + hmac.digest(authentication_key, payload, "sha256")


def decrypt_message(
    ciphertext: bytes, shared_secret: bytes, ephemeral_public: bytes,
    recipient_public: bytes,
) -> bytes:
    encryption_key, authentication_key = derive_keys(
        shared_secret, ephemeral_public, recipient_public
    )
    payload, tag = ciphertext[:-32], ciphertext[-32:]
    expected_tag = hmac.digest(authentication_key, payload, "sha256")
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("unable to authenticate X25519 ciphertext")
    return aes_ctr(payload[52:], encryption_key, payload[36:52])