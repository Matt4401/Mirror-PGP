import pytest
import subprocess
import sys

from main import parse_x25519_key
from src.algorithms.x25519 import core
from src.algorithms.x25519.cipher import aes_ctr
from src.algorithms.x25519.core import decrypt, encrypt, generate_keypair, x25519, x25519_public_key


def test_x25519_matches_rfc_7748_shared_secret_vector():
    alice_private = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )
    bob_public = bytes.fromhex(
        "de9edb7d7b7dc1b4d35b61c2ece43537"
        "3f8343c85b78674dadfc7e146f882b4f"
    )

    assert x25519(alice_private, bob_public).hex() == (
        "4a5d9d5ba4ce2de1728e3bf480350f25"
        "e07e21c947d19e3376f09b3c1e161742"
    )


def test_x25519_public_key_matches_rfc_7748_vector():
    private_key = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )

    assert x25519_public_key(private_key).hex() == (
        "8520f0098930a754748b7ddcb43ef75a"
        "0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )


def test_generated_keypairs_derive_the_same_shared_secret():
    alice_private, alice_public = generate_keypair()
    bob_private, bob_public = generate_keypair()

    assert len(alice_private) == len(alice_public) == 32
    assert x25519(alice_private, bob_public) == x25519(bob_private, alice_public)


def test_x25519_cli_encrypts_and_decrypts_messages():
    private_key, public_key = generate_keypair()
    message = b"A secret message from Arya to Brienne.\n"

    encrypted = subprocess.run(
        [sys.executable, "main.py", "X25519", "-c", public_key.hex()],
        input=message,
        capture_output=True,
        check=True,
    ).stdout
    decrypted = subprocess.run(
        [sys.executable, "main.py", "X25519", "-d", private_key.hex()],
        input=encrypted,
        capture_output=True,
        check=True,
    ).stdout

    assert decrypted == message


def test_aes_ctr_matches_nist_vector():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    counter = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    message = bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    )
    expected = bytes.fromhex(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
    )
    assert aes_ctr(message, key, counter) == expected


@pytest.mark.parametrize("message", [b"", b"a", b"x" * 16, bytes(range(256)) + b"\x00\n"])
def test_message_round_trip_preserves_all_bytes(message):
    private_key, public_key = generate_keypair()
    ciphertext = encrypt(message, public_key)
    assert len(ciphertext) == len(message) + 84
    assert decrypt(ciphertext, private_key) == message


def test_message_encryption_uses_our_x25519(monkeypatch):
    private_key, public_key = generate_keypair()
    calls = []
    original = core.x25519

    def tracked_x25519(private, public):
        calls.append((private, public))
        return original(private, public)

    monkeypatch.setattr(core, "x25519", tracked_x25519)
    ciphertext = encrypt(b"secret", public_key)
    assert decrypt(ciphertext, private_key) == b"secret"
    assert any(public == public_key for _, public in calls)
    assert (private_key, ciphertext[4:36]) in calls


@pytest.mark.parametrize("offset", [0, 4, 36, 52, -1])
def test_message_decryption_rejects_tampering(offset):
    private_key, public_key = generate_keypair()
    ciphertext = bytearray(encrypt(b"secret", public_key))
    ciphertext[offset] ^= 1
    with pytest.raises(ValueError):
        decrypt(bytes(ciphertext), private_key)


def test_message_decryption_rejects_wrong_key_and_truncation():
    private_key, public_key = generate_keypair()
    wrong_private, _ = generate_keypair()
    ciphertext = encrypt(b"secret", public_key)
    with pytest.raises(ValueError):
        decrypt(ciphertext, wrong_private)
    with pytest.raises(ValueError):
        decrypt(ciphertext[:60], private_key)


def test_message_encryption_is_randomized():
    _, public_key = generate_keypair()
    assert encrypt(b"secret", public_key) != encrypt(b"secret", public_key)


def test_cli_rejects_tampered_ciphertext_without_plaintext():
    private_key, public_key = generate_keypair()
    ciphertext = bytearray(encrypt(b"secret", public_key))
    ciphertext[-1] ^= 1
    result = subprocess.run(
        [sys.executable, "main.py", "X25519", "-d", private_key.hex()],
        input=bytes(ciphertext),
        capture_output=True,
    )
    assert result.returncode == 84
    assert result.stdout == b""
    assert b"authenticate" in result.stderr


@pytest.mark.parametrize(
    ("private_key", "public_key"),
    [
        (b"short", bytes(32)),
        (bytes(32), b"short"),
    ],
)
def test_x25519_rejects_keys_with_invalid_lengths(private_key, public_key):
    with pytest.raises(ValueError, match="32 bytes"):
        x25519(private_key, public_key)


def test_x25519_rejects_all_zero_shared_secret():
    with pytest.raises(ValueError, match="all-zero"):
        x25519(bytes(32), bytes(32))


def test_parse_x25519_key_accepts_64_hex_characters():
    key = "ab" * 32

    assert parse_x25519_key(key) == bytes.fromhex(key)


@pytest.mark.parametrize("key", ["not-hex", "ab" * 31, "ab" * 33])
def test_parse_x25519_key_rejects_invalid_keys(key):
    with pytest.raises(ValueError):
        parse_x25519_key(key)