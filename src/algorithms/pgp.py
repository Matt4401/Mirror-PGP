##
## EPITECH PROJECT, 2026
## my_pgp
## File description:
## PGP algorithm implementation
##

from typing import Callable
from src.utils.endianness import hex_to_bytes, bytes_to_hex


def parse_pgp_key(pgp_key: str) -> tuple[str, str]:
    parts = pgp_key.split(":", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("PGP key must have the format SYMMETRIC_KEY:RSA_KEY")
    return parts[0], parts[1]


def pgp_encrypt(
    message: bytes,
    key_str: str,
    single_block: bool,
    process_symmetric: Callable[[bytes, bytes, str, bool], bytes],
    process_rsa: Callable[[bytes, str, str], bytes],
) -> tuple[str, str]:
    sym_key_hex, rsa_pub = parse_pgp_key(key_str)
    sym_key_bytes = hex_to_bytes(sym_key_hex)

    ciphered_key_bytes = process_rsa(sym_key_bytes, rsa_pub, "c")

    ciphered_msg_bytes = process_symmetric(message, sym_key_bytes, "c", single_block)

    return ciphered_key_bytes.hex(), bytes_to_hex(ciphered_msg_bytes)


def pgp_decrypt(
    ciphered_msg_hex: str,
    key_str: str,
    single_block: bool,
    process_symmetric: Callable[[bytes, bytes, str, bool], bytes],
    process_rsa: Callable[[bytes, str, str], bytes],
) -> bytes:
    ciphered_key_hex, rsa_priv = parse_pgp_key(key_str)
    ciphered_key_bytes = hex_to_bytes(ciphered_key_hex)

    sym_key_bytes = process_rsa(ciphered_key_bytes, rsa_priv, "d")

    ciphered_msg_bytes = hex_to_bytes(ciphered_msg_hex)
    return process_symmetric(ciphered_msg_bytes, sym_key_bytes, "d", single_block)
