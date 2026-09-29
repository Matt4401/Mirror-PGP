#!/usr/bin/env python3

##
## EPITECH PROJECT, 2026
## my_pgp
## File description:
## main
##

import sys

from src.algorithms.pgp import pgp_decrypt, pgp_encrypt
from src.parsing.parsing import parse_input
from src.utils.endianness import hex_to_bytes, bytes_to_hex
from src.utils.endianness import bytes_to_int, int_to_bytes
from src.utils.blocks import split_into_blocks, pad_block
from src.algorithms.aes.keys import keys_expansion
from src.algorithms.aes.core import aes_encrypt_block, aes_decrypt_block
from src.algorithms.xor import xor
from src.algorithms.rsa.core import rsa_key_values


def parse_rsa_key(key: str) -> tuple[int, int]:
    parts = key.split("-")
    if len(parts) != 2 or not all(parts):
        raise ValueError("RSA key must have the format exponent-modulus")
    try:
        return bytes_to_int(bytes.fromhex(parts[0])), bytes_to_int(
            bytes.fromhex(parts[1])
        )
    except ValueError as error:
        raise ValueError("RSA key must contain hexadecimal numbers") from error


def format_rsa_number(number: int) -> str:
    if number < 0:
        raise ValueError("RSA values cannot be negative")
    length = max(1, (number.bit_length() + 7) // 8)
    return int_to_bytes(number, length).hex()


def process_rsa(message: bytes, key: str, mode: str) -> bytes:
    exponent, modulus = parse_rsa_key(key)
    if modulus <= 0:
        raise ValueError("RSA modulus must be positive")
    value = bytes_to_int(message)
    if value >= modulus:
        raise ValueError("message must be smaller than the RSA modulus")
    result = pow(value, exponent, modulus)
    target_len = max(1, (modulus.bit_length() + 7) // 8)
    return int_to_bytes(result, target_len)


def process_aes(message: bytes, key: bytes, mode: str, single_block: bool) -> bytes:
    key_schedule = keys_expansion(key)
    block_size = 16

    if single_block:
        if len(message) > block_size:
            message = message[:block_size]
        elif len(message) < block_size:
            message = pad_block(message, block_size)
        blocks = [message]
    else:
        blocks = split_into_blocks(message, block_size)
        if mode == "c" and blocks and len(blocks[-1]) < block_size:
            blocks[-1] = pad_block(blocks[-1], block_size)

    output = []
    for b in blocks:
        if mode == "c":
            output.append(aes_encrypt_block(b, key_schedule))
        else:
            output.append(aes_decrypt_block(b, key_schedule))
    return b"".join(output)


def process_xor(message: bytes, key: bytes, mode: str, single_block: bool) -> bytes:
    block_size = len(key)
    if block_size == 0:
        raise ValueError("Key cannot be empty.")

    if single_block:
        if len(message) > block_size:
            message = message[:block_size]
        elif len(message) < block_size:
            message = pad_block(message, block_size)
        blocks = [message]
    else:
        blocks = split_into_blocks(message, block_size)
        if mode == "c" and blocks and len(blocks[-1]) < block_size:
            blocks[-1] = pad_block(blocks[-1], block_size)

    output = []
    for b in blocks:
        if mode == "c":
            output.append(xor(b[::-1], key))
        else:
            out_b = xor(b, key[: len(b)]) if len(b) < block_size else xor(b, key)
            output.append(out_b[::-1])
    return b"".join(output)


def process_pgp(
    raw_data: bytes,
    key_str: str,
    mode: str,
    single_block: bool,
    crypto_system: str,
) -> tuple[str, str] | bytes:
    symmetric_func = process_aes if crypto_system == "pgp-aes" else process_xor
    if mode == "c":
        return pgp_encrypt(raw_data, key_str, single_block, symmetric_func, process_rsa)
    return pgp_decrypt(
        raw_data.decode("ascii").strip(),
        key_str,
        single_block,
        symmetric_func,
        process_rsa,
    )


def main():
    try:
        args = parse_input()

        if args.mode == "g":
            n, e, d = rsa_key_values(args.primes)
            print(f"public key: {format_rsa_number(e)}-{format_rsa_number(n)}")
            print(f"private key: {format_rsa_number(d)}-{format_rsa_number(n)}")
            return

        if args.crypto_system == "rsa":
            parse_rsa_key(args.key)
        elif args.crypto_system in ("aes", "xor"):
            key_bytes = hex_to_bytes(args.key)
        elif args.crypto_system in ("pgp-xor", "pgp-aes"):
            parts = args.key.split(":")
            if len(parts) != 2:
                raise ValueError("PGP key must be in the format symmetric_key:rsa_key")
            hex_to_bytes(parts[0])
            parse_rsa_key(parts[1])

        raw_data = sys.stdin.buffer.read()
        if (args.single_block or args.crypto_system == "rsa") and raw_data.endswith(b"\n"):
            raw_data = raw_data[:-1]
            if raw_data.endswith(b"\r"):
                raw_data = raw_data[:-1]

        if args.crypto_system == "rsa":
            if args.mode == "c":
                result = process_rsa(raw_data, args.key, args.mode)
                print(result.hex())
            else:
                ciphered = hex_to_bytes(raw_data.decode("ascii").strip())
                result = process_rsa(ciphered, args.key, args.mode)
                sys.stdout.buffer.write(result + b"\n")
            return

        if args.crypto_system in ("pgp-xor", "pgp-aes"):
            if args.mode == "c":
                ciphered_key, ciphered_msg = process_pgp(
                    raw_data, args.key, args.mode, args.single_block, args.crypto_system
                )
                print(ciphered_key)
                print(ciphered_msg)
            else:
                result = process_pgp(
                    raw_data, args.key, args.mode, args.single_block, args.crypto_system
                )
                if not args.single_block:
                    result = result.rstrip(b"\x00")
                sys.stdout.buffer.write(result + b"\n" if args.single_block else result)
            return

        key_bytes = hex_to_bytes(args.key)
        if args.mode == "c":
            message_bytes = raw_data
        else:
            message_bytes = hex_to_bytes(raw_data.decode("ascii").strip())

        if args.crypto_system == "aes":
            result = process_aes(message_bytes, key_bytes, args.mode, args.single_block)
        elif args.crypto_system == "xor":
            result = process_xor(message_bytes, key_bytes, args.mode, args.single_block)
        else:
            raise NotImplementedError(
                f"Crypto system '{args.crypto_system}' is not implemented yet."
            )

        if args.mode == "c":
            print(bytes_to_hex(result))
        else:
            if not args.single_block:
                result = result.rstrip(b"\x00")
            sys.stdout.buffer.write(result + b"\n" if args.single_block else result)

    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(84)


if __name__ == "__main__":
    main()
