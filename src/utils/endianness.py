##
## EPITECH PROJECT, 2026
## my_pgp
## File description:
## endianness
##


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert a hexadecimal string (key or ciphertext) to a byte sequence.
    The string is read from left to right, which corresponds to the requested Little-Endian.
    """
    hex_str = hex_str.strip()
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """
    Convert a byte sequence to a hexadecimal string for standard output.
    """
    return data.hex()


def bytes_to_int(data: bytes) -> int:
    """
    Convert a byte sequence to a large mathematical integer (Little-Endian).
    This is useful for RSA operations, where we need to work with large integers.
    """
    return int.from_bytes(data, byteorder="little")


def int_to_bytes(number: int, length: int) -> bytes:
    """
    Convert a large integer (result of RSA) to a byte sequence (Little-Endian).
    The length parameter ensures that we have the correct block size.
    """
    return number.to_bytes(length, byteorder="little")
