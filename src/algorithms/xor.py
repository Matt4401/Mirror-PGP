##
## EPITECH PROJECT, 2026
## my_pgp
## File description:
## xor
##


def xor(data: bytes, key: bytes) -> bytes:
    """
    XORs the data with the key.

    Args:
        data (bytes): The data to be XORed.
        key (bytes): The key to XOR the data with.

    Returns:
        bytes: The XORed data.
    """
    return bytes(a ^ b for a, b in zip(data, key))
