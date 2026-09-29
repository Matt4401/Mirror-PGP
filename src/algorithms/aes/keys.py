##
## EPITECH PROJECT, 2026
## my_pgp
## File description:
## keys
##

from .constants import SBOX, RCON


def rot_words(word: bytes) -> bytes:
    """
    Rotate a word (4 bytes) to the left by one byte.
    """
    return word[1:] + word[:1]


def sub_word(word: bytes) -> bytes:
    """
    Substitute each byte in a word (4 bytes) using the S-Box.
    """
    return bytes(SBOX[b] for b in word)


def keys_expansion(key: bytes) -> list[bytes]:
    """
    Expand the cipher key into a list of round keys.
    """
    assert len(key) in (16, 24, 32), "Key must be 128, 192, or 256 bits long."

    Nk = len(key) // 4
    Nr = Nk + 6
    expanded_keys = [key[i : i + 4] for i in range(0, len(key), 4)]

    for i in range(Nk, (Nr + 1) * 4):
        temp = expanded_keys[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_words(temp))
            temp = bytes([temp[0] ^ RCON[i // Nk], temp[1], temp[2], temp[3]])
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)
        expanded_keys.append(bytes(a ^ b for a, b in zip(expanded_keys[i - Nk], temp)))

    return expanded_keys
