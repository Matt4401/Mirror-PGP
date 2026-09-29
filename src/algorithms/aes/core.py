from .state import state_to_matrix, matrix_to_state
from .maths import (
    add_round_key,
    sub_bytes,
    shift_rows,
    mix_columns,
    inv_sub_bytes,
    inv_shift_rows,
    inv_mix_columns,
)
from .keys import keys_expansion
from .constants import SBOX, INV_SBOX


def get_key_matrix(key_schedule: list[bytes], round_idx: int) -> list[list[int]]:
    """Extracts 4 words (16 bytes) for the given round and converts them to a 4x4 state matrix."""
    round_bytes = b"".join(key_schedule[round_idx * 4 : (round_idx + 1) * 4])
    return state_to_matrix(round_bytes)


def aes_encrypt_block(block: bytes, key_schedule: list[bytes]) -> bytes:
    """Encrypt a single block of data using AES."""
    Nr = len(key_schedule) // 4 - 1

    state = state_to_matrix(block)
    state = add_round_key(state, get_key_matrix(key_schedule, 0))

    for i in range(1, Nr):
        state = sub_bytes(state, SBOX)
        state = shift_rows(state)
        state = mix_columns(
            state, [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
        )
        state = add_round_key(state, get_key_matrix(key_schedule, i))

    state = sub_bytes(state, SBOX)
    state = shift_rows(state)
    state = add_round_key(state, get_key_matrix(key_schedule, Nr))
    return matrix_to_state(state)


def aes_decrypt_block(block: bytes, key_schedule: list[bytes]) -> bytes:
    """Decrypt a single block of data using AES."""
    Nr = len(key_schedule) // 4 - 1

    state = state_to_matrix(block)
    state = add_round_key(state, get_key_matrix(key_schedule, Nr))

    for i in range(Nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state, INV_SBOX)
        state = add_round_key(state, get_key_matrix(key_schedule, i))
        state = inv_mix_columns(
            state, [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
        )
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state, INV_SBOX)
    state = add_round_key(state, get_key_matrix(key_schedule, 0))
    return matrix_to_state(state)
