##
## EPITECH PROJECT, 2026
## my_pgp
## File description:
## state
##


def state_to_matrix(state: bytes) -> list[list[int]]:
    """Convert a state (bytes) to a matrix (list of lists of integers)."""
    return [[state[i + 4 * j] for j in range(4)] for i in range(4)]


def matrix_to_state(matrix: list[list[int]]) -> bytes:
    """Convert a matrix (list of lists of integers) to a state (bytes)."""
    return bytes([matrix[i][j] for j in range(4) for i in range(4)])
