##
## EPITECH PROJECT, 2026
## Mirro-my_PGP
## File description:
## d_exp
##


def extended_euclidean_algorithm(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm.
    a = e and b = lambda_n
    Returns a tuple (g, x, y) such that a * x + b * y = g = gcd(a, b)"""
    if b == 0:
        return a, 1, 0
    gcd, x, y = extended_euclidean_algorithm(b, a % b)
    return gcd, y, x - (a // b) * y


def get_d_exp(e: int, lambda_n: int) -> int:
    (g, s, t) = extended_euclidean_algorithm(e, lambda_n)
    if g != 1:
        return -1  # e is not invertible
    d = s % lambda_n
    if d >= 0 and d <= lambda_n:  # just to be safe but must be in [0, lambda_n]
        return d
    return -1
