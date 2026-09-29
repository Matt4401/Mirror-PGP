##
## EPITECH PROJECT, 2026
## Mirro-my_PGP
## File description:
## core
##

from src.parsing.parsing import ParsedArguments
from .n_mod import n_mod
from .totient_carmichael import get_lambda_n
from .fermat_biggest_prime import get_biggest_fermat_prime
from .d_exp import get_d_exp


def rsa_key_values(primes: tuple[int, int]) -> tuple[int, int, int]:
    n = n_mod(primes)
    lambda_n = get_lambda_n(primes)
    if lambda_n == -1:
        raise ValueError("unable to compute Carmichael's totient")
    e = get_biggest_fermat_prime(lambda_n)  # fermat biggest prime
    if e == -1:
        raise ValueError("no valid Fermat prime for these primes")
    d = get_d_exp(e, lambda_n)
    if d == -1:
        raise ValueError("public exponent is not invertible")
    return n, e, d
