##
## EPITECH PROJECT, 2026
## Mirro-my_PGP
## File description:
## fermat_biggest_prime
##

from math import gcd

FERMAT_PRIMES = [3, 5, 17, 257, 65537]


def get_biggest_fermat_prime(n_lambda: int) -> int:
    for i in range(len(FERMAT_PRIMES) - 1, -1, -1):
        if FERMAT_PRIMES[i] < n_lambda and gcd(FERMAT_PRIMES[i], n_lambda) == 1:
            return FERMAT_PRIMES[i]
    return -1  # must be not possible
