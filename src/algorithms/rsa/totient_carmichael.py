##
## EPITECH PROJECT, 2026
## Mirro-my_PGP
## File description:
## totient_carmichael
##


def get_pgcd(a: int, b: int) -> int:
    """Euclide algorithm to compute the greatest common divisor (GCD)
    https://fr.wikipedia.org/wiki/Algorithme_d%27Euclide"""
    while b != 0:
        t = b
        b = a % b
        a = t
    return a


def get_ppcm(primes_reducted: tuple[int, int]) -> int:
    """We use this relation PPCM(a, b) = a × b / PGCD(a, b)"""
    a, b = primes_reducted
    return a * b // get_pgcd(a, b)


def get_lambda_n(primes: tuple[int, int]) -> int:
    """We use this : λ(n) = (p − 1) × (q − 1) / PGCD(p − 1, q − 1)
    Using the totient function for Carmichael's theorem."""
    primes_reducted = (primes[0] - 1, primes[1] - 1)
    lambda_n = get_ppcm(primes_reducted)
    if lambda_n == 2 or lambda_n == 3:  # should not be possible
        return -1
    return lambda_n
