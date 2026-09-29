import json
from pathlib import Path

import pytest

from main import format_rsa_number, parse_rsa_key, process_rsa
from src.algorithms.rsa.core import rsa_key_values
from src.algorithms.rsa.d_exp import extended_euclidean_algorithm, get_d_exp
from src.algorithms.rsa.totient_carmichael import get_lambda_n


def load_1024_bit_primes() -> tuple[int, int]:
    primes_file = Path(__file__).parent / "primes" / "1024_rsa_primes.json"
    with primes_file.open(encoding="utf-8") as file:
        data = json.load(file)
    primes = data["prime_numbers"][:2]
    return tuple(int(prime["hexadecimal"], 16) for prime in primes)


def test_extended_euclidean_algorithm_returns_bezout_coefficients():
    gcd, x, y = extended_euclidean_algorithm(17, 3120)

    assert gcd == 1
    assert 17 * x + 3120 * y == gcd


def test_get_d_exp_returns_modular_inverse():
    private_exponent = get_d_exp(17, 3120)

    assert private_exponent == 2753
    assert (17 * private_exponent) % 3120 == 1


def test_get_lambda_n_uses_carmichael_totient():
    assert get_lambda_n((0xD3, 0xE3)) == 0x5CB2


def test_rsa_key_values_match_subject_example():
    assert rsa_key_values((0xD3, 0xE3)) == (0xBB19, 0x101, 0x5B9D)


def test_rsa_generates_keys_with_1024_bit_primes():
    prime_p, prime_q = load_1024_bit_primes()
    modulus, public_exponent, private_exponent = rsa_key_values((prime_p, prime_q))

    assert prime_p.bit_length() == 1024
    assert prime_q.bit_length() == 1024
    assert modulus == prime_p * prime_q
    assert modulus.bit_length() == 2048
    assert public_exponent == 65537
    assert (public_exponent * private_exponent) % get_lambda_n((prime_p, prime_q)) == 1


def test_process_rsa_round_trip_with_1024_bit_primes():
    prime_p, prime_q = load_1024_bit_primes()
    modulus, public_exponent, private_exponent = rsa_key_values((prime_p, prime_q))
    public_key = f"{format_rsa_number(public_exponent)}-{format_rsa_number(modulus)}"
    private_key = f"{format_rsa_number(private_exponent)}-{format_rsa_number(modulus)}"
    message = b"A message encrypted with 1024-bit RSA primes."

    encrypted = process_rsa(message, public_key, "c")
    decrypted = process_rsa(encrypted, private_key, "d")

    assert decrypted == message


def test_parse_rsa_key_reads_little_endian_components():
    assert parse_rsa_key("0101-19bb") == (0x101, 0xBB19)


def test_format_rsa_number_writes_little_endian_hexadecimal():
    assert format_rsa_number(0xBB19) == "19bb"
    assert format_rsa_number(0x101) == "0101"


def test_process_rsa_encrypts_subject_example():
    assert process_rsa(b"WF", "0101-19bb", "c") == bytes.fromhex("8f84")


def test_process_rsa_decrypts_subject_example():
    assert process_rsa(bytes.fromhex("8f84"), "9d5b-19bb", "d") == b"WF"


def test_process_rsa_rejects_invalid_key_format():
    with pytest.raises(ValueError, match="format"):
        process_rsa(b"WF", "0101", "c")


def test_process_rsa_rejects_message_larger_than_modulus():
    with pytest.raises(ValueError, match="smaller"):
        process_rsa(b"WF", "0101-0100", "c")


def test_process_rsa_rejects_zero_modulus():
    with pytest.raises(ValueError, match="positive"):
        process_rsa(b"", "0101-00", "c")
