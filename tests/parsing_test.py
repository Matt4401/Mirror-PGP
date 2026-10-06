##
## EPITECH PROJECT, 2026
## Mirro-my_PGP
## File description:
## parsing
##

import pytest

from src.parsing.parsing import parse_input


@pytest.mark.parametrize(
    "crypto_system", ["xor", "aes", "rsa", "X25519", "pgp-xor", "pgp-aes"]
)
def test_parse_cipher_mode_for_each_crypto_system(crypto_system):
    args = parse_input([crypto_system, "-c", "mykey"])

    assert args.crypto_system == crypto_system
    assert args.mode == "c"
    assert args.key == "mykey"
    assert args.single_block is False
    assert args.primes is None


@pytest.mark.parametrize("mode", ["-c", "-d"])
def test_parse_message_modes(mode):
    args = parse_input(["aes", mode, "mykey"])

    assert args.mode == mode[1:]
    assert args.key == "mykey"


@pytest.mark.parametrize("crypto_system", ["xor", "aes", "pgp-xor", "pgp-aes"])
def test_parse_single_block_for_symmetric_systems(crypto_system):
    args = parse_input([crypto_system, "-c", "mykey", "-b"])

    assert args.single_block is True


def test_parse_rsa_key_generation():
    args = parse_input(["rsa", "-g", "11", "17"])

    assert args.crypto_system == "rsa"
    assert args.mode == "g"
    assert args.key is None
    assert args.single_block is False
    assert args.primes == (17, 23)


def test_parse_x25519_key_generation():
    args = parse_input(["X25519", "-g"])

    assert args.crypto_system == "X25519"
    assert args.mode == "g"
    assert args.key is None
    assert args.primes == ()


@pytest.mark.parametrize("mode", ["-c", "-d"])
def test_parse_uppercase_x25519_message_modes(mode):
    args = parse_input(["X25519", mode, "mykey"])

    assert args.crypto_system == "X25519"
    assert args.mode == mode[1:]


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["unknown", "-c", "key"],
        ["aes"],
        ["aes", "-c"],
        ["aes", "-d"],
        ["aes", "-c", "key", "-d"],
        ["xor", "-g", "17", "23"],
        ["rsa", "-g", "17"],
        ["X25519", "-g", "17", "23"],
        ["x25519", "-g"],
        ["x25519", "-c", "key"],
        ["x25519", "-d", "key"],
        ["rsa", "-g", "17", "23", "key"],
        ["rsa", "-c", "key", "-b"],
    ],
)
def test_parse_rejects_invalid_arguments(arguments):
    with pytest.raises(SystemExit):
        parse_input(arguments)


def test_help_option_exits_successfully(capsys):
    with pytest.raises(SystemExit) as error:
        parse_input(["-h"])

    assert error.value.code == 0
    output = capsys.readouterr()
    assert "usage: ./my_pgp" in output.out
    assert "Cipher or decipher MESSAGE" in output.out
    assert output.err == ""
