##
## EPITECH PROJECT, 2026
## my_pgp
## File description:
## parsing
##


import argparse

from .valids_options import CRYPTO_SYSTEMS, SYMMETRIC_SYSTEMS


def parse_prime(value: str) -> int:
	try:
		return int.from_bytes(bytes.fromhex(value), "little")
	except ValueError:
		raise argparse.ArgumentTypeError(f"invalid hexadecimal number: {value}")

class MyArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        import sys

        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(84)


def build_parser():

    parser = MyArgumentParser(
        prog="./my_pgp",
        usage="%(prog)s CRYPTO_SYSTEM MODE [OPTIONS] [key]",
        description=(
            "DESCRIPTION\n"
            "\n"
            "Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM. "
            "The MESSAGE is read from the standard input."
        ),
    )
    parser.add_argument(
        "crypto_system",
        choices=CRYPTO_SYSTEMS,
        metavar="CRYPTO_SYSTEM",
        help="algorithm used to process the message",
    )

    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument(
        "-c",
        dest="cipher",
        action="store_true",
        help="MESSAGE is clear and we want to cipher it",
    )
    modes.add_argument(
        "-d",
        dest="decipher",
        action="store_true",
        help="MESSAGE is ciphered and we want to decipher it",
    )
    modes.add_argument(
        "-g",
        dest="primes",
        nargs=2,
        metavar=("P", "Q"),
        type=parse_prime,
        help="RSA only: don't read a MESSAGE, but instead generate a public and private key pair from the prime number P and Q",
    )
    parser.add_argument(
        "-b", dest="single_block", action="store_true", help="process one block only"
    )
    parser.add_argument(
        "key",
        nargs="?",
        help="Key used to cipher/decipher MESSAGE (incompatible with -g MODE)",
    )

    return parser
