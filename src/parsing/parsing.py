##
## EPITECH PROJECT, 2026
## my_pgp
## File description:
## parsing
##


from dataclasses import dataclass
from typing import Optional, Sequence, Tuple
from .valids_options import SYMMETRIC_SYSTEMS
from .parser import build_parser


@dataclass(frozen=True)  # just to make it secure
class ParsedArguments:
    """Validated command-line arguments."""

    crypto_system: str
    mode: str
    single_block: bool = False
    key: Optional[str] = None
    primes: Optional[Tuple[int, int]] = None


def _mode_from_namespace(arguments):
    if arguments.primes is not None:
        return "g"
    if arguments.cipher:
        return "c"

    return "d"


def _validate_arguments(arguments, parser):
    mode = _mode_from_namespace(arguments)

    # Careful RSA only for g
    if mode == "g" and arguments.crypto_system != "rsa":
        parser.error("-g can only be used with the rsa crypto system")
    if mode == "g" and arguments.key is not None:
        parser.error("a key cannot be used with -g")

    if arguments.single_block and arguments.crypto_system not in SYMMETRIC_SYSTEMS:
        parser.error("-b can only be used with xor, aes, pgp-xor or pgp-aes")
    if mode != "g" and arguments.key is None:
        parser.error("a key is required with -c or -d")


def parse_input(arguments: Optional[Sequence[str]] = None) -> ParsedArguments:
    """Parse and validate command-line arguments."""
    parser = build_parser()
    parsed = parser.parse_intermixed_args(arguments)
    _validate_arguments(parsed, parser)
    return ParsedArguments(
        crypto_system=parsed.crypto_system,
        mode=_mode_from_namespace(parsed),
        single_block=parsed.single_block,
        key=parsed.key,
        primes=tuple(parsed.primes) if parsed.primes is not None else None,
    )
