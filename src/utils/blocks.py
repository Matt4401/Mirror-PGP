##
## EPITECH PROJECT, 2026
## my_pgp
## File description:
## blocks
##


def split_into_blocks(data: bytes, block_size: int) -> list[bytes]:
    """Split data into blocks of a given size."""
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def pad_block(block: bytes, block_size: int) -> bytes:
    """Pad a block to the specified block size."""
    padding_length = block_size - len(block)
    return block + bytes(b"\x00" * padding_length)
