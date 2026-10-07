import secrets

from .cipher import encrypt_message, decrypt_message


_FIELD_PRIME = 2**255 - 19
_A24 = 121665
_KEY_SIZE = 32
_BASE_POINT = 9


def x25519(private_key: bytes, public_key: bytes) -> bytes:
    if len(private_key) != _KEY_SIZE:
        raise ValueError("X25519 private keys must be exactly 32 bytes")
    if len(public_key) != _KEY_SIZE:
        raise ValueError("X25519 public keys must be exactly 32 bytes")

    scalar_bytes = bytearray(private_key)
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 127
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")

    coordinate = int.from_bytes(public_key, "little") & (2**255 - 1)
    coordinate %= _FIELD_PRIME
    x_2, z_2 = 1, 0
    x_3, z_3 = coordinate, 1
    swap = 0

    for bit_index in range(254, -1, -1):
        bit = (scalar >> bit_index) & 1
        swap ^= bit
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = bit

        a = (x_2 + z_2) % _FIELD_PRIME
        aa = (a * a) % _FIELD_PRIME
        b = (x_2 - z_2) % _FIELD_PRIME
        bb = (b * b) % _FIELD_PRIME
        e = (aa - bb) % _FIELD_PRIME
        c = (x_3 + z_3) % _FIELD_PRIME
        d = (x_3 - z_3) % _FIELD_PRIME
        da = (d * a) % _FIELD_PRIME
        cb = (c * b) % _FIELD_PRIME
        x_3 = ((da + cb) ** 2) % _FIELD_PRIME
        z_3 = (coordinate * ((da - cb) ** 2)) % _FIELD_PRIME
        x_2 = (aa * bb) % _FIELD_PRIME
        z_2 = (e * (aa + _A24 * e)) % _FIELD_PRIME

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    result = (x_2 * pow(z_2, _FIELD_PRIME - 2, _FIELD_PRIME)) % _FIELD_PRIME
    shared_secret = result.to_bytes(_KEY_SIZE, "little")
    if shared_secret == bytes(_KEY_SIZE):
        raise ValueError("X25519 produced an all-zero shared secret")
    return shared_secret


def x25519_public_key(private_key: bytes) -> bytes:
    return x25519(private_key, _BASE_POINT.to_bytes(_KEY_SIZE, "little"))


def generate_keypair() -> tuple[bytes, bytes]:
    private_key = secrets.token_bytes(_KEY_SIZE)
    return private_key, x25519_public_key(private_key)


def encrypt(message: bytes, public_key: bytes) -> bytes:
    if len(public_key) != _KEY_SIZE:
        raise ValueError("X25519 public keys must be exactly 32 bytes")
    ephemeral_private, ephemeral_public = generate_keypair()
    shared_secret = x25519(ephemeral_private, public_key)
    return encrypt_message(message, shared_secret, ephemeral_public, public_key)


def decrypt(ciphertext: bytes, private_key: bytes) -> bytes:
    if len(private_key) != _KEY_SIZE:
        raise ValueError("X25519 private keys must be exactly 32 bytes")
    if len(ciphertext) < 84 or ciphertext[:4] != b"X25\x01":
        raise ValueError("invalid X25519 ciphertext format")
    ephemeral_public = ciphertext[4:36]
    public_key = x25519_public_key(private_key)
    shared_secret = x25519(private_key, ephemeral_public)
    return decrypt_message(ciphertext, shared_secret, ephemeral_public, public_key)