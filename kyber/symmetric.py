import os
from hashlib import shake_128
from typing import Tuple


def hash_g(msg: bytes) -> bytes:
    """
    Hash function G used in Kyber
    Takes arbitrary-length input, outputs 64 bytes (for K||r)
    """
    return shake_128(msg).digest(64)


def hash_h(msg: bytes) -> bytes:
    """
    Hash function H used in Kyber
    Takes arbitrary-length input, outputs 32 bytes
    """
    return shake_128(msg).digest(32)


def kdf(msg: bytes) -> bytes:
    """
    Key derivation function used in Kyber
    Takes arbitrary-length input, outputs 32 bytes
    """
    return shake_128(msg).digest(32)


def prf(seed: bytes, length: int) -> bytes:
    """
    Pseudo-Random Function (PRF) used in Kyber
    Takes a seed and output length, returns pseudorandom bytes
    """
    return shake_128(seed).digest(length)


def xof(seed: bytes, length: int) -> bytes:
    """
    Extendable-Output Function (XOF) used for sampling
    Takes a seed and output length, returns pseudorandom bytes
    """
    return shake_128(seed).digest(length)


def parse_hash_g_output(hash_output: bytes) -> Tuple[bytes, bytes]:
    """
    Helper function to parse G output into (K, r) tuple
    G(msg) = K || r where K is 32 bytes and r is 32 bytes
    """
    if len(hash_output) != 64:
        raise ValueError("hash_g output must be 64 bytes")
    return hash_output[:32], hash_output[32:]


def cbd(eta: int, buf: bytes, n: int = 256) -> list:
    """
    Centered Binomial Distribution sampling
    Converts input bytes to polynomial coefficients following CBD
    """
    if len(buf) != eta * n // 4:
        raise ValueError(f"Input buffer must be {eta * n // 4} bytes for η={eta}")

    coefficients = []
    for i in range(n):
        a = sum((buf[4 * i + j // 8] >> (j % 8)) & 1 for j in range(eta))
        b = sum((buf[4 * i + j // 8 + eta // 2] >> (j % 8)) & 1 for j in range(eta))
        coefficients.append(a - b)
    return coefficients


def generate_random_bytes(length: int = 32) -> bytes:
    """
    Cryptographically secure random bytes generation
    Uses os.urandom() which is suitable for cryptographic use
    """
    return os.urandom(length)