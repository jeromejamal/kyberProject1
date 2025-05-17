# kyber/params.py
from typing import NamedTuple

class KyberParams(NamedTuple):
    """
    Kyber parameters structure containing:
    - k: main security parameter (2, 3, or 4)
    - n: polynomial degree (always 256)
    - q: modulus (always 3329)
    - eta1: sampling parameter for secret vectors
    - eta2: sampling parameter for error vectors
    - du: compression parameter for u
    - dv: compression parameter for v
    """
    k: int
    n: int
    q: int
    eta1: int
    eta2: int
    du: int
    dv: int

# Kyber-512 Parameters (Security Level 1)
KYBER512 = KyberParams(
    k=2,
    n=256,
    q=3329,
    eta1=3,
    eta2=2,
    du=10,
    dv=4
)

# Kyber-768 Parameters (Security Level 3)
KYBER768 = KyberParams(
    k=3,
    n=256,
    q=3329,
    eta1=2,
    eta2=2,
    du=10,
    dv=4
)

# Kyber-1024 Parameters (Security Level 5)
KYBER1024 = KyberParams(
    k=4,
    n=256,
    q=3329,
    eta1=2,
    eta2=2,
    du=11,
    dv=5
)