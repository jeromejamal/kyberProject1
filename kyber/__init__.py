# kyber/__init__.py

# Core components
from .params import KYBER512, KYBER768, KYBER1024, KyberParams
from .poly import Polynomial
from .ntt import ntt, invntt
from .symmetric import hash_g, hash_h, kdf, prf, cbd

# Main cryptographic primitives
from .pke import keygen, encrypt, decrypt
from .kem import KyberKEM

# Version information
__version__ = "1.0.0"
__all__ = [
    # Parameters
    'KYBER512', 'KYBER768', 'KYBER1024', 'KyberParams',

    # Polynomial arithmetic
    'Polynomial', 'ntt', 'invntt',

    # Symmetric primitives
    'hash_g', 'hash_h', 'kdf', 'prf', 'cbd',

    # Public-key encryption
    'keygen', 'encrypt', 'decrypt',

    # Key encapsulation mechanism
    'KyberKEM'
]


# Optional: Add convenience functions
def Kyber512():
    """Convenience function for Kyber-512 KEM"""
    return KyberKEM(KYBER512)


def Kyber768():
    """Convenience function for Kyber-768 KEM"""
    return KyberKEM(KYBER768)


def Kyber1024():
    """Convenience function for Kyber-1024 KEM"""
    return KyberKEM(KYBER1024)