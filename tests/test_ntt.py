# tests/test_ntt.py
import sys
from pathlib import Path

# This line makes Python find your kyber package
sys.path.append(str(Path(__file__).parent.parent))

# Now import from your package
from kyber.ntt import Polynomial, ntt, invntt


def test_ntt():
    # Create test polynomial: 1 + x + x²
    poly = Polynomial([1, 1, 1] + [0] * 253)
    print("Original:", poly.coeffs[:5])

    # Transform
    poly_ntt = ntt(poly)
    print("NTT:", poly_ntt.coeffs[:5])

    # Inverse transform
    poly_recovered = invntt(poly_ntt)
    print("Recovered:", poly_recovered.coeffs[:5])

    # Check they match (mod q)
    assert all((x - y) % 3329 == 0 for x, y in zip(poly.coeffs, poly_recovered.coeffs))
    print("Test passed!")


if __name__ == "__main__":
    test_ntt()