# tests/test_basic.py
from kyber import Kyber512  # NOT from venv!
# In test_basic.py temporarily add:
import sys
print(sys.path)

def test_encryption():
    print("\nStarting test...")

    # 1. Initialize
    print("1. Creating Kyber512 instance...")
    kem = Kyber512()

    # 2. Key generation
    print("2. Generating keys...")
    pk, sk = kem.keypair()
    print(f"   Public key: {len(pk)} bytes")
    print(f"   Secret key: {len(sk)} bytes")

    # 3. Encapsulation
    print("3. Encrypting...")
    ct, ss = kem.encapsulate(pk)
    print(f"   Ciphertext: {len(ct)} bytes")
    print(f"   Shared secret: {ss[:4].hex()}...")

    # 4. Decapsulation
    print("4. Decrypting...")
    recovered = kem.decapsulate(ct, sk)

    # 5. Verification
    assert recovered == ss, "ERROR: Secrets don't match!"
    print("SUCCESS! Test passed.")


if __name__ == "__main__":
    test_encryption()