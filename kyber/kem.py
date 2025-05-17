from typing import Tuple
from .pke import keygen, encrypt, decrypt
from .symmetric import hash_g, hash_h, kdf
from .params import KYBER512
import os


class KyberKEM:
    def __init__(self, params=KYBER512):
        self.params = params

    def keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate public key and secret key
        Returns: (pk, sk) as bytes
        """
        # Step 1: Generate (pk', sk') using PKE.KeyGen
        pk_pke, sk_pke = keygen(self.params)

        # Step 2: Generate random z ∈ B^32
        z = os.urandom(32)

        # Step 3: Return (pk, sk) = (pk', (sk' ‖ pk' ‖ h ‖ z))
        h = hash_h(pk_pke)
        sk = sk_pke + pk_pke + h + z

        return pk_pke, sk

    def encapsulate(self, pk: bytes) -> Tuple[bytes, bytes]:
        """
        Generate ciphertext and shared secret
        Returns: (ciphertext, shared_secret)
        """
        # Step 1: Generate random m ∈ B^32
        m = os.urandom(32)

        # Step 2: Compute (K, r) = G(m ‖ H(pk))
        h_pk = hash_h(pk)
        K_r = hash_g(m + h_pk)
        K = K_r[:32]  # First 32 bytes
        r = K_r[32:]  # Remaining bytes

        # Step 3: Compute ciphertext c = PKE.Encrypt(pk, m; r)
        c = encrypt(pk, m, r, self.params)

        # Step 4: Compute shared secret K = KDF(K ‖ H(c))
        h_c = hash_h(c)
        shared_secret = kdf(K + h_c)

        return c, shared_secret

    def decapsulate(self, c: bytes, sk: bytes) -> bytes:
        """
        Recover shared secret from ciphertext
        Returns: shared_secret
        """
        # Step 1: Parse sk = (sk' ‖ pk' ‖ h ‖ z)
        sk_len = self.params.k * 32  # Size of sk'
        sk_pke = sk[:sk_len]
        pk_pke = sk[sk_len:sk_len * 2]
        h = sk[sk_len * 2:sk_len * 2 + 32]
        z = sk[sk_len * 2 + 32:]

        # Step 2: Decrypt m' = PKE.Decrypt(sk', c)
        m_prime = decrypt(sk_pke, c, self.params)

        # Step 3: Compute (K', r') = G(m' ‖ h)
        K_r_prime = hash_g(m_prime + h)
        K_prime = K_r_prime[:32]
        r_prime = K_r_prime[32:]

        # Step 4: Compute c' = PKE.Encrypt(pk', m'; r')
        c_prime = encrypt(pk_pke, m_prime, r_prime, self.params)

        # Step 5: Compute shared secret
        h_c = hash_h(c)
        if c == c_prime:
            # Case 1: c is valid
            shared_secret = kdf(K_prime + h_c)
        else:
            # Case 2: c is invalid
            shared_secret = kdf(z + h_c)

        return shared_secret