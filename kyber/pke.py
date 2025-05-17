from typing import Tuple, List
from .params import KYBER512, KyberParams
from .poly import Polynomial
from .ntt import ntt, invntt
from .symmetric import hash_g, hash_h, prf
import os


def keygen(params: KyberParams = KYBER512) -> Tuple[bytes, bytes]:
    """
    Generate public and secret keys
    Returns: (public_key, secret_key) as bytes
    """
    # 1. Generate random seed ρ ∈ B^32
    rho = os.urandom(32)

    # 2. Generate matrix A ∈ R^(k×k) from ρ
    A = generate_matrix_A(rho, params)

    # 3. Sample secret s ∈ R^k with coefficients in [-η, η]
    s = [sample_noise_poly(params.eta1, params.n) for _ in range(params.k)]

    # 4. Sample error e ∈ R^k with coefficients in [-η, η]
    e = [sample_noise_poly(params.eta1, params.n) for _ in range(params.k)]

    # 5. Compute t = A ◦ s + e
    t = [Polynomial([0] * params.n) for _ in range(params.k)]
    for i in range(params.k):
        for j in range(params.k):
            t[i] += A[i][j] * s[j]
        t[i] += e[i]
        t[i] = ntt(t[i])

    # 6. Return (pk, sk) = (encode_pk(t, rho), encode_sk(s))
    pk = encode_pk(t, rho, params)
    sk = encode_sk(s, params)
    return pk, sk


def encrypt(pk: bytes, m: bytes, r: bytes, params: KyberParams = KYBER512) -> bytes:
    """
    Encrypt message m with public key pk using randomness r
    Returns: ciphertext as bytes
    """
    # 1. Parse pk = (t, ρ)
    t, rho = decode_pk(pk, params)

    # 2. Generate matrix A ∈ R^(k×k) from ρ
    A = generate_matrix_A(rho, params)

    # 3. Sample r ∈ R^k from randomness seed
    r_poly = sample_poly_from_seed(r, params.eta1, params.n)

    # 4. Sample e1 ∈ R^k and e2 ∈ R
    e1 = [sample_noise_poly(params.eta1, params.n) for _ in range(params.k)]
    e2 = sample_noise_poly(params.eta2, params.n)

    # 5. Compute u = A^T ◦ r + e1
    u = [Polynomial([0] * params.n) for _ in range(params.k)]
    for i in range(params.k):
        for j in range(params.k):
            u[i] += A[j][i] * r_poly  # Note: A^T means we use A[j][i]
        u[i] += e1[i]

    # 6. Compute v = t^T ◦ r + e2 + m
    m_poly = decode_message(m, params.n)
    v = Polynomial([0] * params.n)
    for i in range(params.k):
        v += t[i] * r_poly
    v += e2 + m_poly

    # 7. Compress and return ciphertext
    return compress_ciphertext(u, v, params)


def decrypt(sk: bytes, c: bytes, params: KyberParams = KYBER512) -> bytes:
    """
    Decrypt ciphertext c with secret key sk
    Returns: message as bytes
    """
    # 1. Parse sk = s
    s = decode_sk(sk, params)

    # 2. Decompress ciphertext to (u, v)
    u, v = decompress_ciphertext(c, params)

    # 3. Compute m = v - s^T ◦ u
    m_poly = v.copy()
    for i in range(params.k):
        m_poly -= s[i] * u[i]

    # 4. Decode and return message
    return encode_message(m_poly, params.n)


# Helper Functions ------------------------------------------------------------

def generate_matrix_A(rho: bytes, params: KyberParams) -> List[List[Polynomial]]:
    """Generate matrix A from seed ρ using SHAKE-128"""
    A = [[None for _ in range(params.k)] for _ in range(params.k)]
    for i in range(params.k):
        for j in range(params.k):
            # SHAKE-128 produces a stream of bytes for each polynomial
            seed = rho + bytes([i, j])
            stream = prf(seed, params.n * 3)  # 3 bytes per coefficient
            coeffs = []
            for k in range(params.n):
                # Parse 3 bytes into a coefficient
                val = int.from_bytes(stream[3 * k:3 * k + 3], 'little')
                coeffs.append(val % params.q)
            A[i][j] = Polynomial(coeffs)
    return A


def sample_noise_poly(eta: int, n: int) -> Polynomial:
    """Sample polynomial with binomial noise distribution"""
    coeffs = []
    for _ in range(n):
        # Binomial distribution: sum of η 1s minus sum of η -1s
        val = sum(1 if os.urandom(1)[0] < 128 else -1 for _ in range(eta))
        coeffs.append(val)
    return Polynomial(coeffs)


def sample_poly_from_seed(seed: bytes, eta: int, n: int) -> Polynomial:
    """Deterministically sample polynomial from seed"""
    # Expand seed using PRF
    stream = prf(seed, n * eta)
    coeffs = []
    for i in range(n):
        bits = stream[i * eta:(i + 1) * eta]
        val = sum(1 if bit < 128 else -1 for bit in bits)
        coeffs.append(val)
    return Polynomial(coeffs)


# Serialization Functions -----------------------------------------------------

def encode_pk(t: List[Polynomial], rho: bytes, params: KyberParams) -> bytes:
    """Serialize public key to bytes"""
    pk = bytearray()
    for poly in t:
        for coeff in poly.coeffs:
            pk += coeff.to_bytes(3, 'little')
    pk += rho
    return bytes(pk)


def decode_pk(pk: bytes, params: KyberParams) -> Tuple[List[Polynomial], bytes]:
    """Deserialize public key from bytes"""
    t = []
    pos = 0
    for _ in range(params.k):
        coeffs = []
        for _ in range(params.n):
            coeff = int.from_bytes(pk[pos:pos + 3], 'little')
            coeffs.append(coeff)
            pos += 3
        t.append(Polynomial(coeffs))
    rho = pk[pos:pos + 32]
    return t, rho


def encode_sk(s: List[Polynomial], params: KyberParams) -> bytes:
    """Serialize secret key to bytes"""
    sk = bytearray()
    for poly in s:
        for coeff in poly.coeffs:
            sk += coeff.to_bytes(2, 'little', signed=True)
    return bytes(sk)


def decode_sk(sk: bytes, params: KyberParams) -> List[Polynomial]:
    """Deserialize secret key from bytes"""
    s = []
    pos = 0
    for _ in range(params.k):
        coeffs = []
        for _ in range(params.n):
            coeff = int.from_bytes(sk[pos:pos + 2], 'little', signed=True)
            coeffs.append(coeff)
            pos += 2
        s.append(Polynomial(coeffs))
    return s


def compress_ciphertext(u: List[Polynomial], v: Polynomial, params: KyberParams) -> bytes:
    """Compress ciphertext components into bytes"""
    c = bytearray()

    # Compress u
    for poly in u:
        for coeff in poly.coeffs:
            # Compress to du bits
            compressed = ((coeff << params.du) + params.q // 2) // params.q
            c.append(compressed & 0xff)
            if params.du > 8:
                c.append((compressed >> 8) & 0xff)

    # Compress v
    for coeff in v.coeffs:
        # Compress to dv bits
        compressed = ((coeff << params.dv) + params.q // 2) // params.q
        c.append(compressed & 0xff)
        if params.dv > 8:
            c.append((compressed >> 8) & 0xff)

    return bytes(c)


def decompress_ciphertext(c: bytes, params: KyberParams) -> Tuple[List[Polynomial], Polynomial]:
    """Decompress ciphertext from bytes"""
    u = []
    pos = 0

    # Decompress u
    for _ in range(params.k):
        coeffs = []
        for _ in range(params.n):
            if params.du <= 8:
                compressed = c[pos]
                pos += 1
            else:
                compressed = c[pos] | (c[pos + 1] << 8)
                pos += 2
            coeff = ((compressed * params.q) + (1 << (params.du - 1))) >> params.du
            coeffs.append(coeff)
        u.append(Polynomial(coeffs))

    # Decompress v
    coeffs = []
    for _ in range(params.n):
        if params.dv <= 8:
            compressed = c[pos]
            pos += 1
        else:
            compressed = c[pos] | (c[pos + 1] << 8)
            pos += 2
        coeff = ((compressed * params.q) + (1 << (params.dv - 1))) >> params.dv
        coeffs.append(coeff)
    v = Polynomial(coeffs)

    return u, v


def decode_message(msg: bytes, n: int) -> Polynomial:
    """Convert message bytes to polynomial"""
    coeffs = []
    for byte in msg:
        bits = [(byte >> i) & 1 for i in range(8)]
        coeffs.extend(bits)
    return Polynomial(coeffs[:n])


def encode_message(poly: Polynomial, n: int) -> bytes:
    """Convert polynomial to message bytes"""
    bits = [1 if coeff > 0 else 0 for coeff in poly.coeffs[:n]]
    msg = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        msg.append(byte)
    return bytes(msg)