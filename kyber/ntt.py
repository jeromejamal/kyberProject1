class Polynomial:
    def __init__(self, coeffs=None, n=256, q=3329):
        self.n = n
        self.q = q
        self.coeffs = coeffs if coeffs is not None else [0] * n


# Corrected ZETAS array for Kyber's NTT
ZETAS = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
    2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
    732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
    1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
    107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
    430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
    1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
    418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
    1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
    478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
]


def ntt(poly: Polynomial) -> Polynomial:
    """Corrected Number Theoretic Transform for Kyber"""
    if len(poly.coeffs) != 256:
        raise ValueError("Polynomial must have 256 coefficients")

    res = poly.coeffs.copy()
    k = 0
    for level in range(7):
        distance = 1 << level
        for start in range(0, 256, distance << 1):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + distance):
                temp = (zeta * res[j + distance]) % poly.q
                res[j + distance] = (res[j] - temp) % poly.q
                res[j] = (res[j] + temp) % poly.q
    return Polynomial(res, q=poly.q)


def invntt(poly: Polynomial) -> Polynomial:
    """Corrected Inverse NTT for Kyber"""
    res = poly.coeffs.copy()
    k = 127
    for level in range(6, -1, -1):
        distance = 1 << level
        for start in range(0, 256, distance << 1):
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + distance):
                temp = res[j]
                res[j] = (temp + res[j + distance]) % poly.q
                res[j + distance] = ((temp - res[j + distance]) * zeta) % poly.q

    # Final scaling with 1/128 mod q
    f = 1441  # 1441 ≡ 1/128 mod 3329
    res = [(x * f) % poly.q for x in res]
    return Polynomial(res, q=poly.q)