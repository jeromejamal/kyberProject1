class Polynomial:
    def __init__(self, coeffs=None, n=256, q=3329):
        """
        Initialize a polynomial with:
        - coeffs: coefficient list (default all zeros)
        - n: maximum degree (default 256 for Kyber)
        - q: modulus (default 3329 for Kyber)
        """
        self.n = n
        self.q = q
        self.coeffs = coeffs or [0] * n

    def __add__(self, other):
        """Add two polynomials element-wise modulo q"""
        if self.n != other.n or self.q != other.q:
            raise ValueError("Polynomials must have same degree and modulus")
        return Polynomial(
            [(a + b) % self.q for a, b in zip(self.coeffs, other.coeffs)],
            n=self.n,
            q=self.q
        )

    def __sub__(self, other):
        """Subtract two polynomials element-wise modulo q"""
        if self.n != other.n or self.q != other.q:
            raise ValueError("Polynomials must have same degree and modulus")
        return Polynomial(
            [(a - b) % self.q for a, b in zip(self.coeffs, other.coeffs)],
            n=self.n,
            q=self.q
        )

    def __mul__(self, other):
        """Multiply two polynomials using schoolbook multiplication"""
        if self.n != other.n or self.q != other.q:
            raise ValueError("Polynomials must have same degree and modulus")

        # Schoolbook multiplication
        res = [0] * (2 * self.n)
        for i in range(self.n):
            for j in range(self.n):
                res[i + j] = (res[i + j] + self.coeffs[i] * other.coeffs[j]) % self.q

        # Modulo x^n + 1 (reduce higher terms)
        for i in range(self.n, 2 * self.n):
            res[i - self.n] = (res[i - self.n] - res[i]) % self.q

        return Polynomial(res[:self.n], n=self.n, q=self.q)

    def __mod__(self, modulus):
        """Apply modulus to all coefficients"""
        return Polynomial(
            [c % modulus for c in self.coeffs],
            n=self.n,
            q=modulus
        )

    def copy(self):
        """Create a deep copy of the polynomial"""
        return Polynomial(
            self.coeffs.copy(),
            n=self.n,
            q=self.q
        )

    def to_ntt(self):
        """Convert to NTT domain (returns new polynomial)"""
        from .ntt import ntt  # Import here to avoid circular imports
        return ntt(self)

    def to_normal(self):
        """Convert from NTT domain (returns new polynomial)"""
        from .ntt import invntt  # Import here to avoid circular imports
        return invntt(self)

    def __repr__(self):
        """String representation showing first 3 coefficients"""
        return f"Polynomial(n={self.n}, q={self.q}, coeffs={self.coeffs[:3]}...)"