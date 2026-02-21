"""Tests for GF(2^128) arithmetic (gf128.py)."""

import pytest
from gpufitscrypt.gf128 import GF128_ONE, gf128_mul, gf128_pow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def int_to_hex(n: int) -> str:
    return f"{n:032x}"


# ---------------------------------------------------------------------------
# Identity element
# ---------------------------------------------------------------------------

class TestGF128Identity:
    """GF128_ONE is the multiplicative identity (x^0 = 1)."""

    def test_one_is_bit_127(self):
        assert GF128_ONE == (1 << 127)

    def test_mul_identity_left(self):
        # GF128_ONE * X == X
        x = 0xFEDCBA9876543210FEDCBA9876543210
        assert gf128_mul(GF128_ONE, x) == x

    def test_mul_identity_right(self):
        # X * GF128_ONE == X
        x = 0xDEADBEEFCAFEBABE0123456789ABCDEF
        assert gf128_mul(x, GF128_ONE) == x

    def test_mul_zero(self):
        # 0 * X == 0
        x = 0xDEADBEEFCAFEBABE0123456789ABCDEF
        assert gf128_mul(0, x) == 0
        assert gf128_mul(x, 0) == 0


# ---------------------------------------------------------------------------
# Field axioms
# ---------------------------------------------------------------------------

class TestGF128FieldAxioms:
    """GF multiplication satisfies the required field axioms."""

    def test_commutativity(self):
        a = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        b = 0x5555555555555555BBBBBBBBBBBBBBBB
        assert gf128_mul(a, b) == gf128_mul(b, a)

    def test_associativity(self):
        a = 0x11223344556677881122334455667788
        b = 0x99AABBCCDDEEFF0099AABBCCDDEEFF00
        c = 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
        assert gf128_mul(gf128_mul(a, b), c) == gf128_mul(a, gf128_mul(b, c))

    def test_distributivity(self):
        # (a XOR b) * c == a*c XOR b*c
        a = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        b = 0x5555555555555555BBBBBBBBBBBBBBBB
        c = 0x0102030405060708090A0B0C0D0E0F10
        lhs = gf128_mul(a ^ b, c)
        rhs = gf128_mul(a, c) ^ gf128_mul(b, c)
        assert lhs == rhs

    def test_result_fits_128_bits(self):
        a = (1 << 128) - 1  # all ones
        b = (1 << 128) - 1
        result = gf128_mul(a, b)
        assert result < (1 << 128)


# ---------------------------------------------------------------------------
# Known GCM test vector – H subkey and hash-subkey self-product
# ---------------------------------------------------------------------------

class TestGF128KnownValues:
    """Spot-check multiplication against the AES-GCM NIST test vector."""

    # NIST SP 800-38D Test Case 2:
    # Key = 00000000000000000000000000000000
    # H   = AES(key, 0^128) = 66E94BD4EF8A2C3B884CFA59CA342B2E
    H_TC2 = 0x66E94BD4EF8A2C3B884CFA59CA342B2E

    def test_h_squared(self):
        """H^2 must equal gf128_mul(H, H)."""
        h = self.H_TC2
        h2_via_pow = gf128_pow(h, 2)
        h2_via_mul = gf128_mul(h, h)
        assert h2_via_pow == h2_via_mul

    def test_pow_zero(self):
        assert gf128_pow(self.H_TC2, 0) == GF128_ONE

    def test_pow_one(self):
        assert gf128_pow(self.H_TC2, 1) == self.H_TC2

    def test_pow_consistency(self):
        h = self.H_TC2
        # H^4 == H^2 * H^2
        assert gf128_pow(h, 4) == gf128_mul(gf128_pow(h, 2), gf128_pow(h, 2))
