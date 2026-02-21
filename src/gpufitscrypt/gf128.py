"""GF(2^128) arithmetic for AES-GCM GHASH computation.

Elements are 128-bit integers where the most significant bit (bit 127)
corresponds to the coefficient of x^0, consistent with NIST SP 800-38D.

The field uses the irreducible polynomial:
    f(x) = x^128 + x^7 + x^2 + x + 1

In the MSB-first bit ordering used by GCM, the reduction constant R
encodes x^7 + x^2 + x + 1 with x^0 at bit 127:
    R = 0xE1000000000000000000000000000000
"""

# Reduction polynomial R for GF(2^128) in GCM bit ordering.
# Represents x^0 + x^1 + x^2 + x^7 at bit positions 127, 126, 125, 120.
_GCM_POLY = 0xE1000000000000000000000000000000

# Multiplicative identity: element "1" = x^0 has bit 127 set.
GF128_ONE = 1 << 127


def gf128_mul(x: int, y: int) -> int:
    """Multiply two GF(2^128) elements x and y using the GCM field.

    Implements Algorithm 1 from NIST SP 800-38D, Section 6.3.
    Iterates over the bits of y from MSB (x^0 coefficient) to LSB (x^127).

    Args:
        x: First GF(2^128) element as a 128-bit integer.
        y: Second GF(2^128) element as a 128-bit integer.

    Returns:
        The product x * y in GF(2^128).
    """
    z = 0
    v = x
    for i in range(128):
        if y & (1 << (127 - i)):
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _GCM_POLY
        else:
            v >>= 1
    return z


def gf128_pow(base: int, exp: int) -> int:
    """Compute base^exp in GF(2^128) using square-and-multiply.

    Args:
        base: A GF(2^128) element.
        exp:  Non-negative integer exponent.

    Returns:
        base^exp in GF(2^128).  Returns GF128_ONE when exp == 0.
    """
    result = GF128_ONE
    b = base
    while exp > 0:
        if exp & 1:
            result = gf128_mul(result, b)
        b = gf128_mul(b, b)
        exp >>= 1
    return result
