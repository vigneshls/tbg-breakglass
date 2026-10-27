"""Shamir (t, n) secret sharing over GF(2^8), applied bytewise.

Field: GF(2^8) with the AES reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
Share i is the evaluation of a random degree-(t-1) polynomial at x = i (1..n),
one independent polynomial per secret byte. Any t shares reconstruct the
secret by Lagrange interpolation at x = 0; t-1 shares are independent of it.
"""
from __future__ import annotations

import os
from typing import Dict, List, Tuple

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # multiply by generator 0x03
        x ^= (x << 1) ^ (0x11B if x & 0x80 else 0)
        x &= 0xFF
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^8)")
    return _EXP[255 - _LOG[a]]


def split(secret: bytes, t: int, n: int) -> List[Tuple[int, bytes]]:
    """Return n shares (x, y-bytes), x in 1..n."""
    if not 1 <= t <= n <= 255:
        raise ValueError("require 1 <= t <= n <= 255")
    coeffs = [os.urandom(t - 1) for _ in secret]  # per byte: c1..c_{t-1}
    shares = []
    for x in range(1, n + 1):
        out = bytearray(len(secret))
        for j, s in enumerate(secret):
            # Horner evaluation of s + c1 x + ... + c_{t-1} x^{t-1}
            y = 0
            for c in reversed(coeffs[j]):
                y = gf_mul(y, x) ^ c
            y = gf_mul(y, x) ^ s
            out[j] = y
        shares.append((x, bytes(out)))
    return shares


def reconstruct(shares: List[Tuple[int, bytes]]) -> bytes:
    """Lagrange interpolation at 0 from the given shares (use exactly t)."""
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share indices")
    length = len(shares[0][1])
    # Lagrange basis at 0: l_i = prod_{j!=i} x_j / (x_j - x_i); in GF(2^8) minus is xor
    basis: Dict[int, int] = {}
    for i, xi in enumerate(xs):
        num, den = 1, 1
        for j, xj in enumerate(xs):
            if i != j:
                num = gf_mul(num, xj)
                den = gf_mul(den, xj ^ xi)
        basis[xi] = gf_mul(num, gf_inv(den))
    out = bytearray(length)
    for x, y in shares:
        li = basis[x]
        for k in range(length):
            out[k] ^= gf_mul(li, y[k])
    return bytes(out)
