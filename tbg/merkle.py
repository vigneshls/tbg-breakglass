"""Append-only Merkle log following RFC 9162 (Certificate Transparency v2).

Leaf hash  = SHA-256(0x00 || leaf)
Node hash  = SHA-256(0x01 || left || right)
Empty tree = SHA-256("")

Proof generation follows the PATH / PROOF / SUBPROOF definitions of RFC 9162
section 2.1; verification follows sections 2.1.3.2 and 2.1.4.2.
Hashes of complete (power-of-two, aligned) subtrees are cached so that roots
and proofs over large logs cost O(log^2 n) after the first computation.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Tuple

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split_point(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class MerkleLog:
    def __init__(self) -> None:
        self.leaves: List[bytes] = []
        self.hashes: List[bytes] = []
        self._cache: Dict[Tuple[int, int], bytes] = {}

    # ---------------------------------------------------------------- basics
    def __len__(self) -> int:
        return len(self.leaves)

    def append(self, leaf: bytes) -> int:
        self.leaves.append(leaf)
        self.hashes.append(leaf_hash(leaf))
        return len(self.leaves) - 1

    def _mth(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return self.hashes[lo]
        perfect = (n & (n - 1)) == 0
        if perfect:
            cached = self._cache.get((lo, n))
            if cached is not None:
                return cached
        k = _split_point(n)
        h = node_hash(self._mth(lo, lo + k), self._mth(lo + k, hi))
        if perfect:
            self._cache[(lo, n)] = h
        return h

    def root(self, size: int | None = None) -> bytes:
        size = len(self) if size is None else size
        if size > len(self):
            raise ValueError("size exceeds log length")
        return self._mth(0, size)

    # ---------------------------------------------------------------- proofs
    def inclusion_proof(self, index: int, size: int) -> List[bytes]:
        if not 0 <= index < size <= len(self):
            raise ValueError("bad inclusion proof request")
        return self._path(index, 0, size)

    def _path(self, m: int, lo: int, hi: int) -> List[bytes]:
        n = hi - lo
        if n <= 1:
            return []
        k = _split_point(n)
        if m < k:
            return self._path(m, lo, lo + k) + [self._mth(lo + k, hi)]
        return self._path(m - k, lo + k, hi) + [self._mth(lo, lo + k)]

    def consistency_proof(self, old_size: int, new_size: int) -> List[bytes]:
        if not 0 <= old_size <= new_size <= len(self):
            raise ValueError("bad consistency proof request")
        if old_size == 0 or old_size == new_size:
            return []
        return self._subproof(old_size, 0, new_size, True)

    def _subproof(self, m: int, lo: int, hi: int, complete: bool) -> List[bytes]:
        n = hi - lo
        if m == n:
            return [] if complete else [self._mth(lo, hi)]
        k = _split_point(n)
        if m <= k:
            return self._subproof(m, lo, lo + k, complete) + [self._mth(lo + k, hi)]
        return self._subproof(m - k, lo + k, hi, False) + [self._mth(lo, lo + k)]


# -------------------------------------------------------------------- verify
def verify_inclusion(index: int, size: int, lhash: bytes, proof: List[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, lhash
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = node_hash(p, r)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes,
                       proof: List[bytes]) -> bool:
    """RFC 9162 section 2.1.4.2 (old_size == 0 is trivially consistent)."""
    if old_size == 0:
        return proof == []
    if old_size > new_size:
        return False
    if old_size == new_size:
        return proof == [] and old_root == new_root
    path = list(proof)
    if (old_size & (old_size - 1)) == 0:  # exact power of two
        path = [old_root] + path
    if not path:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not (fn & 1):
                while not (fn & 1) and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0
