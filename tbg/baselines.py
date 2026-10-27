"""Single-escrow baseline (E8b).

A software emulation of the common industry pattern: one escrow service holds
a key that can unwrap every record key, checks policy, writes a local
hash-chained audit entry, and re-wraps the record key to the requester.
It is NOT an HSM measurement: it isolates the cryptographic cost of a
single-party design with locally kept (not externally verifiable) logs.
"""
from __future__ import annotations

import time
from typing import Dict, Tuple

from .backend import Backend, aead_decrypt, aead_encrypt, random_bytes, sha256
from .scheme import Envelope, enc, unwrap, wrap


class EscrowService:
    def __init__(self, be: Backend) -> None:
        self.be = be
        self.ek, self._dk = be.kem_keygen()
        self.chain_head = b"\x00" * 32
        self.entries = 0

    def release(self, rid: str, clinician: str, env: Envelope, ek_d: bytes) -> Envelope:
        self.chain_head = sha256(self.chain_head + enc(rid.encode(), clinician.encode()))
        self.entries += 1
        key = unwrap(self.be, self._dk, env, enc(b"escrow", rid.encode()))
        return wrap(self.be, ek_d, key, enc(b"escrow-out", rid.encode()))


def escrow_protect(be: Backend, plaintext: bytes, rid: str, users: Dict[str, bytes],
                   escrow: EscrowService) -> Tuple[bytes, bytes, Dict[str, Envelope], Envelope]:
    key = random_bytes(32)
    nonce = random_bytes(12)
    ct = aead_encrypt(key, nonce, plaintext, rid.encode())
    routine = {u: wrap(be, ek, key, enc(b"routine", rid.encode(), u.encode())) for u, ek in users.items()}
    return nonce, ct, routine, wrap(be, escrow.ek, key, enc(b"escrow", rid.encode()))


def escrow_break_glass(be: Backend, rid: str, nonce: bytes, ct: bytes, env: Envelope,
                       escrow: EscrowService, clinician: str) -> Tuple[bytes, float]:
    t0 = time.perf_counter()
    ek_d, dk_d = be.kem_keygen()
    out = escrow.release(rid, clinician, env, ek_d)
    key = unwrap(be, dk_d, out, enc(b"escrow-out", rid.encode()))
    pt = aead_decrypt(key, nonce, ct, rid.encode())
    return pt, time.perf_counter() - t0
