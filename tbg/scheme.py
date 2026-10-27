"""TBG: post-quantum transparent break-glass for EMRs (reference implementation).

Section numbers refer to the manuscript (Section 4). Everything runs in one
process; network transport is out of scope, so measured latencies are
cryptographic and protocol-processing costs only.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import merkle, shamir
from .backend import Backend, aead_decrypt, aead_encrypt, hkdf, random_bytes, sha256


# ---------------------------------------------------------------- encoding
def enc(*fields: bytes) -> bytes:
    """Unambiguous length-prefixed encoding."""
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)


def u64(x: int) -> bytes:
    return struct.pack(">Q", x)


# ---------------------------------------------------------------- envelopes
@dataclass
class Envelope:
    kem_ct: bytes
    nonce: bytes
    ct: bytes

    def size(self) -> int:
        return len(self.kem_ct) + len(self.nonce) + len(self.ct)


def wrap(be: Backend, ek: bytes, x: bytes, ctx: bytes) -> Envelope:
    kem_ct, ss = be.kem_encaps(ek)
    k = hkdf(ss, ctx)
    nonce = random_bytes(12)
    return Envelope(kem_ct, nonce, aead_encrypt(k, nonce, x, ctx))


def unwrap(be: Backend, dk: bytes, env: Envelope, ctx: bytes) -> bytes:
    ss = be.kem_decaps(dk, env.kem_ct)
    return aead_decrypt(hkdf(ss, ctx), env.nonce, env.ct, ctx)


# ---------------------------------------------------------------- records
@dataclass
class Record:
    rid: str
    nonce: bytes
    ciphertext: bytes
    routine: Dict[str, Envelope]
    emergency: Dict[int, Envelope]
    t: int
    n: int

    def overhead_bytes(self, plaintext_len: int) -> int:
        env = sum(e.size() for e in self.routine.values()) + sum(e.size() for e in self.emergency.values())
        return env + len(self.nonce) + (len(self.ciphertext) - plaintext_len)


def protect(be: Backend, plaintext: bytes, rid: str, users: Dict[str, bytes],
            agent_eks: Dict[int, bytes], t: int) -> Record:
    """Section 4.2."""
    n = len(agent_eks)
    key = random_bytes(32)
    nonce = random_bytes(12)
    rid_b = rid.encode()
    ct = aead_encrypt(key, nonce, plaintext, rid_b)
    routine = {u: wrap(be, ek, key, enc(b"routine", rid_b, u.encode())) for u, ek in users.items()}
    shares = shamir.split(key, t, n)
    idx = sorted(agent_eks)
    emergency = {}
    for (x, s), i in zip(shares, idx):
        emergency[i] = wrap(be, agent_eks[i], bytes([x]) + s, enc(b"bg", rid_b, u64(i)))
    return Record(rid, nonce, ct, routine, emergency, t, n)


def routine_access(be: Backend, rec: Record, user: str, dk: bytes) -> bytes:
    key = unwrap(be, dk, rec.routine[user], enc(b"routine", rec.rid.encode(), user.encode()))
    return aead_decrypt(key, rec.nonce, rec.ciphertext, rec.rid.encode())


# ---------------------------------------------------------------- log maintainer
@dataclass
class STH:
    size: int
    root: bytes
    sig: bytes

    def message(self) -> bytes:
        return enc(b"TBG-STH", u64(self.size), self.root)


class LogMaintainer:
    """Untrusted log maintainer M. `fork()` exists only for tamper experiments."""

    def __init__(self, be: Backend) -> None:
        self.be = be
        self.vk, self._sk = be.sig_keygen()
        self.log = merkle.MerkleLog()

    def append(self, leaf: bytes) -> Tuple[int, STH]:
        m = self.log.append(leaf)
        return m, self.sth()

    def append_unsigned(self, leaf: bytes) -> int:
        """Bulk prefill without signing a head per leaf."""
        return self.log.append(leaf)

    def sth(self, size: Optional[int] = None) -> STH:
        size = len(self.log) if size is None else size
        root = self.log.root(size)
        head = STH(size, root, b"")
        head.sig = self.be.sign(self._sk, head.message())
        return head

    def inclusion_proof(self, m: int, size: int) -> List[bytes]:
        return self.log.inclusion_proof(m, size)

    def consistency_proof(self, old: int, new: int) -> List[bytes]:
        return self.log.consistency_proof(old, new)

    def sign_head(self, size: int, root: bytes) -> STH:
        """Sign an arbitrary head (used to simulate equivocation)."""
        head = STH(size, root, b"")
        head.sig = self.be.sign(self._sk, head.message())
        return head


def verify_sth(be: Backend, vk_m: bytes, head: STH) -> bool:
    return be.verify(vk_m, head.message(), head.sig)


# ---------------------------------------------------------------- requests
@dataclass
class Request:
    rid: str
    clinician: str
    reason: str
    ts_ms: int
    nonce: bytes
    ek_d: bytes

    def encode(self) -> bytes:
        return enc(b"TBG-REQ", self.rid.encode(), self.clinician.encode(), self.reason.encode(),
                   u64(self.ts_ms), self.nonce, self.ek_d)

    def leaf(self) -> bytes:
        return b"\x01" + self.encode()

    def digest(self) -> bytes:
        return sha256(self.encode())


class Reject(Exception):
    pass


# ---------------------------------------------------------------- trustee agent
class TrusteeAgent:
    """Automated trustee A_i (Section 4.3, steps 3-4)."""

    def __init__(self, be: Backend, idx: int, vk_m: bytes,
                 approve: Optional[Callable[[Request], bool]] = None,
                 window_ms: int = 300_000) -> None:
        self.be = be
        self.idx = idx
        self.ek, self._dk = be.kem_keygen()
        self.vk, self._sk = be.sig_keygen()
        self.vk_m = vk_m
        self.last_size = 0
        self.last_root = merkle.EMPTY_ROOT
        self.seen: set = set()
        self.approve = approve or (lambda r: True)
        self.window_ms = window_ms
        self.timing: Dict[str, float] = {}

    def release(self, req: Request, m: int, head: STH, incl: List[bytes],
                cons: List[bytes], rec: Record, now_ms: Optional[int] = None):
        t0 = time.perf_counter()
        if not verify_sth(self.be, self.vk_m, head):
            raise Reject("bad tree-head signature")
        t1 = time.perf_counter()
        if not merkle.verify_inclusion(m, head.size, merkle.leaf_hash(req.leaf()), incl, head.root):
            raise Reject("request not included in log")
        if head.size < self.last_size or not merkle.verify_consistency(
                self.last_size, head.size, self.last_root, head.root, cons):
            raise Reject("log not consistent with last-seen head")
        t2 = time.perf_counter()
        now_ms = int(time.time() * 1000) if now_ms is None else now_ms
        if abs(now_ms - req.ts_ms) > self.window_ms:
            raise Reject("stale request")
        if req.nonce in self.seen:
            raise Reject("replayed request")
        if self.idx not in rec.emergency or rec.rid != req.rid:
            raise Reject("no envelope for this agent/record")
        if not self.approve(req):
            raise Reject("officer declined")
        t3 = time.perf_counter()
        share = unwrap(self.be, self._dk, rec.emergency[self.idx], enc(b"bg", rec.rid.encode(), u64(self.idx)))
        f_i = wrap(self.be, req.ek_d, share, enc(b"share", req.digest(), u64(self.idx)))
        t4 = time.perf_counter()
        a_i = self.be.sign(self._sk, enc(b"TBG-APPROVE", req.digest(), u64(head.size), head.root))
        t5 = time.perf_counter()
        self.seen.add(req.nonce)
        self.last_size, self.last_root = head.size, head.root
        self.timing = {"agent_sth_verify": t1 - t0, "agent_proof_verify": t2 - t1,
                       "agent_policy": t3 - t2, "agent_share_rewrap": t4 - t3,
                       "agent_approval_sign": t5 - t4}
        return f_i, a_i

    # rotation (Section 4.5): hand share j to a successor key
    def rewrap_for(self, rec: Record, new_ek: bytes) -> Envelope:
        ctx = enc(b"bg", rec.rid.encode(), u64(self.idx))
        return wrap(self.be, new_ek, unwrap(self.be, self._dk, rec.emergency[self.idx], ctx), ctx)


# ---------------------------------------------------------------- workstation
def break_glass(be: Backend, rec: Record, clinician: str, reason: str, log: LogMaintainer,
                agents: List[TrusteeAgent], now_ms: Optional[int] = None,
                tamper: Optional[Callable] = None) -> Tuple[bytes, Dict[str, float]]:
    """Section 4.3. Contacts agents in order until t shares are obtained.

    Returns (plaintext, timing breakdown in seconds). Raises if fewer than t
    agents release a share. `tamper` lets tests alter (m, head, incl) before
    agents see them.
    """
    tm: Dict[str, float] = {}
    t0 = time.perf_counter()
    ek_d, dk_d = be.kem_keygen()
    req = Request(rec.rid, clinician, reason,
                  int(time.time() * 1000) if now_ms is None else now_ms,
                  random_bytes(16), ek_d)
    t1 = time.perf_counter()
    m, head = log.append(req.leaf())
    incl = log.inclusion_proof(m, head.size)
    t2 = time.perf_counter()
    if tamper is not None:
        m, head, incl = tamper(m, head, incl)
    shares, approvals, agent_tm = [], [], []
    t_agents = 0.0
    for a in agents:
        if len(shares) == rec.t:
            break
        ta = time.perf_counter()
        try:
            cons = log.consistency_proof(a.last_size, head.size) if a.last_size <= head.size <= len(log.log) else []
            f_i, a_i = a.release(req, m, head, incl, cons, rec, now_ms=now_ms)
        except Reject:
            t_agents += time.perf_counter() - ta
            continue
        t_agents += time.perf_counter() - ta
        shares.append((a.idx, f_i))
        approvals.append((a.idx, a_i))
        agent_tm.append(a.timing)
    if len(shares) < rec.t:
        raise Reject(f"only {len(shares)} of {rec.t} shares released")
    t3 = time.perf_counter()
    pts = []
    for i, f_i in shares:
        raw = unwrap(be, dk_d, f_i, enc(b"share", req.digest(), u64(i)))
        pts.append((raw[0], raw[1:]))
    key = shamir.reconstruct(pts)
    plaintext = aead_decrypt(key, rec.nonce, rec.ciphertext, rec.rid.encode())
    t4 = time.perf_counter()
    leaf = b"\x02" + enc(b"TBG-APPROVALS", req.digest(), *[u64(i) + s for i, s in approvals])
    log.append(leaf)
    t5 = time.perf_counter()
    tm.update({"request_keygen": t1 - t0, "log_append_and_proof": t2 - t1,
               "agents_total": t_agents, "recover_and_decrypt": t4 - t3,
               "evidence_append": t5 - t4, "total": t5 - t0})
    for k in agent_tm[0]:
        tm[k + "_sum"] = sum(d[k] for d in agent_tm)
    return plaintext, tm


# ---------------------------------------------------------------- audit (Section 4.4)
def audit(be: Backend, log: LogMaintainer, held: List[STH]) -> Dict[str, bool]:
    """Recompute the root from the published leaves and check held heads."""
    recomputed = merkle.MerkleLog()
    for leaf in log.log.leaves:
        recomputed.append(leaf)
    ok_sig = all(verify_sth(be, log.vk, h) for h in held)
    ok_match = all(h.size <= len(recomputed) and recomputed.root(h.size) == h.root for h in held)
    return {"signatures_valid": ok_sig, "heads_match_published_leaves": ok_match}


def equivocation_evidence(be: Backend, vk_m: bytes, a: STH, b: STH,
                          proof: Optional[List[bytes]] = None) -> bool:
    """True if two validly signed heads cannot both describe one append-only log."""
    if not (verify_sth(be, vk_m, a) and verify_sth(be, vk_m, b)):
        return False
    if a.size == b.size:
        return a.root != b.root
    lo, hi = (a, b) if a.size < b.size else (b, a)
    return not merkle.verify_consistency(lo.size, hi.size, lo.root, hi.root, proof or [])


# ---------------------------------------------------------------- deployment helper
@dataclass
class Deployment:
    be: Backend
    t: int
    n: int
    log: LogMaintainer = field(init=False)
    agents: List[TrusteeAgent] = field(init=False)
    users: Dict[str, Tuple[bytes, bytes]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.log = LogMaintainer(self.be)
        self.agents = [TrusteeAgent(self.be, i, self.log.vk) for i in range(1, self.n + 1)]

    def add_users(self, names: List[str]) -> None:
        for u in names:
            self.users[u] = self.be.kem_keygen()

    def protect(self, plaintext: bytes, rid: str) -> Record:
        return protect(self.be, plaintext, rid, {u: k[0] for u, k in self.users.items()},
                       {a.idx: a.ek for a in self.agents}, self.t)
