"""Functional tests. Run: pytest -q   (set TBG_BACKEND=pq-oqs|pq-pure|classical)."""
import itertools
import os
import time

import pytest

from tbg import merkle, shamir
from tbg.backend import get_backend
from tbg.baselines import EscrowService, escrow_break_glass, escrow_protect
from tbg.scheme import (Deployment, Reject, Request, STH, TrusteeAgent, audit, break_glass,
                        equivocation_evidence, routine_access)

BE = get_backend(os.environ.get("TBG_BACKEND", "pq"))


@pytest.fixture()
def dep():
    d = Deployment(BE, t=3, n=5)
    d.add_users(["dr_a"])
    return d


def test_merkle_proofs_exhaustive():
    log = merkle.MerkleLog()
    for _ in range(40):
        log.append(os.urandom(16))
    for n in range(1, 41):
        root = log.root(n)
        for m in range(n):
            assert merkle.verify_inclusion(m, n, log.hashes[m], log.inclusion_proof(m, n), root)
        for o in range(n + 1):
            assert merkle.verify_consistency(o, n, log.root(o), root, log.consistency_proof(o, n))


def test_shamir_threshold():
    s = os.urandom(32)
    sh = shamir.split(s, 3, 5)
    for c in itertools.combinations(sh, 3):
        assert shamir.reconstruct(list(c)) == s
    assert shamir.reconstruct(sh[:2]) != s


def test_routine_and_break_glass(dep):
    data = os.urandom(5000)
    rec = dep.protect(data, "rec-1")
    assert routine_access(BE, rec, "dr_a", dep.users["dr_a"][1]) == data
    pt, tm = break_glass(BE, rec, "dr_x", "R01", dep.log, dep.agents)
    assert pt == data and tm["total"] > 0
    assert len(dep.log.log) == 2  # request leaf + approvals leaf


def test_no_share_without_log_entry(dep):
    """E6a: request never appended -> every agent refuses."""
    rec = dep.protect(b"x" * 100, "rec-2")
    ek_d, _ = BE.kem_keygen()
    req = Request("rec-2", "dr_x", "R01", int(time.time() * 1000), os.urandom(16), ek_d)
    head = dep.log.sth()
    for a in dep.agents:
        with pytest.raises(Reject):
            a.release(req, 0, head, [], [], rec)


def test_fewer_than_t_agents_fail(dep):
    """E6b."""
    rec = dep.protect(b"y" * 100, "rec-3")
    with pytest.raises(Reject):
        break_glass(BE, rec, "dr_x", "R01", dep.log, dep.agents[:2])


def test_officer_refusal_counts(dep):
    rec = dep.protect(b"z" * 100, "rec-4")
    for a in dep.agents[:3]:
        a.approve = lambda r: False
    with pytest.raises(Reject):  # 3 of 5 officers decline -> only 2 shares
        break_glass(BE, rec, "dr_x", "R01", dep.log, dep.agents)
    dep.agents[0].approve = lambda r: True  # one officer reconsiders -> 3 shares
    pt, _ = break_glass(BE, rec, "dr_x", "R01", dep.log, dep.agents)
    assert pt == b"z" * 100


def test_replay_and_stale_rejected(dep):
    rec = dep.protect(b"w" * 100, "rec-5")
    ek_d, _ = BE.kem_keygen()
    req = Request("rec-5", "dr_x", "R01", int(time.time() * 1000), os.urandom(16), ek_d)
    m, head = dep.log.append(req.leaf())
    incl = dep.log.inclusion_proof(m, head.size)
    a = dep.agents[0]
    a.release(req, m, head, incl, dep.log.consistency_proof(0, head.size), rec)
    with pytest.raises(Reject, match="replayed"):
        a.release(req, m, head, incl, [], rec)
    old = Request("rec-5", "dr_x", "R01", int(time.time() * 1000) - 10 * 60_000, os.urandom(16), ek_d)
    m2, head2 = dep.log.append(old.leaf())
    with pytest.raises(Reject, match="stale"):
        dep.agents[1].release(old, m2, head2, dep.log.inclusion_proof(m2, head2.size),
                              dep.log.consistency_proof(0, head2.size), rec)


def test_forked_log_rejected(dep):
    """E5/E6: agent saw head N; maintainer then shows a tree that rewrites history."""
    rec = dep.protect(b"v" * 100, "rec-6")
    break_glass(BE, rec, "dr_x", "R01", dep.log, dep.agents)  # agents now hold a head
    seen = STH(dep.agents[0].last_size, dep.agents[0].last_root, b"")
    # build a forked log that drops history and contains a fresh request
    fork = merkle.MerkleLog()
    ek_d, _ = BE.kem_keygen()
    req = Request("rec-6", "dr_y", "R01", int(time.time() * 1000), os.urandom(16), ek_d)
    for _ in range(seen.size):
        fork.append(os.urandom(20))
    m = fork.append(req.leaf())
    fake = dep.log.sign_head(len(fork), fork.root())
    with pytest.raises(Reject, match="consistent"):
        dep.agents[0].release(req, m, fake, fork.inclusion_proof(m, len(fork)),
                              fork.consistency_proof(seen.size, len(fork)), rec)
    real = dep.log.sth()
    assert equivocation_evidence(BE, dep.log.vk, real, dep.log.sign_head(real.size, os.urandom(32)))


def test_audit_detects_modification(dep):
    rec = dep.protect(b"u" * 100, "rec-7")
    break_glass(BE, rec, "dr_x", "R01", dep.log, dep.agents)
    head = dep.log.sth()
    assert all(audit(BE, dep.log, [head]).values())
    dep.log.log.leaves[0] = b"tampered"  # maintainer edits published data
    assert not audit(BE, dep.log, [head])["heads_match_published_leaves"]


def test_rotation(dep):
    rec = dep.protect(b"r" * 100, "rec-8")
    new = TrusteeAgent(BE, 1, dep.log.vk)
    rec.emergency[1] = dep.agents[0].rewrap_for(rec, new.ek)
    agents = [new] + dep.agents[1:]
    pt, _ = break_glass(BE, rec, "dr_x", "R01", dep.log, agents)
    assert pt == b"r" * 100


def test_escrow_baseline():
    esc = EscrowService(BE)
    nonce, ct, _, env = escrow_protect(BE, b"e" * 64, "rec-9", {}, esc)
    pt, _ = escrow_break_glass(BE, "rec-9", nonce, ct, env, esc, "dr_x")
    assert pt == b"e" * 64
