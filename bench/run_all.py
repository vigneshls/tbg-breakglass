"""Run experiments E1-E8 (manuscript Section 6) and write raw measurements.

Usage (from the project root):
    python -m bench.run_all --backend pq --quick          # smoke test, ~1-3 min
    python -m bench.run_all --backend pq                  # full run
    python -m bench.run_all --backend classical --only E1 E4 E8
    python -m bench.summarize results/<run-folder>        # tables with 95% CIs

Outputs in results/<timestamp>_<backend>/:
    env.json        machine, OS, Python, library versions, backend, arguments
    timings.csv     experiment,backend,config,metric,iteration,value_ms
    sizes.csv       experiment,backend,config,metric,bytes
    functional.json pass/fail outcomes of the security tests (E5, E6)
Every number in the paper must come from these files.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import platform
import sys
import time
from pathlib import Path

from tbg import merkle, shamir
from tbg.backend import aead_decrypt, aead_encrypt, get_backend, hkdf, random_bytes
from tbg.baselines import EscrowService, escrow_break_glass, escrow_protect
from tbg.scheme import (Deployment, Reject, Request, STH, TrusteeAgent, audit, break_glass,
                        equivocation_evidence, routine_access)

KB, MB = 1024, 1024 * 1024


class Sink:
    def __init__(self, out: Path, backend: str) -> None:
        self.backend = backend
        self.tf = open(out / "timings.csv", "w", newline="")
        self.sf = open(out / "sizes.csv", "w", newline="")
        self.tw = csv.writer(self.tf)
        self.sw = csv.writer(self.sf)
        self.tw.writerow(["experiment", "backend", "config", "metric", "iteration", "value_ms"])
        self.sw.writerow(["experiment", "backend", "config", "metric", "bytes"])

    def t(self, exp, config, metric, i, seconds):
        self.tw.writerow([exp, self.backend, config, metric, i, f"{seconds * 1000:.6f}"])

    def s(self, exp, config, metric, nbytes):
        self.sw.writerow([exp, self.backend, config, metric, nbytes])

    def flush(self):
        self.tf.flush()
        self.sf.flush()


def timed(fn):
    t0 = time.perf_counter()
    r = fn()
    return r, time.perf_counter() - t0


def bench(sink, exp, config, metric, fn, iters, warmup=3):
    for _ in range(warmup):
        fn()
    for i in range(iters):
        _, dt_ = timed(fn)
        sink.t(exp, config, metric, i, dt_)


# ------------------------------------------------------------------ E1
def e1(be, sink, q):
    it = 10 if q else 100
    ek, dk = be.kem_keygen()
    ct, _ = be.kem_encaps(ek)
    vk, sk = be.sig_keygen()
    msg = random_bytes(256)
    sig = be.sign(sk, msg)
    bench(sink, "E1", "-", "kem_keygen", be.kem_keygen, it)
    bench(sink, "E1", "-", "kem_encaps", lambda: be.kem_encaps(ek), it)
    bench(sink, "E1", "-", "kem_decaps", lambda: be.kem_decaps(dk, ct), it)
    bench(sink, "E1", "-", "sig_keygen", be.sig_keygen, it)
    bench(sink, "E1", "-", "sign_256B", lambda: be.sign(sk, msg), it)
    bench(sink, "E1", "-", "verify_256B", lambda: be.verify(vk, msg, sig), it)
    key, nonce, mb = random_bytes(32), random_bytes(12), random_bytes(MB)
    c = aead_encrypt(key, nonce, mb, b"ad")
    bench(sink, "E1", "-", "aes256gcm_enc_1MB", lambda: aead_encrypt(key, nonce, mb, b"ad"), it)
    bench(sink, "E1", "-", "aes256gcm_dec_1MB", lambda: aead_decrypt(key, nonce, c, b"ad"), it)
    bench(sink, "E1", "-", "hkdf_sha256", lambda: hkdf(key, b"info"), it)
    sh = shamir.split(key, 3, 5)
    bench(sink, "E1", "(3,5)", "shamir_split_32B", lambda: shamir.split(key, 3, 5), it)
    bench(sink, "E1", "(3,5)", "shamir_rec_32B", lambda: shamir.reconstruct(sh[:3]), it)
    for name, val in [("kem_ek", ek), ("kem_dk", dk), ("kem_ct", ct), ("sig_vk", vk), ("sig_sk", sk),
                      ("signature", sig)]:
        sink.s("E1", "-", name, len(val))


# ------------------------------------------------------------------ E2
def e2(be, sink, q):
    sizes = [1 * KB, 100 * KB, 5 * MB] if q else [1 * KB, 100 * KB, 5 * MB, 50 * MB, 200 * MB]
    d = Deployment(be, 3, 5)
    d.add_users(["u1", "u2", "u3"])
    for size in sizes:
        it = 3 if q else (5 if size >= 50 * MB else 20)
        data = random_bytes(size)
        cfg = f"{size // KB}KB"
        rec = d.protect(data, "r")
        sink.s("E2", cfg, "storage_overhead", rec.overhead_bytes(size))
        bench(sink, "E2", cfg, "protect", lambda: d.protect(data, "r"), it, warmup=1)
        dk = d.users["u1"][1]
        bench(sink, "E2", cfg, "routine_access", lambda: routine_access(be, rec, "u1", dk), it, warmup=1)
        del data, rec


# ------------------------------------------------------------------ E3
def e3(be, sink, q):
    it = 5 if q else 20
    for t, n in [(2, 3), (3, 5), (4, 7), (5, 10)]:
        cfg = f"({t},{n})"
        d = Deployment(be, t, n)
        rec = d.protect(b"x" * KB, "r")
        key = random_bytes(32)
        sh = shamir.split(key, t, n)
        bench(sink, "E3", cfg, "shamir_split", lambda: shamir.split(key, t, n), it)
        bench(sink, "E3", cfg, "shamir_rec", lambda: shamir.reconstruct(sh[:t]), it)
        bench(sink, "E3", cfg, "protect_emergency_only", lambda: d.protect(b"x" * KB, "r"), it)
        from tbg.scheme import enc, u64, unwrap

        def unwrap_t():
            for a in d.agents[:t]:
                unwrap(be, a._dk, rec.emergency[a.idx], enc(b"bg", b"r", u64(a.idx)))
        bench(sink, "E3", cfg, "unwrap_t_shares", unwrap_t, it)
        sink.s("E3", cfg, "emergency_envelopes", sum(e.size() for e in rec.emergency.values()))


# ------------------------------------------------------------------ E4
def e4(be, sink, q, prefill):
    it = 5 if q else 30
    sizes = [1 * KB, 100 * KB, 5 * MB]
    for t, n in [(3, 5), (5, 10)]:
        d = Deployment(be, t, n)
        for i in range(prefill):
            d.log.append_unsigned(b"\x01prefill" + i.to_bytes(4, "big"))
        for size in sizes:
            cfg = f"({t},{n})/{size // KB}KB"
            data = random_bytes(size)
            rec = d.protect(data, "rec")
            for i in range(-2, it):  # two warm-up runs
                pt, tm = break_glass(be, rec, "dr", "R01", d.log, d.agents)
                assert pt == data
                if i >= 0:
                    for k, v in tm.items():
                        sink.t("E4", cfg, k, i, v)
            sink.flush()


# ------------------------------------------------------------------ E5
def e5(be, sink, q, func):
    sizes = [100, 1000] if q else [100, 1000, 10_000, 100_000]
    it = 10 if q else 50
    for n in sizes:
        lm = merkle.MerkleLog()
        t0 = time.perf_counter()
        for i in range(n):
            lm.append(b"\x01leaf" + i.to_bytes(4, "big"))
        lm.root()
        sink.t("E5", f"N={n}", "build_log", 0, time.perf_counter() - t0)
        root = lm.root()
        m = n // 3
        pr = lm.inclusion_proof(m, n)
        cp = lm.consistency_proof(n // 2, n)
        old = lm.root(n // 2)
        bench(sink, "E5", f"N={n}", "inclusion_proof_gen", lambda: lm.inclusion_proof(m, n), it)
        bench(sink, "E5", f"N={n}", "inclusion_verify",
              lambda: merkle.verify_inclusion(m, n, lm.hashes[m], pr, root), it)
        bench(sink, "E5", f"N={n}", "consistency_proof_gen", lambda: lm.consistency_proof(n // 2, n), it)
        bench(sink, "E5", f"N={n}", "consistency_verify",
              lambda: merkle.verify_consistency(n // 2, n, old, root, cp), it)
        sink.s("E5", f"N={n}", "inclusion_proof", 32 * len(pr))
        sink.s("E5", f"N={n}", "consistency_proof", 32 * len(cp))

    # tamper tests on a signed log observed by an auditor
    d = Deployment(be, 3, 5)
    rec = d.protect(b"t" * 100, "rec")
    for _ in range(4):
        break_glass(be, rec, "dr", "R01", d.log, d.agents)
    head = d.log.sth()
    r = {"clean_audit_passes": all(audit(be, d.log, [head]).values())}
    saved = list(d.log.log.leaves)
    d.log.log.leaves[2] = b"modified"
    r["modified_leaf_detected"] = not audit(be, d.log, [head])["heads_match_published_leaves"]
    d.log.log.leaves = saved[:3] + saved[4:]
    r["deleted_leaf_detected"] = not audit(be, d.log, [head])["heads_match_published_leaves"]
    d.log.log.leaves = saved[:2] + [saved[3], saved[2]] + saved[4:]
    r["reordered_leaves_detected"] = not audit(be, d.log, [head])["heads_match_published_leaves"]
    d.log.log.leaves = saved
    forged = d.log.sign_head(head.size, random_bytes(32))
    r["equivocation_same_size_detected"] = equivocation_evidence(be, d.log.vk, head, forged)
    func["E5"] = r


# ------------------------------------------------------------------ E6
def e6(be, sink, func):
    r = {}
    d = Deployment(be, 3, 5)
    rec = d.protect(b"s" * 100, "rec")
    ek_d, _ = be.kem_keygen()
    req = Request("rec", "dr", "R01", int(time.time() * 1000), random_bytes(16), ek_d)
    released = 0
    for a in d.agents:
        try:
            a.release(req, 0, d.log.sth(), [], [], rec)
            released += 1
        except Reject:
            pass
    r["unlogged_request_shares_released"] = released  # expected 0
    try:
        break_glass(be, rec, "dr", "R01", d.log, d.agents[:2])
        r["t_minus_1_agents_recover"] = True
    except Reject:
        r["t_minus_1_agents_recover"] = False  # expected False
    m, head = d.log.append(req.leaf())
    incl = d.log.inclusion_proof(m, head.size)
    d.agents[0].release(req, m, head, incl, d.log.consistency_proof(d.agents[0].last_size, head.size), rec)
    try:
        d.agents[0].release(req, m, head, incl, [], rec)
        r["replay_rejected"] = False
    except Reject:
        r["replay_rejected"] = True
    old = Request("rec", "dr", "R01", int(time.time() * 1000) - 3_600_000, random_bytes(16), ek_d)
    m2, h2 = d.log.append(old.leaf())
    try:
        d.agents[1].release(old, m2, h2, d.log.inclusion_proof(m2, h2.size),
                            d.log.consistency_proof(d.agents[1].last_size, h2.size), rec)
        r["stale_rejected"] = False
    except Reject:
        r["stale_rejected"] = True
    # forked history shown to an agent that already holds a head
    a = d.agents[0]
    fork = merkle.MerkleLog()
    for _ in range(a.last_size):
        fork.append(random_bytes(20))
    req3 = Request("rec", "dr", "R01", int(time.time() * 1000), random_bytes(16), ek_d)
    m3 = fork.append(req3.leaf())
    fake = d.log.sign_head(len(fork), fork.root())
    try:
        a.release(req3, m3, fake, fork.inclusion_proof(m3, len(fork)),
                  fork.consistency_proof(a.last_size, len(fork)), rec)
        r["forked_log_rejected"] = False
    except Reject:
        r["forked_log_rejected"] = True
    func["E6"] = r


# ------------------------------------------------------------------ E7
def e7(be, sink, q):
    counts = [10, 100] if q else [100, 1000, 10_000]
    d = Deployment(be, 3, 5)
    d.add_users(["u1", "u2", "u3"])
    data = random_bytes(KB)
    for c in counts:
        t0 = time.perf_counter()
        recs = [d.protect(data, f"r{i}") for i in range(c)]
        sink.t("E7", f"records={c}", "protect_batch_1KB", 0, time.perf_counter() - t0)
        new = TrusteeAgent(be, 1, d.log.vk)
        t0 = time.perf_counter()
        for rec in recs:
            rec.emergency[1] = d.agents[0].rewrap_for(rec, new.ek)
        sink.t("E7", f"records={c}", "rotate_one_agent", 0, time.perf_counter() - t0)
        sink.flush()


# ------------------------------------------------------------------ E8
def e8(be, sink, q):
    it = 5 if q else 30
    for size in [1 * KB, 5 * MB]:
        cfg = f"{size // KB}KB"
        data = random_bytes(size)
        esc = EscrowService(be)
        users = {u: be.kem_keygen()[0] for u in ["u1", "u2", "u3"]}
        bench(sink, "E8", cfg, "escrow_protect", lambda: escrow_protect(be, data, "r", users, esc), it, 1)
        nonce, ct, routine, env = escrow_protect(be, data, "r", users, esc)
        for i in range(-2, it):
            pt, dt_ = escrow_break_glass(be, "r", nonce, ct, env, esc, "dr")
            assert pt == data
            if i >= 0:
                sink.t("E8", cfg, "escrow_break_glass", i, dt_)
        size_e = sum(e.size() for e in routine.values()) + env.size() + len(nonce) + (len(ct) - size)
        sink.s("E8", cfg, "escrow_storage_overhead", size_e)


# ------------------------------------------------------------------ main
def environment(be, args):
    env = {"timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
           "platform": platform.platform(), "machine": platform.machine(),
           "processor": platform.processor(), "cpu_count": os.cpu_count(),
           "python": sys.version, "args": vars(args), **be.describe()}
    try:
        from importlib.metadata import version
        env["cryptography_version"] = version("cryptography")
    except Exception:
        pass
    try:
        import psutil  # optional
        env["ram_gb"] = round(psutil.virtual_memory().total / 2**30, 1)
    except Exception:
        env["ram_gb"] = "install psutil to record"
    return env


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--backend", default="pq", choices=["pq", "pq-oqs", "pq-pure", "classical"])
    p.add_argument("--quick", action="store_true", help="few iterations, small sizes (smoke test)")
    p.add_argument("--only", nargs="*", default=None, help="subset, e.g. E1 E4")
    p.add_argument("--prefill", type=int, default=1000, help="log entries before E4")
    p.add_argument("--out", default="results")
    args = p.parse_args()
    be = get_backend(args.backend)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = Path(args.out) / f"{stamp}_{be.name}{'_quick' if args.quick else ''}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "env.json").write_text(json.dumps(environment(be, args), indent=2))
    sink, func = Sink(out, be.name), {}
    todo = args.only or ["E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8"]
    for e in todo:
        t0 = time.perf_counter()
        print(f"[{be.name}] {e} ...", flush=True)
        {"E1": lambda: e1(be, sink, args.quick), "E2": lambda: e2(be, sink, args.quick),
         "E3": lambda: e3(be, sink, args.quick), "E4": lambda: e4(be, sink, args.quick, args.prefill),
         "E5": lambda: e5(be, sink, args.quick, func), "E6": lambda: e6(be, sink, func),
         "E7": lambda: e7(be, sink, args.quick), "E8": lambda: e8(be, sink, args.quick)}[e]()
        sink.flush()
        print(f"[{be.name}] {e} done in {time.perf_counter() - t0:.1f} s", flush=True)
    (out / "functional.json").write_text(json.dumps(func, indent=2))
    print(f"results written to {out}")


if __name__ == "__main__":
    main()
