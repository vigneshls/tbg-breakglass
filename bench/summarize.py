"""Summarize a results folder: python -m bench.summarize results/<run-folder>

Writes summary.csv (n, mean, sd, median, p95, min, max, 95% bootstrap CI of the
mean; 2,000 resamples, fixed seed) and prints sizes and functional outcomes.
"""
import csv
import json
import random
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path


def boot_ci(xs, reps=2000, seed=12345):
    if len(xs) < 2:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    means = sorted(st.fmean(rng.choices(xs, k=len(xs))) for _ in range(reps))
    return means[int(0.025 * reps)], means[int(0.975 * reps) - 1]


def p95(xs):
    s = sorted(xs)
    return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]


def main(folder):
    folder = Path(folder)
    groups = defaultdict(list)
    with open(folder / "timings.csv") as f:
        for r in csv.DictReader(f):
            groups[(r["experiment"], r["backend"], r["config"], r["metric"])].append(float(r["value_ms"]))
    rows = []
    for (e, b, c, m), xs in sorted(groups.items()):
        lo, hi = boot_ci(xs)
        rows.append([e, b, c, m, len(xs), st.fmean(xs), st.stdev(xs) if len(xs) > 1 else 0.0,
                     st.median(xs), p95(xs), min(xs), max(xs), lo, hi])
    with open(folder / "summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["experiment", "backend", "config", "metric", "n", "mean_ms", "sd_ms", "median_ms",
                    "p95_ms", "min_ms", "max_ms", "ci95_low_ms", "ci95_high_ms"])
        for r in rows:
            w.writerow(r[:5] + [f"{v:.4f}" for v in r[5:]])
    for r in rows:
        print(f"{r[0]:3} {r[2]:18} {r[3]:32} n={r[4]:3} mean={r[5]:10.3f} ms  median={r[7]:10.3f}  p95={r[8]:10.3f}")
    print("\nsizes:")
    with open(folder / "sizes.csv") as f:
        for r in csv.DictReader(f):
            print(f"  {r['experiment']:3} {r['config']:12} {r['metric']:28} {r['bytes']} B")
    fj = folder / "functional.json"
    if fj.exists():
        print("\nfunctional:", json.dumps(json.loads(fj.read_text()), indent=2))


if __name__ == "__main__":
    main(sys.argv[1])
