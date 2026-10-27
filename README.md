# TBG: Post-Quantum Transparent Break-Glass for Electronic Medical Records

Reference implementation, benchmark harness, raw measurements and ProVerif model for the manuscript
"Post-Quantum Transparent Break-Glass: Threshold, Log-Gated Emergency Access to Electronic Medical Records"
(L. S. Vignesh et al., submitted).

TBG splits each record key among n trustee agents (any t can restore it). An agent releases its
share only after verifying that the emergency request is included in an RFC 9162 Merkle log,
that the log is consistent with its last view, that the request is fresh, and that its officer
approved. Primitives: ML-KEM-768, ML-DSA-65 (NIST FIPS 203/204), AES-256-GCM, HKDF-SHA-256,
SHA-256, Shamir sharing over GF(2^8).

This is research code for measurement and verification. It is not a production system and has
not been audited.

## Repository layout
```
tbg/          scheme.py (Protect, BreakGlass, audit, rotation), merkle.py, shamir.py,
              backend.py (liboqs / pure-Python / classical), baselines.py (single escrow)
tests/        11 functional and negative tests
bench/        run_all.py (experiments E1-E8), summarize.py (statistics, bootstrap CIs)
proverif/     symbolic model (2,3) + three mutants; proverif_results_v2.05.txt = output used in the paper
results/
  paper_liboqs_2026-10-26/          runs reported in the paper (Tables I-VIII)
  supplementary_purepython_2026-10-24/  pure-Python backend runs (supplementary only)
```
Each run folder holds env.json (machine, OS, library versions, arguments), timings.csv and
sizes.csv (raw measurements), functional.json (security test outcomes) and summary.csv
(computed by bench/summarize.py from timings.csv).

## Reproducing
Python 3.11+.
```
pip install -r requirements.txt
python -m pytest -q                         # 11 tests must pass
python -m bench.run_all --backend pq-oqs    # needs liboqs, see below
python -m bench.run_all --backend classical
python -m bench.summarize results/<run-folder>
```
Without liboqs, `--backend pq` falls back to pure-Python ML-KEM/ML-DSA (correct but slow;
not comparable with the C-based classical backend).

### liboqs on Windows (as used for the paper)
Visual Studio Build Tools (Desktop development with C++), Git, then in the
x64 developer prompt:
```
git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs\build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=C:\oqs-install
cmake --build liboqs\build
cmake --install liboqs\build
setx OQS_INSTALL_PATH C:\oqs-install
pip install liboqs-python==0.16.0.1
```
### liboqs on Linux
```
git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=$HOME/_oqs
ninja -C liboqs/build install && export OQS_INSTALL_PATH=$HOME/_oqs
pip install liboqs-python==0.16.0.1
```

### ProVerif
```
proverif proverif/tbg_threshold.pv
proverif proverif/mutant_M1_two_corrupt.pv
proverif proverif/mutant_M2_no_rid_check.pv
proverif proverif/mutant_M3_signing_key_leak.pv
```
Expected outcomes are listed in proverif/README.md.

## What the measurements include
Single process, no network: latencies are cryptographic and protocol-processing costs, including
Python-wrapper overhead. Network delay and human approval time are not measured. The escrow
baseline is a software emulation, not an HSM.

## Citation
See CITATION.cff. The archived release DOI will be added after the first Zenodo release.

## Licence
MIT (see LICENSE). Third-party libraries keep their own licences.
