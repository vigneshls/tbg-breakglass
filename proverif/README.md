# ProVerif model of TBG (manuscript Section 5.4)

Files
- tbg_threshold.pv               the protocol model: (t,n) = (2,3), agent 3 corrupted, untrusted log maintainer
- mutant_M1_two_corrupt.pv       agents 2 AND 3 corrupted (threshold exceeded)  -> Q1 must be false
- mutant_M2_no_rid_check.pv      agent does not check the envelope's record id  -> Q1 must be false
- mutant_M3_signing_key_leak.pv  an agent leaks its signing key                 -> Q2 must be false

The mutants show that each verified property depends on the protocol step meant
to enforce it (the model is not trivially true).

Run (official ProVerif, https://bblanche.gitlabpages.inria.fr/proverif/ ; Windows binaries are offered there)
    proverif tbg_threshold.pv
    proverif mutant_M1_two_corrupt.pv
    proverif mutant_M2_no_rid_check.pv
    proverif mutant_M3_signing_key_leak.pv
Record: ProVerif version (proverif -help shows it), every line starting with RESULT, and run time.

Expected for tbg_threshold.pv
    RESULT attacker(kRecord[]) ==> event(Released(i1,...)) || event(Released(i2,...)) is true.
    RESULT event(ApprovalVerified(i1,...)) ==> event(Released(i1,...)) is true.
    RESULT event(ApprovalVerified(i2,...)) ==> event(Released(i2,...)) is true.
    RESULT not event(Recovered(...)) is false.      <- means an honest run CAN complete (sanity)

Not modelled (state in the paper): Merkle consistency proofs and gossip (log abstracted
as a hash chain), freshness windows and replay sets, arbitrary (t,n), implementation flaws.
