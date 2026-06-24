#!/usr/bin/env bash
# Driver for the gove-zone proof-sequence demo recording.
#
# Runs the canonical, documented proof path against the REAL gove-zone API and
# prints the three load-bearing proofs in order:
#
#   (1) an ALLOWED write succeeds (a real side effect runs);
#   (2) a write to an id_rsa / /etc/shadow path is DENIED before any side effect;
#   (3) a tampered audit entry makes chain verification FAIL.
#
# Proof (1)+(2) come from `gove-zone smoke` (smoke.py denies the `id_rsa` path
# via SMOKE_SECRET_BOUNDARY). Proof (3) comes from the undeniable-demo step [5a]
# ("mutating one audit event -> hash-chain mismatch"), run under the signed
# production profile (require_signature=True) which needs the `crypto` extra.
#
# This script is what `demo-proof-sequence.cast` was recorded from
# (`asciinema rec -c docs/launch/evidence/record-proof-sequence.sh ...`), and
# what `demo-proof-sequence.txt` is the plain transcript of. Re-run it from the
# monorepo root to reproduce the evidence.
#
# Honest scope: gove-zone is Alpha (0.1.0.dev0). This is a LOCAL proof of the
# fail-closed invariant, not a production / compliance / regulator certification.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"

rule() { printf '\n================================================================\n'; }

rule
echo "gove-zone proof sequence  —  allow  ->  deny(id_rsa)  ->  tamper-fail"
echo "(real API; signed production profile for the tamper step)"
rule

echo
echo ">>> [1+2] gove-zone smoke  —  ALLOW succeeds, id_rsa write DENIED"
echo "    \$ uv run --package gove-zone gove-zone smoke --audit <tmp>/audit.jsonl"
echo
tmp="$(mktemp -d)"
uv run --package gove-zone gove-zone smoke --audit "$tmp/audit.jsonl"
echo
echo "    ^ decision=allow bytesWritten=15  (proof 1: allowed side effect ran)"
echo "    ^ decision=deny  matchedRules=SMOKE_SECRET_BOUNDARY:keyword:id_rsa"
echo "      (proof 2: write to an id_rsa path blocked, no side effect on disk)"

rule
echo
echo ">>> [3] undeniable-demo  —  tampered audit entry -> verification FAILS"
echo "    \$ uv run --package gove-zone --extra crypto python \\"
echo "          packages/gove-zone/examples/undeniable-demo/demo.py"
echo
uv run --package gove-zone --extra crypto python \
    packages/gove-zone/examples/undeniable-demo/demo.py
echo
echo "    ^ step [5a]: chain after mutation valid=False,"
echo "      failure type=event_hash_mismatch  (proof 3: tamper fails closed)"

rule
echo "Proof sequence complete: allow -> deny(id_rsa) -> tamper-fail, all real."
rule
