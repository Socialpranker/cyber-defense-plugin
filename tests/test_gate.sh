#!/bin/bash
# The report gate must stay closed until a human labels the finding:
# a row without the second labeler's mark is CLOSED (exit 1), the same row with TP is OPEN (exit 0).
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
ledger="$here/skills/cyber-defense/scripts/ledger.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export LEDGER="$tmp/findings.tsv"

python3 "$ledger" init >/dev/null
printf 'syn-1\tsynlib\thunt-syn\tsynthetic row without a second label\t4\tCONFIRMED\tSURVIVES\tTP\t-\tci\n' >> "$LEDGER"
printf 'syn-2\tsynlib\thunt-syn\tsynthetic row with a second label\t4\tCONFIRMED\tSURVIVES\tTP\tTP\tci\n' >> "$LEDGER"
printf 'syn-3\tsynlib\thunt-syn\tsynthetic row a labeler rejected\t4\tCONFIRMED\tSURVIVES\tTP\tFP\tci\n' >> "$LEDGER"

expect() {  # expect <exit code> <id>
  local want="$1" id="$2" got=0
  python3 "$ledger" gate "$id" || got=$?
  if [ "$got" -ne "$want" ]; then echo "FAIL: gate $id exited $got, expected $want" >&2; exit 1; fi
  echo "ok   gate $id exited $got"
}
expect 1 syn-1
expect 0 syn-2
expect 1 syn-3
