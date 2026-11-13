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
printf 'syn-1\tsynlib\thunt-syn\tsynthetic row without a second label\t4\tPASS\tCONFIRMED\tSURVIVES\tTP\t-\tci\n' >> "$LEDGER"
printf 'syn-2\tsynlib\thunt-syn\tsynthetic row with a second label\t4\tPASS\tCONFIRMED\tSURVIVES\tTP\tTP\tci\n' >> "$LEDGER"
printf 'syn-3\tsynlib\thunt-syn\tsynthetic row a labeler rejected\t4\tPASS\tCONFIRMED\tSURVIVES\tTP\tFP\tci\n' >> "$LEDGER"
printf 'syn-4\tsynlib\thunt-syn\tsynthetic row the pre-PoC filter dismissed\t4\tDISMISS\tCONFIRMED\tSURVIVES\tTP\tTP\tci\n' >> "$LEDGER"

expect() {  # expect <exit code> <id>
  local want="$1" id="$2" got=0 out
  out="$(python3 "$ledger" gate "$id" 2>&1)" || got=$?
  if [ "$got" -ne "$want" ]; then echo "FAIL: gate $id exited $got, expected $want: $out" >&2; exit 1; fi
  # An invalid ledger also exits 1, so a closed gate must say that it is the gate that closed.
  case "$out" in
    "gate OPEN for $id"*|"gate CLOSED for $id"*) ;;
    *) echo "FAIL: gate $id did not reach a verdict: $out" >&2; exit 1 ;;
  esac
  echo "ok   gate $id exited $got"
}
expect 1 syn-1
expect 0 syn-2
expect 1 syn-3
expect 1 syn-4

# A ledger written before the prefilter column existed still loads, and migrate adds the column.
printf 'id\tproject\trun\ttitle\tstage\tpoc\trefuter\tlabel_a\tlabel_b\tnote\n' > "$LEDGER"
printf 'syn-1\tsynlib\thunt-syn\told-header row without a second label\t4\tCONFIRMED\tSURVIVES\tTP\t-\tci\n' >> "$LEDGER"
printf 'syn-2\tsynlib\thunt-syn\told-header row with a second label\t4\tCONFIRMED\tSURVIVES\tTP\tTP\tci\n' >> "$LEDGER"
expect 1 syn-1
expect 0 syn-2
python3 "$ledger" migrate >/dev/null
if [ "$(head -1 "$LEDGER" | cut -f6)" != "prefilter" ]; then echo "FAIL: migrate did not add the prefilter column" >&2; exit 1; fi
echo "ok   migrate added the prefilter column"
expect 1 syn-1
expect 0 syn-2
python3 "$ledger" migrate >/dev/null
echo "ok   migrate twice is a no-op"
