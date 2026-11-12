"""Example property harness (Hypothesis): werkzeug.security.safe_join must reject every Windows
device name, whatever suffix hides it. Calibration control: fails on werkzeug before b2a2c0973008
("CON:"), passes after it.

Shape to copy: (1) an oracle written from the spec, not from the code under test; (2) a strategy
that builds inputs from known-dangerous cores plus hiding suffixes, because plain st.text() will
not reach "CON:" in any useful time; (3) run in sandbox_run.sh, print the minimal failing input.
"""
import os
import sys
import types

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import werkzeug.security as sec

# Exercise the Windows branch on Linux by swapping os only inside the module under test.
sec.os = types.SimpleNamespace(name="nt", path=os.path, sep=os.sep, altsep=os.altsep)

DEVICES = ["CON", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "CONIN$", "CONOUT$"]


def windows_opens_device(segment):
    # Win32 path rules: a stream suffix (":...") and an extension (".…") are ignored when matching
    # reserved device names, and so are trailing spaces.
    stem = segment.split(":", 1)[0].split(".", 1)[0].rstrip(" ")
    return stem.upper() in DEVICES


core = st.sampled_from(DEVICES).flatmap(
    lambda d: st.lists(st.booleans(), min_size=len(d), max_size=len(d)).map(
        lambda up: "".join(c.lower() if u else c for c, u in zip(d, up))))
suffix = st.text(alphabet=" .:$-_aDATtx0", max_size=6)
segment = st.builds(lambda c, s: c + s, core, suffix)
path = st.builds(lambda pre, seg: pre + seg, st.sampled_from(["", "a/", "a/b/"]), segment)


@settings(max_examples=3000, deadline=None, suppress_health_check=list(HealthCheck))
@given(path)
def test_device_names_rejected(p):
    if any(windows_opens_device(s) for s in p.split("/")):
        assert sec.safe_join("/base", p) is None, f"safe_join accepted device path {p!r}"


if __name__ == "__main__":
    try:
        test_device_names_rejected()
    except AssertionError as e:
        print(f"PROPERTY FAILED: {e}")
        sys.exit(1)
    print("property holds")
