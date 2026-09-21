#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold `RSKeyTransport`'s `Cap` to the width the Rust harnesses actually pose.

`crates/rsk-usb/src/transport_assurance.rs` carries the model→code bridge for
`SEC-TRANS-001..003`: what TLA+ counts in CHUNKS the reassembler counts in BYTES,
so `Cap` chunks must BE `INIT_DATA + Cap * CONT_DATA` bytes. Two `const _: () =
assert!` hold the Rust half of that, and they are enough for the Rust half.

They are not enough for the claim, because **Rust cannot read `formal/`**. Three
numbers have to agree and only two of them are in the language:

* `formal/Transport.cfg`'s `Cap` — what TLC actually walks;
* `formal/scopes.txt`'s `RSKeyTransport Cap` — the recorded FLOOR, the smallest
  width at which the module's mutants still fire;
* `PROBE_CHUNKS` — the width the Kani harnesses pose, `cfg(kani)` and shipped.

Measured before this existed: `Cap = 3 -> 4` in the generator and all seven
`Trans*.cfg` left `config_gen_gate.py` and `scope_gate.py` both exit 0 (the floor
is a `>=`, and 4 clears it), with no Rust file affected — `PROBE_CHUNKS` has zero
mentions outside `crates/rsk-usb/` and `CHANGELOG.md`. The prose beside
`PROBE_MAX` would then have said "runs `Cap = 3`" over a configuration running 4,
which is the same unchecked shape as the sentence it replaced ("`Cap` is 2 in
`Transport.cfg`", when the file said 3 and 2 was the floor). A bridge whose two
ends are checked separately and never against each other is not a bridge.

## The rules

1. `PROBE_CHUNKS` under `cfg(kani)` **equals** the recorded floor. The harnesses
   claim to pose the model's own bound; this is that claim.
2. `formal/Transport.cfg`'s `Cap` is **at or above** the floor — a configuration
   below the width its mutants need is a green run that watched nothing.
3. The prose beside `PROBE_MAX` **names the configuration's real `Cap`**. This is
   the rule the two constants cannot carry: it is the only one that fails when
   the configuration moves and the Rust does not.
4. `PROBE_CHUNKS` under `cfg(not(kani))` **equals** the multiplier in
   `ctaphid.rs`'s shipped `CTAP_MAX_MESSAGE`. The Rust asserts agree with this
   through `PROBE_MAX`; stated here too so a reader of one file sees both ends,
   and so rule 1's sibling cannot be the only cross-file tie.

Every number is READ, none is transcribed: a rule whose expected value is written
in this file is a second place for the truth to live.

## What it is not

It does not check that `Cap` is *large enough to be interesting* — that is what
the mutation configurations measure, and `formal/scopes.txt` is where the answer
is recorded. It reads the floor; it does not re-derive it.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

BRIDGE = pathlib.Path("crates/rsk-usb/src/transport_assurance.rs")
REASSEMBLER = pathlib.Path("crates/rsk-usb/src/ctaphid.rs")
CONFIG = pathlib.Path("formal/Transport.cfg")
SCOPES = pathlib.Path("formal/scopes.txt")

#: `PROBE_CHUNKS` under each arm. The `cfg` line is part of the pattern: without
#: it a single-arm definition would match twice and the two arms would collapse.
PROBE = re.compile(
    r"#\[cfg\((?P<cfg>not\(kani\)|kani)\)\]\s*\n"
    r"pub const PROBE_CHUNKS: usize = (?P<n>\d+);"
)
#: `Cap = 3` in the generated configuration.
CFG_CAP = re.compile(r"^\s*Cap\s*=\s*(\d+)\s*$", re.M)
#: The floor row: module, constant, value, witness.
SCOPE_CAP = re.compile(r"^RSKeyTransport\s+Cap\s+(\d+)\s+\S+", re.M)
#: The shipped multiplier, `INIT_DATA + 128 * CONT_DATA`. Anchored on its `cfg`
#: for the reason PROBE is: the shrink writes the same line with 2, and an
#: unanchored pattern matched both and read the kani width as the shipped one.
SHIPPED = re.compile(
    r"#\[cfg\(not\(kani\)\)\]\s*\n"
    r"pub const CTAP_MAX_MESSAGE: usize = INIT_DATA \+ (\d+) \* CONT_DATA"
)
#: The prose rule 3 reads. A page that stops saying it fails rather than passes.
PROSE_CAP = re.compile(r"runs `Cap = (\d+)`")


def one(pattern, text, where, what, problems, group=1):
    """The single match, or a problem — a regex that stopped matching finds none."""
    found = pattern.findall(text)
    if len(found) != 1:
        problems.append(f"{where}: {what} matched {len(found)} time(s), expected 1")
        return None
    return int(found[0] if isinstance(found[0], str) else found[0][group])


def audit(root):
    """(problems, one-line summary) for the three numbers and their relations."""
    root = pathlib.Path(root)
    problems: list[str] = []
    texts = {}
    for rel in (BRIDGE, REASSEMBLER, CONFIG, SCOPES):
        path = root / rel
        if not path.is_file():
            problems.append(f"{rel} is gone; the transport bridge is unchecked")
            return problems, ""
        texts[rel] = path.read_text()

    arms = {m.group("cfg"): int(m.group("n")) for m in PROBE.finditer(texts[BRIDGE])}
    if set(arms) != {"kani", "not(kani)"}:
        problems.append(
            f"{BRIDGE}: PROBE_CHUNKS needs a kani arm and a not(kani) arm;"
            f" found {sorted(arms) or 'none'}"
        )
        return problems, ""

    floor = one(SCOPE_CAP, texts[SCOPES], SCOPES, "the RSKeyTransport Cap floor", problems)
    cap = one(CFG_CAP, texts[CONFIG], CONFIG, "Cap", problems)
    shipped = one(SHIPPED, texts[REASSEMBLER], REASSEMBLER, "the shipped multiplier", problems)
    prose = one(PROSE_CAP, texts[BRIDGE], BRIDGE, "the `runs `Cap = N`` sentence", problems)
    if None in (floor, cap, shipped, prose):
        return problems, ""

    if arms["kani"] != floor:
        problems.append(
            f"{BRIDGE}: PROBE_CHUNKS is {arms['kani']} under cfg(kani) but"
            f" {SCOPES} records {floor} as RSKeyTransport's Cap floor — the"
            " harnesses do not pose the bound they say they pose"
        )
    if cap < floor:
        problems.append(
            f"{CONFIG}: Cap = {cap} is under {SCOPES}'s floor of {floor}; the"
            " mutants were measured at the floor and cannot fire below it"
        )
    if prose != cap:
        problems.append(
            f"{BRIDGE}: says the configuration runs `Cap = {prose}`, and"
            f" {CONFIG} runs {cap} — the sentence is the only place these two"
            " ends meet, so it is the one that has to be true"
        )
    if arms["not(kani)"] != shipped:
        problems.append(
            f"{BRIDGE}: PROBE_CHUNKS is {arms['not(kani)']} shipped but"
            f" {REASSEMBLER} builds CTAP_MAX_MESSAGE from {shipped} continuations"
        )
    return problems, (
        f"transport-bridge: ok — Cap {cap} in {CONFIG.name} at or above the"
        f" floor {floor}, posed by PROBE_CHUNKS {arms['kani']} under kani and"
        f" {arms['not(kani)']} shipped"
    )


def main():
    problems, summary = audit(ROOT)
    if problems:
        print("transport-bridge-gate:")
        for line in problems:
            print(f"  {line}")
        print(
            "\nRust cannot read formal/. These four numbers are the whole of the\n"
            "chunk-to-byte bridge SEC-TRANS-001..003 are proved through, and two\n"
            "of them live in files no compiler opens."
        )
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
