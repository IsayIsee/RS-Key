#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold every hand-written copy of the counter-FID set to the applet crates.

`rsk_store::is_counter_fid` decides which partition a record is written to and
read back from, and it is a `matches!` over four bare literals whose named homes
are in other crates — `EF_COUNTER` and `EF_CRED_CTR` in `rsk-fido`,
`EF_SIG_COUNT` in `rsk-openpgp`, `COUNTER_FID` in `rsk-vendor`. Nothing links a
literal to its constant, so the table and the constants drift with no compile
error, and the resulting state is the one `crates/rsk-store/src/lib.rs` records
above `remove`: a copy in the wrong partition is invisible to `read` yet yielded
by every `for_each_key`, so `authenticatorReset`'s sweep loops on it until its
progress bound gives up.

The set has moved twice already, both times in a copy nothing derived.
`EF_CRED_CTR` joined the table at 0x0821, after 0x081D had been writing that FID
to the main partition; and the `power_cut` fuzz target's mirror listed three of
the four while its selector was `& 7` over nine entries, so the ninth — the
counter FID — could never be written by any input while the sweep asserted it
absent on every one.

So the VALUES are derived. The doc comment over `is_counter_fid` names the
constants; each name is resolved to a `const NAME: u16 = 0x…;` in a crate that is
NOT `rsk-store`, which is what makes this a reading of the applet crates rather
than of the table's own file; and every copy is then held to the values that come
back.

What each copy is held to:

* the doc comment itself: it must spell the value of every constant it names, so
  the prose that sends the next reader to those homes cannot go on quoting an old
  number. Only that direction — a doc comment carries prose, and the drift story
  above `is_counter_fid` quotes FIDs of its own;
* the `matches!` arms, read out of `is_counter_fid`'s OWN BODY: exactly the
  derived values, and each arm a bare literal. An arm this cannot read (a range,
  an identifier) is reported rather than skipped — skipping is how a copy stops
  being checked without anyone deciding it;
* `crates/rsk-store/src/tests.rs`: the loop that asserts `is_counter_fid` is
  exactly the derived set, and the loop that asserts `!is_counter_fid` shares no
  member with it. The two loops are found by what they assert and not by the
  test's name, which carries a cardinal of its own;
* `fuzz/fuzz_targets/power_cut.rs`: `FIDS` is a superset (it torments five
  main-partition FIDs as well), and every index into it ENDS in `% FIDS.len()`.
  That last rule is the other half of the copy's second drift, and it is a rule
  about the whole expression rather than a substring of it: `(… % FIDS.len()) & 7`
  and `… % FIDS.len() / 2` both carry the modulo and both put entries back out of
  reach, so a list carrying a FID no input can select is a list the sweep asserts
  about nothing.

Deliberately not here, and both limits are real. Whether a FID *belongs* in the
counter partition is a judgement about how hot a record is, it is `rsk-store`'s to
make, and removing a member from the doc comment and from every copy in one edit
is green — as it should be. And the ROSTER is that doc comment: a new counter
constant declared at its home and named nowhere over the table derives nothing, so
what this row buys is that the four copies and the constants they name cannot say
different things — not that the table is complete.
"""

import pathlib
import re
import sys

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The routing table, its host tests, and the fuzz target that mirrors the set.
TABLE = "crates/rsk-store/src/lib.rs"
TESTS = "crates/rsk-store/src/tests.rs"
FUZZ = "fuzz/fuzz_targets/power_cut.rs"
#: The crate the table lives in. A name that resolves only here is refused: the
#: whole point is that the homes are elsewhere, and a constant moved into
#: `rsk-store` would make the table its own source of truth again.
TABLE_CRATE = "crates/rsk-store/"
FUZZ_ARRAY = "FIDS"

#: The doc comment over `pub fn is_counter_fid`, which names the constants. Read
#: from the RAW text — `gate_lines.rust_code` blanks it, and every other read
#: below wants exactly that, so a literal in a comment is not a member. The
#: attributes are skipped rather than ended on: an `#[inline]` between the two is
#: an ordinary edit, and reading it as "there is no doc comment" is a false red.
DOC = re.compile(r"((?:^///.*\n)+)(?:^#\[[^\]]*\]\s*\n)*pub fn is_counter_fid\b", re.M)

#: The function's own body. The `matches!` is read from INSIDE it, not from the
#: first one in the file: a sibling predicate declared above `is_counter_fid`
#: would otherwise become the thing this checks, under a message naming the one
#: it does not.
BODY = re.compile(r"pub fn is_counter_fid\s*\([^)]*\)\s*->\s*bool\s*\{(.*?)\n\}", re.S)

#: A constant named in the doc: a backticked SCREAMING_SNAKE identifier.
NAMED = re.compile(r"`([A-Z][A-Z0-9_]{2,})`")

#: A FID literal, underscores included — `0x00_93` is this tree's own spelling in
#: `crates/rsk-rescue`. Width is judged in [`literals`], not here, because a
#: pattern that stops at four digits does not reject a wider literal, it silently
#: reads its first four.
HEX = re.compile(r"\b0x[0-9A-Fa-f_]+\b")

#: The table itself, matched inside [`BODY`].
MATCHES = re.compile(r"matches!\(\s*fid\s*,([^)]*)\)")

#: `for fid in [ … ] { assert!(<!?>is_counter_fid(fid) … ` — the two host loops,
#: told apart by what they assert rather than by the name of the test they sit
#: in. That name spells a cardinal ("the_four_hot_counters"), and keying on it
#: would make this guard's reading move with a count it does not check.
LOOP = re.compile(
    r"for\s+fid\s+in\s*\[([^\]]*)\]\s*\{\s*assert!\(\s*(!?)\s*is_counter_fid\(fid\)",
    re.S,
)

#: The fuzz target's mirror, its index expressions, and the reduction that makes
#: every entry selectable. `REDUCED` anchors at the END of the expression: the
#: defect this rule exists for carries a `%` of its own in front of the mask.
ARRAY = re.compile(rf"const {FUZZ_ARRAY}\s*:\s*\[u16;\s*\d+\]\s*=\s*\[([^\]]*)\]")
INDEXED = re.compile(rf"(?<!\w){FUZZ_ARRAY}\[([^\]]*)\]")
REDUCED = re.compile(rf"%\s*{re.escape(FUZZ_ARRAY)}\.len\(\)$")

#: The derivation cannot shrink to nothing without someone saying so: with no
#: names resolved every rule below compares an empty set to an empty set and the
#: row is green over an unguarded table. Floored under today's four so ordinary
#: movement does not trip it and a broken read does.
FLOOR_NAMES = 3


def bind(name):
    """A module-level `const <name>: u16 = …;`, whatever its visibility.

    `pub(crate)` counts — a home does not stop being one because the crate keeps
    it to itself — and so does a bare `const`. Column 0 is the whole of what is
    required instead: an indented `const` is inside a function or an impl, and a
    local shadowing a FID name is not its home.
    """
    return re.compile(rf"^(?:pub(?:\([^)]*\))?\s+)?const {re.escape(name)}\s*:\s*u16\s*=([^;]+);", re.M)


def sources(root):
    """Every crate `.rs` file outside `rsk-store`, as (path, code), git's list.

    From `git ls-files` rather than a walk, for `gate_lines.tree_files`'s reason:
    an agent worktree under `.claude/` is a whole second checkout, and a constant
    resolved there reads as a second, conflicting home.
    """
    out = []
    for relative in sorted(gate_lines.tree_files(root)):
        rel = relative.as_posix()
        if relative.suffix != ".rs" or not rel.startswith("crates/"):
            continue
        if rel.startswith(TABLE_CRATE):
            continue
        out.append((rel, gate_lines.rust_code((root / relative).read_text())))
    return out


def resolve(root, names):
    """({name: value}, problems) — each named constant, read out of its crate."""
    files, found, problems = sources(root), {}, []
    for name in names:
        homes, unreadable = {}, {}
        for rel, code in files:
            for value in bind(name).findall(code):
                spelled = value.strip()
                if HEX.fullmatch(spelled):
                    homes.setdefault(int(spelled.replace("_", ""), 16), []).append(rel)
                else:
                    unreadable.setdefault(spelled, []).append(rel)
        if unreadable:
            # Said apart from "no home at all", because they are different
            # repairs: this one is a constant sitting right there, spelled in a
            # way nothing here can turn into a number.
            problems.append(
                f"{TABLE} names `{name}`, which {sorted(unreadable)} defines as an"
                " expression rather than a literal — the copies hold numbers, so a"
                " home this cannot evaluate leaves them measured against nothing"
            )
        elif not homes:
            problems.append(
                f"{TABLE} names `{name}`, which no crate outside {TABLE_CRATE}"
                " defines as a `const … : u16` — the table's own file is not"
                " allowed to be the home, so this name derives nothing and every"
                " copy below is measured against a set it is missing from"
            )
        elif len(homes) > 1:
            spelled = ", ".join(f"0x{v:04X} in {sorted(f)}" for v, f in sorted(homes.items()))
            problems.append(f"`{name}` resolves to more than one value: {spelled}")
        else:
            found[name] = next(iter(homes))
    return found, problems


def literals(text):
    """The FID literals in `text`, as a set of ints.

    Underscores are dropped and anything wider than four digits with them: a FID
    is a `u16`, and a pattern that simply stopped at the fourth digit would read
    `0x10FFFF00` as `0x10FF` rather than as the address it is.
    """
    found = {h.replace("_", "") for h in HEX.findall(text)}
    return {int(h, 16) for h in found if len(h) <= len("0xFFFF")}


def compare(where, listed, derived, derived_names, both_ways=True):
    """`listed` against the derived set, naming the constants behind each miss."""
    problems = []
    if missing := sorted(derived - listed):
        problems.append(
            f"{where} does not list {[f'0x{v:04X}' for v in missing]}, which"
            f" {sorted(n for n in derived_names if derived_names[n] in missing)}"
            " resolve to — a live FID on the wrong side of the split reads absent"
            " on the partition it is fetched from while its old value stays live"
            " in the other ring"
        )
    if both_ways and (stray := sorted(listed - derived)):
        problems.append(
            f"{where} lists {[f'0x{v:04X}' for v in stray]}, which no constant"
            " named over `is_counter_fid` has — the table and the applet crates"
            " have drifted, which is what this row exists to notice"
        )
    return problems


def derive(root):
    """({name: value}, problems) — the roster the doc comment names, resolved."""
    table = (root / TABLE).read_text()
    doc = DOC.search(table)
    if doc is None:
        return {}, [f"{TABLE} has no doc comment over `pub fn is_counter_fid`"]
    names = sorted(set(NAMED.findall(doc.group(1))))
    if len(names) < FLOOR_NAMES:
        return {}, [
            f"{TABLE}'s comment over `is_counter_fid` names {len(names)} constant(s),"
            f" under the floor of {FLOOR_NAMES} — with nothing to resolve, every"
            " rule below compares an empty set to an empty set"
        ]
    return resolve(root, names)


def audit(root, derived):
    """Every disagreement between a hand-written copy and the applet crates."""
    table = (root / TABLE).read_text()
    values = set(derived.values())
    # The doc comment's own numbers: the missing direction only. It is prose as
    # well as a roster — the drift story quoting 0x0821 belongs above this very
    # function — and reading every hex in it as a claimed member is a red on a
    # sentence that is right.
    problems = compare(f"{TABLE}'s comment over `is_counter_fid`",
                       literals(DOC.search(table).group(1)), values, derived, both_ways=False)
    problems += table_arms(gate_lines.rust_code(table), values, derived)
    problems += host_loops(root, values, derived)
    problems += fuzz_mirror(root, values, derived)
    return problems


def table_arms(code, values, derived):
    """The `matches!` inside `is_counter_fid`, held to the derived set."""
    if (body := BODY.search(code)) is None:
        return [f"{TABLE} has no `pub fn is_counter_fid(…) -> bool` body to read"]
    if (found := MATCHES.search(body.group(1))) is None:
        return [f"{TABLE} has no `matches!(fid, …)` inside `is_counter_fid`"]
    arms = [arm.strip() for arm in found.group(1).split("|")]
    if unreadable := [a for a in arms if not HEX.fullmatch(a)]:
        return [
            f"{TABLE}'s `matches!` carries {unreadable}, which is not a bare FID"
            " literal — an arm this cannot read is reported rather than skipped,"
            " because skipping is how a copy stops being checked"
        ]
    return compare(f"{TABLE}'s `matches!`", literals(found.group(1)), values, derived)


def host_loops(root, values, derived):
    """The two loops in `tests.rs`, each held to the side it asserts."""
    code = gate_lines.rust_code((root / TESTS).read_text())
    loops = {"": [], "!": []}
    for listed, negated in LOOP.findall(code):
        loops[negated].append(listed)
    problems = []
    for negated, wanted in (("", "asserting `is_counter_fid`"), ("!", "asserting `!is_counter_fid`")):
        if len(loops[negated]) != 1:
            problems.append(
                f"{TESTS} has {len(loops[negated])} `for fid in [ … ]` loops"
                f" {wanted}, not one — the routing test is what holds the table"
                " with a wrong edit, so it has to be found"
            )
    if problems:
        return problems
    problems += compare(f"{TESTS}'s counter loop", literals(loops[""][0]), values, derived)
    if both := sorted(literals(loops["!"][0]) & values):
        problems.append(
            f"{TESTS} asserts {[f'0x{v:04X}' for v in both]} must stay in main while"
            " a constant over `is_counter_fid` routes it to the counter partition"
        )
    return problems


def fuzz_mirror(root, values, derived):
    """`FIDS` covers the derived set, and every entry is reachable by the selector."""
    code = gate_lines.rust_code((root / FUZZ).read_text())
    arrays = ARRAY.findall(code)
    if len(arrays) != 1:
        return [
            f"{FUZZ} declares {len(arrays)} `const {FUZZ_ARRAY}: [u16; N]`, not one"
            f" — with a second one the mirror this holds is whichever comes first"
        ]
    # A superset, not an equality, and not `compare`'s wording: the target
    # torments five main-partition FIDs as well, so a literal here that no
    # constant explains is a main FID and not drift — and a member it omits costs
    # a fuzz run, not a misroute.
    problems = []
    if missing := sorted(values - literals(arrays[0])):
        problems.append(
            f"{FUZZ}'s `{FUZZ_ARRAY}` does not list {[f'0x{v:04X}' for v in missing]},"
            f" which {sorted(n for n in derived if derived[n] in missing)} resolve"
            " to — the target then tears no record of that partition, and the"
            " mirror it replaced was missing `EF_CRED_CTR` for exactly that long"
        )
    indices = sorted(set(INDEXED.findall(code)))
    if not indices:
        problems.append(f"{FUZZ} never indexes `{FUZZ_ARRAY}`, so the mirror drives nothing")
    for index in indices:
        problems += selector(code, index.strip())
    return problems


def selector(code, index):
    """Whether one `FIDS[…]` can reach every entry, or why this cannot say.

    Every binding of a named index is required to reduce, not the first one
    found: one reduced `let` earlier in the file would otherwise vouch for a
    masked one below it, which is the shape of the drift being guarded.
    """
    if REDUCED.search(index):
        return []
    if not re.fullmatch(r"\w+", index):
        return [
            f"{FUZZ} selects `{FUZZ_ARRAY}[{index}]`, an index this cannot read —"
            " reported rather than skipped, since an unreadable selector is the"
            " one that stops being checked"
        ]
    bound = [m.group(1).strip() for m in re.finditer(rf"let\s+{index}\s*=([^;]*);", code)]
    if bound and all(REDUCED.search(b) for b in bound):
        return []
    return [
        f"{FUZZ} selects `{FUZZ_ARRAY}[{index}]` from {len(bound)} binding(s), not"
        f" all of which END in `% {FUZZ_ARRAY}.len()` — the mirror was `& 7` over"
        " nine entries once, so the ninth could never be written by any input"
        " while the sweep asserted it absent on every one, and a mask after the"
        " modulo puts entries back out of reach exactly the same way"
    ]


def run(root):
    try:
        derived, problems = derive(root)
        problems += audit(root, derived) if not problems else []
    except OSError as error:
        derived, problems = {}, [f"the counter-FID copies cannot be read: {error}"]
    if problems:
        print("partition-routing-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\n`is_counter_fid` decides which partition a record is written to and\n"
            "read back from. A FID on the wrong side reads absent while its old\n"
            "value stays live in the other ring, and every `for_each_key` yields a\n"
            "record nothing can delete. The set is spelled by hand in four places\n"
            "and has drifted in two of them, so its values are derived from the\n"
            "applet crates that own the constants rather than retyped.",
            file=sys.stderr,
        )
        return 1
    spelled = ", ".join(f"{name} 0x{value:04X}" for name, value in sorted(derived.items()))
    print(f"partition-routing-gate: ok — {spelled}, in all four copies")
    return 0


def main():
    if sys.argv[1:]:
        print("usage: partition_routing_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
