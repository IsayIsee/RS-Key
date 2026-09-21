#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the OTP use-counter's writer roster against the tree, both ways.

The Yubico-OTP use counter is the first two bytes of a slot record's 8-byte
tail, and it is the replay defence: a validation server orders OTPs by
`(use, session)`, so a counter that repeats hands out a pair it has already
accepted. `crates/rsk-otp/src/counter.rs` owns the *rule* that moves it, and
`counter_kani.rs` proves that rule.

Neither knew how many writers there were. `counter.rs` said "Both writers of the
non-volatile counter … take their step from here"; `counter_kani.rs` said
`cmd_config` and `cmd_update` "plus the two proved here are every writer of the
first two tail bytes". Derived here, there are EIGHT, and TWO of them take their
step from `counter.rs`. `cmd_swap` — which writes the bytes twice per command —
and `migrate_seal` — which writes them twice per boot — appear in neither
sentence. A proof whose stated scope is smaller than its sentence is the defect
this row exists to stop repeating, and it is the same failure `deleter_gate.py`
was written for one layer down: a ledger of judgements is only worth the roster
under it, so the roster is DERIVED and only the judgement is stored.

What is checked, and the direction of each:

* every derived persist site has exactly one entry, and every entry names a site
  that is still there. A new writer arrives unlisted and the row goes red — which
  is the property the two sentences above never had;
* a site is identified by `(file, fn, call)` and NOT by its line, which is the
  one place this deliberately departs from `deleter_gate.py`. That guard is
  about a per-call-site judgement, so a moved line is news; this one is about
  *how many writers there are*, and that answer must not change because an
  unrelated edit above pushed every site down twelve lines. Line freshness for
  the tree's citations is `citation_gate.py`'s row, not this one. The key has to
  be unique, so a derivation that produces it twice is itself a failure;
* `fn` — the enclosing function — is DERIVED, so a site cannot be re-attributed
  to a neighbour by editing the ledger;
* `kind` is DERIVED too. A `forwarder` is a persist helper that other persist
  sites call (`put_slot`), and it decides no byte; everything else is a writer.
  Recording that by hand would let a writer be relabelled out of the count;
* `proved` — whether `counter_kani.rs` covers the site — is held to the set of
  functions that actually call `next_use_counter`/`boot_use_counter`, derived
  from the tree. `proved = "no"` is required of every site outside that set and
  refused of every site inside it. `via` carries the one indirection there is
  (`button_ticket` → `ticket::build`) and must itself name a derived stepper, so
  the hop cannot be invented;
* the `[scope]` counts, because they are what `counter_kani.rs` now cites
  instead of a number typed into a doc comment;
* both counter files must cite this ledger. That is the whole repair: the
  harness's scope stops being a sentence and becomes a file the gate reads;
* and a `#[kani::proof]` in `counter_kani.rs` still calls each rule. Every clause
  above is derived from PRODUCTION code, so all of them passed with that file
  emptied: measured, both harnesses deleted was EXIT=0 here, still printing "2
  functions take their step from counter.rs" over no proof at all;
* no production source outside `crates/rsk-otp/` may reach `rsk_otp::seal`. The
  seal verb is `pub`, so a ninth writer could otherwise be added in `firmware/`
  or `tools/emu/` where this roster does not look;
* the roster is not empty. A derivation that finds nothing satisfies every rule
  above, which is the failure mode a verdict column cannot show.

Deliberately not here: whether a site's handling of the counter is *right*. That
is prose in the ledger and in the proof, and no script can check it. What this
row keeps honest is that the proof's stated scope is the tree's actual roster.
"""

import pathlib
import re
import sys
import tomllib

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent
LEDGER = pathlib.Path("assurance/otp_counter_writers.toml")

#: The crate that owns `EF_OTP_SLOT*`, and so the only place a slot record can be
#: addressed by name — the slot fids are `pub(crate)`.
CRATE = "crates/rsk-otp"

#: The two counter source files whose claims this ledger replaces.
COUNTER = f"{CRATE}/src/counter.rs"
PROOF = f"{CRATE}/src/counter_kani.rs"

#: The verbs that persist a whole slot record: the crate's own `put_slot` helper
#: and the `seal_put` it forwards to.
VERBS = ("put_slot", "seal_put")

#: A call to one of them. The receiver is deliberately NOT required. An earlier
#: version demanded a leading `.` or `::`, which made a BARE `seal_put(dev, …)`
#: invisible — and that spelling is this tree's own house style three times over
#: in `crates/rsk-piv/src/seal.rs`. Measured: a ninth writer spelled that way
#: left the row at EXIT=0 still reporting eight. `(?<!\w)` is what remains of the
#: receiver test, and it is the part that was doing real work: it separates
#: `seal_put(` from `my_seal_put(` while letting `.put_slot(` and `seal::seal_put(`
#: through.
PERSIST = re.compile(rf"(?<!\w)(?:{'|'.join(VERBS)})\s*\(")

#: `use crate::seal::seal_put as sp;` renames the verb, and a roster that only
#: knows the two spellings above stops seeing the call. Captured per file,
#: because an alias is scoped to the file that declares it.
ALIAS = re.compile(rf"(?<!\w)(?:{'|'.join(VERBS)})\s+as\s+(\w+)")

#: The rule that moves the counter, in the two spellings `counter.rs` exports. A
#: function whose body calls either of these is a "stepper": its bytes are the
#: ones `counter_kani.rs` reasons about.
RULES = ("next_use_counter", "boot_use_counter")
STEP = re.compile(rf"(?<![\w])({'|'.join(RULES)})\s*\(")

#: The attribute that makes a function a harness the solver runs. Read here as
#: well as in `kani_gate.py` because the two rows ask different questions: that
#: one asks whether the solver is pointed at the crate, this one whether the file
#: every `proved` verdict below is written about still reaches the rule.
KANI_PROOF = re.compile(r"^\s*#\[kani::proof\]")

#: A function definition, at the head of its line. Used to attribute a site to
#: the function that contains it by walking BACK, which is what makes `fn` a
#: derived field rather than a label — and to skip a DEFINITION line when
#: hunting callers: `fn next_use_counter(…)` matches [`STEP`] too, so without
#: this the two rules in `counter.rs` derive as their own callers and every
#: `proved` judgement is measured against a set of four instead of two.
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)")

#: A called name, last path segment only: `ticket::build(` yields `build`. Used
#: to read the one-hop call graph the `via` field claims, so the claim is a fact
#: about the caller rather than about the ledger.
CALLEE = re.compile(r"(?<![\w.])(?:\w+\s*::\s*)*(\w+)\s*\(")

#: A `use`/`mod` line, where a verb name is being imported rather than called.
#: Without this the `use crate::{… counter::next_use_counter …}` import in
#: `ticket.rs` makes the file's first function read as a stepper.
IMPORT = re.compile(r"^\s*(?:pub\s+)?(?:use|mod)\b")

#: How the rest of the tree could reach a slot record: `rsk_otp::seal` is `pub`.
#: The `{…}` alternative is not decoration — `use rsk_otp::{Rng as _R, seal};` is
#: this tree's own style (`fuzz/fuzz_targets/otp_apdu.rs`), and a plain
#: `rsk_otp::seal` match missed it: measured, a writer in `firmware/` imported
#: that way left the row at EXIT=0. The negated class spans newlines, so a
#: rustfmt-wrapped group is caught too.
REACHES_SEAL = re.compile(r"\brsk_otp\s*::\s*(?:seal\b|\{[^}]*\bseal\b)")

#: A cfg-gated source, by the convention AGENTS.md states: tests and proofs live
#: in sibling files hooked with `#[path]`. Derived from the naming rule rather
#: than listed, the way `deleter_gate.py` does it — cfg-gated code never reaches
#: the image, so a persist call there writes no device's counter.
#:
#: `_assurance.rs` is deliberately NOT here, though it is the third sibling of
#: that convention: `clientpin_assurance.rs` is hooked on
#: `cfg(any(test, kani, feature = "assurance-trace"))`, and that feature is a
#: real build rather than a test one. Excusing the suffix would excuse a file
#: that ships.
CFG_GATED = re.compile(r"(?:^|_)(tests|kani)\.rs$")

#: Not scope — the same carve-out `deleter_gate.py` states: `fuzz/` drives the
#: API rather than shipping a decision, and its targets are built by a separate
#: nightly workspace.
SKIP_DIRS = ("fuzz",)

#: The roster cannot shrink to nothing without someone saying so. Measured at 9
#: (8 writers + 1 forwarder) when this landed; floored under that so ordinary
#: movement does not trip it and a broken derivation does.
FLOOR_SITES = 6

KINDS = ("writer", "forwarder")
PROVED = ("yes", "partial", "no")

#: What a `[[site]]` may say, and which tables the file may have. Neither had a
#: list in the guard this is modelled on until an invented key was measured to
#: pass at EXIT=0: a key added here would be read by nothing and printed by
#: nothing, and a whole new table would be invisible in both directions.
SITE_FIELDS = ("fn", "file", "kind", "ordinal", "proved", "verb", "via", "why")
SCOPE_FIELDS = ("forwarders", "stepped", "writers")
TABLES = ("scope", "site")


def sources(root):
    """Every production `.rs` file of `crates/rsk-otp`, in a stable order.

    From `git ls-files` and not from a walk: an agent worktree under `.claude/`
    is a whole second copy of the checkout, and a roster walking the filesystem
    reports its sites as a second, unlisted set of writers (`gate_lines`'s own
    docstring, and the finding five other gates already read the tree for).
    """
    out = []
    for relative in sorted(gate_lines.tree_files(root)):
        rel = relative.as_posix()
        if relative.suffix != ".rs" or not rel.startswith(CRATE + "/"):
            continue
        if CFG_GATED.search(relative.name):
            continue
        out.append((rel, root / relative))
    return out


def outsiders(root):
    """Production files outside the crate that can reach `rsk_otp::seal`.

    The escape hatch this roster would otherwise not see: `seal_put` is `pub`, so
    a writer added in `firmware/` or `tools/emu/` would never be derived above.
    """
    out = []
    for relative in sorted(gate_lines.tree_files(root)):
        rel = relative.as_posix()
        if relative.suffix != ".rs" or rel.startswith(CRATE + "/"):
            continue
        if CFG_GATED.search(relative.name):
            continue
        if any(rel == d or rel.startswith(d + "/") for d in SKIP_DIRS):
            continue
        if REACHES_SEAL.search((root / relative).read_text()):
            out.append(rel)
    return out


def enclosing(lines, index):
    """The name of the function containing `lines[index]`, or `None`.

    A walk back to the nearest `fn` at the head of a line. It is what makes the
    ledger's `fn` a fact about the tree: a site cannot be filed under a
    neighbouring function by editing the ledger.
    """
    for at in range(index, -1, -1):
        found = FN.match(lines[at])
        if found:
            return found.group(1)
    return None


def steppers(root):
    """{(file, fn)} whose bodies take a step from `counter.rs`.

    Keyed on the FILE as well as the name, and that is not tidiness. Measured:
    with bare names, adding an unrelated `fn cmd_update` to `hid.rs` that calls
    `next_use_counter` made `lib.rs`'s own `cmd_update` read as covered and the
    row said "3 functions take their step" at EXIT=0. A stepper is a particular
    function in a particular file.

    Derived, because this is the set both replaced sentences got wrong. `use`/
    `mod` lines are skipped (importing the verb is not calling it, and the import
    in `ticket.rs` sits above every function in the file), and so are `fn`
    definition lines — `fn next_use_counter(` matches [`STEP`] too.
    """
    found = set()
    for rel, path in sources(root):
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines):
            if IMPORT.match(line) or FN.match(line) or line.strip().startswith("//"):
                continue
            if STEP.search(line) and (name := enclosing(lines, number)):
                found.add((rel, name))
    return found


def calls(root):
    """{(file, fn): {names it calls}} — the one-hop call graph.

    `button_ticket` does not step the counter itself; it reaches the rule through
    `ticket::build`. That hop used to be asserted by the ledger and checked only
    for naming *a* stepper, so a site could attach itself to a hop it never
    calls: measured, `cmd_update` marked `proved = "yes"` with `via = "build"`
    passed at EXIT=0 while calling neither. The hop is read out of the tree here
    instead, so the roster stops grading its own homework.
    """
    graph = {}
    for rel, path in sources(root):
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines):
            if IMPORT.match(line) or FN.match(line) or line.strip().startswith("//"):
                continue
            if (name := enclosing(lines, number)) is None:
                continue
            graph.setdefault((rel, name), set()).update(CALLEE.findall(line))
    return graph


def covered(root):
    """{(file, fn)}: the functions whose bytes `counter_kani.rs` reasons about.

    A function that steps the counter, or one that calls a function that does.
    Computed from the tree ALONE — no ledger field feeds it, which is the whole
    repair: `[scope] stepped` and every `proved` verdict are now measured against
    this rather than against what the ledger says about itself.
    """
    stepped = steppers(root)
    names = {fn for _rel, fn in stepped}
    graph = calls(root)
    return {key for key in graph if key in stepped or graph[key] & names}


def sites(root):
    """[(file, line, fn, ordinal, verb, kind)] for every persist call in the crate.

    A site is identified by `(file, fn, ordinal)` — the Nth persist call inside
    that function — and NOT by the text of its call line. Measured on the version
    that did: renaming a local from `rec` to `record` at one call site, same
    file, same function, same count, reported BOTH "does not list it" and "which
    persists nothing" at EXIT=1. Any rename or `rustfmt` reflow was a false red,
    and a guard that cries wolf is a guard someone deletes. `verb` is what
    survives of the call text, and it is the half that carries meaning.

    `kind` is derived in a second pass: a `forwarder` is a persist helper that
    other persist sites call, which today is `put_slot` and only `put_slot`. It
    is derived rather than recorded so a writer cannot be relabelled out of the
    count — the number is the whole point of this file.
    """
    raw, called, seen = [], set(), {}
    for rel, path in sources(root):
        text = path.read_text()
        lines = text.splitlines()
        # An alias is scoped to the file that renamed the verb, so the pattern is
        # rebuilt per file rather than once for the crate.
        verbs = list(VERBS) + ALIAS.findall(text)
        persist = re.compile(rf"(?<!\w)({'|'.join(map(re.escape, verbs))})\s*\(")
        for number, line in enumerate(lines, 1):
            if IMPORT.match(line) or FN.match(line) or line.strip().startswith("//"):
                continue
            for hit in persist.finditer(line):
                fn = enclosing(lines, number - 1) or "<module>"
                key = (rel, fn)
                ordinal = seen.get(key, 0)
                seen[key] = ordinal + 1
                called.add(hit.group(1))
                raw.append((rel, number, fn, ordinal, hit.group(1)))
    return [
        (rel, n, fn, ordinal, verb, "forwarder" if fn in called else "writer")
        for rel, n, fn, ordinal, verb in raw
    ]


def proven_rules(root):
    """The rules of `counter.rs` a `#[kani::proof]` in `counter_kani.rs` calls.

    Every `proved` verdict here, and `[scope] stepped`, are graded from PRODUCTION
    code alone — whether a writer's function reaches the rule. Nothing asked
    whether the proof reaching it still existed. Measured on this guard before
    this function: with BOTH harnesses deleted the row printed "2 functions take
    their step from counter.rs" at EXIT=0, and the whole `proved` column stood
    over an empty file. `kani_gate.py` catches that deletion, but by a crate-wide
    harness floor that names no property and would not survive the crate keeping
    two harnesses about something else.

    Attributed by [`enclosing`], not by proximity, so an edit above every harness
    moves nothing; comment lines are skipped, so a rule NAMED in the scope prose
    above a harness is not a rule the harness reaches.
    """
    lines = (root / PROOF).read_text().splitlines()
    harnesses, armed = set(), False
    for number, line in enumerate(lines):
        if KANI_PROOF.match(line):
            armed = True
        elif (found := FN.match(line)) and armed:
            harnesses.add(found.group(1))
            armed = False
    reached = set()
    for number, line in enumerate(lines):
        if IMPORT.match(line) or FN.match(line) or line.strip().startswith("//"):
            continue
        if STEP.search(line) and enclosing(lines, number) in harnesses:
            reached.update(STEP.findall(line))
    return reached


def audit(root):  # noqa: C901 — one clause per failure mode, each named
    """Every disagreement between the ledger and the tree, each reported once."""
    problems = []
    with (root / LEDGER).open("rb") as handle:
        doc = tomllib.load(handle)
    derived = sites(root)
    if len(derived) < FLOOR_SITES:
        problems.append(
            f"{len(derived)} persist sites derived, under the floor of {FLOOR_SITES}"
            " — the derivation found (almost) nothing, so every rule below passed"
            " over an empty roster"
        )
        return problems

    ledger = {(e["file"], e["fn"], e["ordinal"]): e for e in doc.get("site", [])}
    if len(ledger) != len(doc.get("site", [])):
        problems.append("two entries name the same file, function and ordinal")
    by_key = {(rel, fn, ordinal): (n, verb, kind) for rel, n, fn, ordinal, verb, kind in derived}

    for key in sorted(by_key.keys() - ledger.keys()):
        rel, fn, ordinal = key
        line, verb, _kind = by_key[key]
        problems.append(
            f"{rel}:{line} call #{ordinal} of `{verb}` in `{fn}` persists a slot"
            f" record and {LEDGER} does not list it — the counter has a writer the"
            " proof's scope does not mention, which is the exact defect this"
            " ledger replaces"
        )
    for key in sorted(ledger.keys() - by_key.keys()):
        rel, fn, ordinal = key
        problems.append(
            f"{LEDGER} lists call #{ordinal} in `{rel}` `{fn}`, which persists nothing"
        )

    stepped = steppers(root)
    reaches = covered(root)
    graph = calls(root)
    for key in sorted(by_key.keys() & ledger.keys()):
        rel, fn, ordinal = key
        line, verb, kind = by_key[key]
        entry = ledger[key]
        where = f"{rel}:{line}"
        if entry["verb"] != verb:
            problems.append(f"{where} calls `{verb}`, listed as `{entry['verb']}`")
        if entry["kind"] != kind:
            problems.append(
                f"{where} derives as a {kind} and is listed as a {entry['kind']}"
                " — `kind` is read from the tree, so a writer cannot be relabelled"
                " out of the roster"
            )
        hop = entry.get("via")
        # DERIVED, not read off the ledger. `hop` documents which call carries the
        # coverage; it cannot create it.
        is_covered = (rel, fn) in reaches
        if is_covered and entry["proved"] == "no":
            problems.append(
                f"{where} takes its step from counter.rs and is listed as unproved"
                " — a stepper demoted by a label is a proof quietly narrowed"
            )
        if not is_covered and entry["proved"] != "no":
            problems.append(
                f"{where} is listed as `{entry['proved']}` while `{fn}` neither"
                " calls next_use_counter/boot_use_counter nor calls anything that"
                f" does (steppers: {sorted(stepped)}) — counter_kani.rs does not"
                " reach it"
            )
        if hop is not None:
            if hop not in graph.get((rel, fn), set()):
                problems.append(
                    f"{where}: `via = \"{hop}\"` but `{fn}` does not call `{hop}` —"
                    " the hop is a fact about the caller, not a field the ledger"
                    " may assert"
                )
            elif not any(fn_name == hop for _f, fn_name in stepped):
                problems.append(
                    f"{where}: `via = \"{hop}\"` names no function that steps the counter"
                )
            if (rel, fn) in stepped:
                problems.append(f"{where}: `{fn}` steps the counter itself, so `via` describes nothing")

    scope = doc.get("scope", {})
    counted = {
        "writers": sum(1 for *_, kind in derived if kind == "writer"),
        "forwarders": sum(1 for *_, kind in derived if kind == "forwarder"),
        # From the DERIVED graph, not from the ledger's own `via`. Counting the
        # ledger let it certify itself: `cmd_update` claiming `via = "build"`
        # took `stepped` from 2 to 3 and the row stayed at EXIT=0.
        "stepped": sum(1 for rel, _n, fn, *_ in derived if (rel, fn) in reaches),
    }
    for field, value in sorted(counted.items()):
        if scope.get(field) != value:
            problems.append(
                f"[scope] {field} = {scope.get(field)} and the tree has {value}"
                " — counter_kani.rs cites this table instead of a number in a"
                " doc comment, so it is the sentence that goes stale here"
            )

    for rel in (COUNTER, PROOF):
        if LEDGER.as_posix() not in (root / rel).read_text():
            problems.append(
                f"{rel} does not cite {LEDGER} — its scope is a sentence again,"
                " which is what was wrong with it"
            )
    if unproved := sorted(set(RULES) - proven_rules(root)):
        problems.append(
            f"no `#[kani::proof]` in {PROOF} calls {unproved} — the `proved`"
            " column and `[scope] stepped` are derived from production code, so"
            " they go on grading a rule the proof no longer reaches"
        )
    if stray := sorted(outsiders(root)):
        problems.append(
            f"{stray} reach `rsk_otp::seal` from outside {CRATE} — a writer there"
            " is invisible to this roster, so the seal verb stays crate-local"
        )

    if stray := sorted(set(doc) - set(TABLES)):
        problems.append(f"{LEDGER} carries {stray}, which nothing reads")
    if stray := sorted(set(scope) - set(SCOPE_FIELDS)):
        problems.append(f"[scope] carries {stray}, which nothing reads")
    for entry in doc.get("site", []):
        where = f"{entry['file']} `{entry['fn']}`"
        if stray := sorted(set(entry) - set(SITE_FIELDS)):
            problems.append(f"{where}: carries {stray}, which nothing reads")
        if entry["kind"] not in KINDS:
            problems.append(f"{where}: kind `{entry['kind']}` is not one of {KINDS}")
        if entry["proved"] not in PROVED:
            problems.append(f"{where}: proved `{entry['proved']}` is not one of {PROVED}")
        if not entry.get("why", "").strip():
            problems.append(f"{where}: a listed writer with no reason is not a judgement")
    return problems


def run(root):
    try:
        problems = audit(root)
    except (KeyError, OSError, tomllib.TOMLDecodeError) as error:
        problems = [f"{LEDGER} cannot be read as a writer roster: {error}"]
    if problems:
        print("counter-writers-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nThe OTP use counter is the replay defence, and every site that\n"
            "persists a slot record writes it. Both halves of that counter's own\n"
            "documentation once stated a roster from memory and both were wrong —\n"
            f"so the roster lives in {LEDGER}, derived from the tree, and\n"
            "counter_kani.rs cites it rather than counting writers in prose.",
            file=sys.stderr,
        )
        return 1
    derived = sites(root)
    writers = sum(1 for *_, kind in derived if kind == "writer")
    print(
        f"counter-writers-gate: ok — {writers} writers of the OTP use counter,"
        f" {len(derived) - writers} forwarder(s), each listed;"
        f" {len(steppers(root))} functions take their step from counter.rs"
    )
    return 0


def main():
    if sys.argv[1:]:
        print("usage: counter_writers_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
