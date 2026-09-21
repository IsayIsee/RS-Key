#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the secret-lifetime register against the wipes the tree actually has.

`docs/threat-model.md`'s Zeroization clause says key-grade material in RAM is
wiped when its use ends — on drop, at end of scope including error paths, and
out of the transport buffers as soon as a message completes — and names three
accepted residuals. Nothing read that sentence against the code. There was no
inventory of *which* secrets those are, no statement of which of a request's
exits each wipe is on, and the one exit the clause never mentions is the one
where nothing runs at all: this firmware links `panic-halt`, so a panic spins
in place with no unwinding, no `Drop`, and every secret in the frame resident.
That absence was the finding this file was written for, and it is now a named
residual with a trigger rather than a silence.

A register of judgements is worth the roster under it, so the roster is DERIVED
and nothing about which secrets exist is stored. `assurance/secrets.toml` holds
only what a script cannot decide: what the secret IS, which of the exits its
wipe is on, and why the ones it is not on are allowed.

Seven rules:

* the ROW SET is the union of three derivations over the shipped sources — a
  `.zeroize()` call, a `Zeroizing` wrapper, and a type that wipes itself on
  `Drop` (a wiping `impl Drop`, or a `ZeroizeOnDrop` derive). Held both ways: a
  file that starts carrying a secret arrives unowned, and a row over a file that
  carries none is stale. The scope is the device image, and `tools/` is out
  because the five exits below are properties of the *device* — a halt with no
  unwinding, a reboot that clears SRAM — which a host process does not have. So
  that exclusion cannot be silent, its site count is derived too and held to a
  stated number — and a source in NEITHER list is a finding, because two tuples
  answer for what is inside them and say nothing about `rsk-wipe/` or `fuzz/`;
* `bearers`, `sites` and `skippable` are DERIVED per row and compared. A
  hand-written count in a register is the defect this programme keeps finding,
  so none is read for truth: a wipe deleted from a file moves its count and
  reddens the row. The PROSE is held the same way wherever it states a count in
  the one spelling that cannot be domain vocabulary — `N of M` — because the
  headline of this register is a number in a sentence. That clause found its
  first error the hour it was written, in this file's own residual;
* each row answers for SUCCESS, ERROR and CANCEL, and every word is held against
  the derivation rather than read. `explicit` needs a wipe in that file and
  `on-drop` a bearer defined in it; on the two exits an early return reaches,
  both also need the file to have NO wipe sitting below one, which is counted —
  the threat model's "at end of scope including error paths" is a claim about
  444 statements and 300 of them are under one. A file where that count is not
  zero answers `partial` and owes a residual. The cancel exit is narrower still:
  the worker's dispatch is synchronous, so a cancel is observed only where a PIN
  entry or a cancel frame is, and whether this source is one of those is derived
  — `n/a` there is a fact rather than a judgement, and a file that starts taking
  a PIN entry stops being allowed to answer it;
* the PANIC exit is derived, not stated. `firmware/Cargo.toml` links a halting
  panic runtime and no source in the tree defines one of its own, so no
  destructor and no explicit wipe runs on any row — one answer for all, which is
  writing it per row would be 56 copies of one fact. It owes exactly one
  residual, carrying a reason and a revalidation trigger, and the day a real
  `#[panic_handler]` appears this row goes red asking for the judgement again;
* the REBOOT exit rests on `worker::reboot` calling a set of scrubs before it
  drops the device, and that set is DERIVED out of its body the way
  `deleter_gate.py` derives its `head_minters`. Deleting `otp_kbd::scrub()` from
  it is then a finding rather than an edit, and any row resting on a wiper is
  held to the derived list;
* a RESIDUAL is a stated reason plus a trigger that would make it stale, and
  both are required. One naming an exit no row leaves open is refused as stale,
  and one nothing points at is too — the exception to that being the panic
  residual, which every row inherits by derivation rather than by reference. A
  residual that hands its reasoning to a board question names the `PLAT-…` id
  that owns it, held against `assurance/platform.toml` and printed with its live
  status, because `citation_gate.py` does not read that file at all;
* the roster is not empty, the counts do not collapse, and the threat clause the
  rows source to is really declared in `assurance/threat_clauses.toml`, is a
  defence, and carries the `rests_on` pins locking the sentences these rows
  answer — all three are BELOW that clause's locked first line, so unpinned the
  page could be rewritten under the whole register with the threat gate green.
  A derivation that finds nothing satisfies every rule above.

What this cannot say, and the first one is worth being blunt about. The roster
is a roster of WIPES, not of secrets: a source is in it because it wipes, wraps,
or defines a self-wiping type, so a source that unseals a key into a static and
never touches it again is in no row and owes no answer — the shape a secret
inventory would most like to catch is the one this derivation is blind to by
construction. Nor whether a wipe is REACHED: `skippable` is syntax, the exits are
judged per file rather than per statement, and the register records which exits
the author checked. Nor whether the compiler kept the write, which is a
disassembly question and `elf_gate.py` is the place for it.
"""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTER = pathlib.Path("assurance/secrets.toml")
CLAUSES = pathlib.Path("assurance/threat_clauses.toml")
MANIFEST = pathlib.Path("firmware/Cargo.toml")
REBOOT_FILE = pathlib.Path("firmware/src/worker.rs")
#: The platform registry, borrowed rather than copied: a residual that hands its
#: reasoning to a board question hands it to an id THAT file owns.
ASSUMPTIONS = pathlib.Path("assurance/platform.toml")
#: A `PLAT-…` id as a residual writes one.
PLAT = re.compile(r"\bPLAT-[A-Z0-9-]+\b")

#: What ships on the device. `tools/` is a host program: its PIN buffer is a real
#: secret, but the exits below are the device's — a halting panic, a reboot that
#: clears SRAM — and a host row would answer five questions that do not apply to
#: it. Held rather than dropped: [`OUT_OF_SCOPE`] is counted and stated.
SCOPE = ("crates", "firmware")
OUT_OF_SCOPE = ("tools",)

#: cfg-gated sources, by the naming rule AGENTS.md states rather than by a list:
#: tests and proofs live in sibling `*_tests.rs` / `*_kani.rs` files hooked in
#: with `#[path]`. A fixture wiping its own copy is not a shipped decision.
CFG_GATED = re.compile(r"(?:^|_)(tests|kani)\.rs$")

#: The explicit wipe, in both spellings Rust has for it. The receiver is not
#: tested: `zeroize` is the crate's one method name and nothing else in the tree
#: defines one. The second alternative is UFCS — `Zeroize::zeroize(k)`,
#: `zeroize::Zeroize::zeroize(k)`, `<[u8; 32] as Zeroize>::zeroize(k)` — which
#: the method spelling cannot see, and which a review measured as invisible: a
#: source whose only wipes were UFCS was in no roster and owed no row. Zero such
#: sites today, so this is reachable rather than reached, which is exactly when
#: it is cheap to close.
CALL = re.compile(r"\.zeroize\s*\(\s*\)|\bZeroize\s*>?\s*::\s*zeroize\s*\(")

#: A `#[cfg(test)]` / `#[cfg(kani)]` attribute, wherever it sits. `CFG_GATED`
#: below is a FILENAME rule and this is the other half: `seed.rs` carries an
#: inline `#[cfg(test)] pub(crate) fn wrap_keydev_legacy` whose two wipes were
#: counted as shipped, so the tree's highest-value row read 37 where the image
#: has 35, and the register total and its headline inherited it.
CFG_ITEM = re.compile(r"#\s*\[\s*cfg\s*\(\s*(?:test|kani)\s*\)\s*\]")
#: The wrapper that wipes what it owns when it drops. Counted as a bearer signal
#: rather than a bearer: it names no type of its own.
WRAP = re.compile(r"\bZeroizing\b")
#: `impl Drop for T`, with the optional generic parameter list a lifetime or a
#: backend parameter puts there.
#: `impl Drop for T`, with the optional generic parameter list. The parameter
#: list is matched by BRACKET DEPTH rather than by `<[^>]*>`, because the latter
#: stops at the first `>` and so loses `impl<T: AsRef<[u8]>> Drop for Key<T>` —
#: measured: a nested bound made the bearer invisible, and the file could then
#: never answer `on-drop`. The nine live impls are all flat.
DROP = re.compile(
    r"\bimpl(?:\s*<(?:[^<>]|<[^<>]*>)*>)?[^;{]*?\bDrop\s+for\s+([A-Za-z_][A-Za-z0-9_]*)"
)
#: `#[derive(… ZeroizeOnDrop …)]` over a type, tolerating the attributes that sit
#: between the derive and the item.
DERIVE = re.compile(
    r"#\s*\[\s*derive\s*\(([^)]*)\)\s*\]((?:\s|#\[[^]]*\])*)"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:struct|enum|union)\s+([A-Za-z_][A-Za-z0-9_]*)"
)

#: The reboot path's wipes, as `worker::reboot` spells them. The leading receiver
#: chain is captured because `ctap.scrub_secrets` and `ccid.scrub` are different
#: wipes over different buffers and a bare method name would merge them.
SCRUB = re.compile(r"((?:[A-Za-z_]\w*(?:\(\s*\))?\s*(?:\.|::)\s*)*scrub\w*)\s*\(")
#: The one operator whose body IS the reboot path.
REBOOT_FN = re.compile(r"\bfn\s+reboot\b")

#: A halting panic strategy: nothing unwinds, so no destructor runs. Either
#: spelling puts the whole tree on one answer for the panic exit.
PANIC_CRATE = re.compile(r"^\s*panic-(?:halt|abort)\s*=", re.M)
PANIC_ABORT = re.compile(r"^\s*panic\s*=\s*[\"']abort[\"']", re.M)
#: A handler the firmware writes itself, which would be free to wipe before it
#: halts. There is none today; one arriving is the trigger to re-judge.
PANIC_HANDLER = re.compile(r"#\s*\[\s*panic_handler\s*\]")

#: What an early exit from a function looks like. Not a control-flow analysis and
#: not sold as one: it is the syntax that CAN leave a wipe below it unrun, and it
#: is what turns "wiped at end of scope including error paths" from a sentence
#: into a number a row has to answer for. Two corrections a review measured. It
#: used to count `ok_or` and a bare `map_err(`, neither of which returns from
#: anything — 3 wipes over 3 rows inflated. And it read `return Err`/`return
#: None` only, so `return Sw::MEMORY_FAILURE` was invisible: the card applets do
#: not return `Result`, and `rsk-piv`'s `lib.rs` derived ZERO early exits over
#: eleven real ones. A trailing `?` at end of line is the third spelling and is
#: matched here too.
EARLY = re.compile(r"\?\s*(?:[;,).]|$)|\breturn\b")

#: Where a cancel is OBSERVED. Everything else runs inside the worker's
#: synchronous dispatch, which a `CTAPHID_CANCEL` sets a flag for rather than
#: unwinds — so `n/a` on the cancel exit is a derived fact for those rows and a
#: judgement only for these. A file that starts taking a PIN entry stops being
#: allowed to answer `n/a`. `SECURE_ERR_CANCELLED` was here and is gone: it
#: matched `rsk-usb/src/ccid.rs` on the line DECLARING the constant, so that row's
#: "derived fact" was "this file defines a name containing CANCELLED".
CANCELLABLE = re.compile(
    r"\bPinEntry\b|\brequest_cancel\b|\bis_cancel_frame\b|\bCTAPHID_CANCEL\b"
    r"|\bcollect_pin\b"
)

#: The exits a row answers for. `panic` is absent on purpose — it is derived once
#: for every row, and a per-row field would be a copy of that one fact.
EXITS = ("success", "error", "cancel", "reboot")
#: What an exit may say. `wiper` and `platform` are the reboot exit's alone: the
#: first names a scrub `worker::reboot` calls, the second the SRAM clear the
#: threat model measures, which is a property of the silicon and so owes a
#: residual with a trigger. `partial` belongs to the two exits an early return
#: reaches, and says at least one of the file's wipes sits BELOW one — so that
#: exit is not covered. (An earlier wording said "not all below one", which is
#: the opposite and is false of `openpgp/keys.rs`, where all 21 are below.)
ANSWERS = ("explicit", "on-drop", "partial", "wiper", "platform", "not-wiped", "n/a")
#: Which words each exit may take. A single ANSWERS list let a review flip a row's
#: reboot answer to `explicit` — escaping the wiper rule AND the residual rule at
#: once, since neither is about `explicit` — and let `n/a` stand on `success` and
#: `error`, where nothing derives it, so the register's highest-value row could
#: answer "the error exit cannot happen here" and pass. `n/a` is a DERIVED word
#: and it is derived for the cancel exit alone.
ALLOWED = {
    "success": ("explicit", "on-drop", "not-wiped"),
    "error": ("explicit", "on-drop", "partial", "not-wiped"),
    "cancel": ("explicit", "on-drop", "partial", "not-wiped", "n/a"),
    "reboot": ("wiper", "platform", "not-wiped"),
}
#: The exits an early return can leave a wipe below.
EARLY_EXITS = ("error", "cancel")
#: The answers that are not a wipe, and so owe the reason an argument about that
#: exit rather than a blank. `partial` is one of them: it names a residual too,
#: but it is a measured count rather than a judgement, so the reason is spared.
OPEN = ("not-wiped", "n/a")
#: The answers that leave something resident, and so owe a residual. `n/a` is not
#: one: it says the exit cannot happen here, which is a scope claim rather than a
#: risk, and the derivation already holds the only `n/a` this register uses.
NEEDS_RESIDUAL = ("not-wiped", "partial", "platform")

SECRET_FIELDS = (
    "bearers",
    "cancel",
    "error",
    "file",
    "reboot",
    "residual",
    "secret",
    "sites",
    "skippable",
    "success",
    "why",
    "wiper",
    "wraps",
)
RESIDUAL_FIELDS = ("applies", "id", "paths", "revalidate", "what", "why")
#: Who a residual is about. `rows` is the ordinary one and must be pointed at by
#: the rows that leave an exit open on it; `register` is the shape the panic exit
#: forced — a fact true of every row at once, where 56 citations would be 56
#: copies of one sentence and the citation rule would stop meaning anything.
APPLIES = ("register", "rows")
TABLES = ("clause", "out_of_scope_sites", "reboot_wipers", "residual", "secret")

#: Floors under today's measurement (56 rows over 446 wipes, 11 bearer types), so
#: ordinary movement does not trip them and a derivation that stopped reading the
#: tree does. A register over an empty roster passes every rule above.
FLOOR_ROWS = 40
FLOOR_SITES = 350
FLOOR_BEARERS = 8


def sources(root, scope=None):
    """Every shipped `.rs` under `scope`, from git's answer rather than a walk.

    `gate_lines.tree_files` for the reason its own docstring gives: a filesystem
    walk descends into the agent worktrees under `.claude/` and into the second
    `target/` the detached workspaces build, and a roster then depends on whether
    anyone had run cargo. `scope=None` is the whole checkout, which is what
    [`unscoped`] needs.
    """
    for rel in sorted(gate_lines.tree_files(root)):
        if rel.suffix != ".rs" or CFG_GATED.search(rel.name):
            continue
        if scope is not None and rel.as_posix().split("/")[0] not in scope:
            continue
        yield rel.as_posix(), root / rel


def unscoped(root):
    """Sources that carry a wipe and are in NEITHER list.

    The hole every new guard in this tree has shipped with, one layer out: a
    scope written as two tuples answers for what is inside them and says nothing
    about the rest of the checkout. `rsk-wipe/` links the same halting panic
    runtime and `fuzz/` builds the same crates, and a wipe appearing in either
    would be invisible to every rule above — measured at zero today, which is
    exactly when a rule like this is cheap to add and impossible to notice
    missing.
    """
    known = set(SCOPE) | set(OUT_OF_SCOPE)
    out = []
    for rel, path in sources(root):
        if rel.split("/")[0] in known:
            continue
        code = shipped(gate_lines.rust_code(path.read_text(encoding="utf-8")))
        found = len(CALL.findall(code))
        if found or WRAP.search(code) or bearers_in(code):
            out.append((rel, found))
    return out


def bearers_in(code):
    """The types in this source that wipe themselves when they drop.

    A `Drop` impl counts only when its body wipes: `rsk-fs` and the display stack
    both have destructors that release a peripheral, and reading those as secret
    bearers would put a row over a file with no secret in it.
    """
    found = []
    for hit in DROP.finditer(code):
        if CALL.search(braced(code, hit.end())):
            found.append(hit.group(1))
    for hit in DERIVE.finditer(code):
        if "ZeroizeOnDrop" in hit.group(1):
            found.append(hit.group(3))
    return sorted(set(found))


#: `N of M`, `N of the M`, `N of its M`, `N of these M` — the one shape in which
#: this register's prose states a count of its OWN quantities. Deliberately not
#: "every integer": the rows are full of `P-256`, `ML-DSA-87`, `SLIP-39`,
#: `AES-256-GCM` and `audit run-34 #23`, and a rule reading those as counts is
#: `docstring_count_gate.py`'s refused version — it ignores digits for exactly
#: this reason. Measured over the register as written: this matches five phrases
#: and none of the vocabulary.
RATIO = re.compile(r"\b(\d+) of (?:the |its |these )?(\d+)\b")

#: A function head, at any indent and in the spellings this tree writes.
FN = re.compile(
    r"^(\s*)(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?"
    r"fn\s+([A-Za-z_]\w*)",
    re.M,
)


def skippable_in(code):
    """How many of this source's wipes sit below an early exit of their function.

    A PROXY and reported as one: the `?` may be in a branch the wipe is not
    under, or the value may be owned by a caller that wipes it whatever this
    function returns — `clientpin`'s `perform_builtin_uv` returns on four entry
    outcomes without touching `pin`, and `builtin_uv` above it owns that buffer
    and wipes it on all four. What the number is good for is the direction it
    forbids: a file where it is ZERO cannot have a wipe an early return skips,
    so `explicit` on the error exit is a claim the derivation supports, and a
    file where it is not zero owes a residual instead of a claim.
    """
    lines = code.splitlines()
    heads = [at for at, line in enumerate(lines) if FN.match(line)]
    heads.append(len(lines))
    found = 0
    for index in range(len(heads) - 1):
        early = False
        for at in range(heads[index], heads[index + 1]):
            if CALL.search(lines[at]) and early:
                found += 1
            if EARLY.search(lines[at]):
                early = True
    return found


def shipped(code):
    """`code` with every `#[cfg(test)]` / `#[cfg(kani)]` item blanked, spans kept.

    `CFG_GATED` puts the sibling test and proof FILES out; this puts the inline
    ones out, and the two together are what "the image" means. Without it the
    device master seed's row counted two wipes that no firmware contains.
    """
    out, at = [], 0
    for found in CFG_ITEM.finditer(code):
        if found.start() < at:
            continue
        block = braced(code, found.end())
        if block:
            stop = code.index(block, found.end()) + len(block)
        else:
            semi = code.find(";", found.end())
            stop = found.end() if semi < 0 else semi + 1
        out.append(code[at:found.start()])
        out.append(" " * (stop - found.start()))
        at = stop
    out.append(code[at:])
    return "".join(out)


def braced(text, start):
    """The `{ … }` block beginning at or after `start`, brace-balanced."""
    open_at = text.find("{", start)
    if open_at < 0:
        return ""
    depth, at = 0, open_at
    while at < len(text):
        if text[at] == "{":
            depth += 1
        elif text[at] == "}":
            depth -= 1
            if not depth:
                return text[open_at : at + 1]
        at += 1
    return text[open_at:]


def derive(root, scope=SCOPE):
    """`file -> {sites, wraps, bearers}` over `scope`, comments and strings blanked.

    Lexed with `gate_lines.rust_code` for the reason that helper exists: the word
    `zeroize` appears in rustdoc all over this tree ("zeroized on drop" is the
    phrase `rsk-rsa`'s key module opens with), and a raw scan counts the sentence
    describing a wipe as a wipe.
    """
    out = {}
    for rel, path in sources(root, scope):
        code = shipped(gate_lines.rust_code(path.read_text(encoding="utf-8")))
        row = {
            "sites": len(CALL.findall(code)),
            "wraps": len(WRAP.findall(code)),
            "bearers": bearers_in(code),
            "skippable": skippable_in(code),
            "cancellable": bool(CANCELLABLE.search(code)),
        }
        if row["sites"] or row["wraps"] or row["bearers"]:
            out[rel] = row
    return out


def reboot_wipers(root):
    """The scrubs `worker::reboot` calls, in the order its body calls them.

    Derived rather than listed for `deleter_gate.py`'s reason one file over: a
    register that names the reboot wipes is a second copy of the reboot path, and
    the copy is what goes stale. `self.` and `crate::` are stripped so the names
    read as the wipes rather than as the paths to them.
    """
    text = (root / REBOOT_FILE).read_text(encoding="utf-8")
    code = shipped(gate_lines.rust_code(text))
    found = REBOOT_FN.search(code)
    if not found:
        return None
    out = []
    for hit in SCRUB.finditer(braced(code, found.end())):
        name = re.sub(r"\s+", "", hit.group(1))
        name = re.sub(r"^(?:self\.|crate::)", "", name)
        if name not in out:
            out.append(name)
    return out


def panic_wipes(root):
    """Whether ANY wipe runs on a panic, and the sentence saying why not.

    Two halves, because either alone reads the wrong answer: the manifest says
    the strategy is a halt, and `firmware/src` is read for a handler of the
    firmware's own, which would be free to wipe before halting and would make
    the derived answer wrong.
    """
    manifest = (root / MANIFEST).read_text(encoding="utf-8")
    halting = bool(PANIC_CRATE.search(manifest) or PANIC_ABORT.search(manifest))
    # The WHOLE checkout, not `firmware/src`: panic behaviour is a property of the
    # image, and a handler in a `crates/rsk-*` the firmware links is the same
    # handler. Reading one directory was measured green over a handler in a crate.
    own = [
        rel
        for rel, path in sources(root)
        if PANIC_HANDLER.search(gate_lines.rust_code(path.read_text(encoding="utf-8")))
    ]
    if own:
        return True, f"{', '.join(own)} defines a #[panic_handler] of its own"
    if not halting:
        return True, f"{MANIFEST} links no halting panic strategy"
    return False, (
        f"{MANIFEST} links a halting panic runtime and no source in the tree defines"
        " a #[panic_handler] of its own, so nothing unwinds and no destructor runs"
    )


def clauses(root):
    """`id -> entry` out of the threat-clause registry."""
    doc = tomllib.loads((root / CLAUSES).read_text(encoding="utf-8"))
    return {entry["id"]: entry for entry in doc.get("clause", [])}


def assumptions(root):
    """`id -> status` out of the platform registry.

    Read, never written. A residual whose reasoning rests on a board question
    names the id that owns it, and `citation_gate.py` cannot hold that: its own
    docstring says it resolves `.rs`/`.sh`/`.txt`/`.py` citations and does not
    read `assurance/*.toml` outside `bundle/`, so a `PLAT-…` written here would
    be checked by nothing at all. That blind spot is why this reads the file.
    """
    doc = tomllib.loads((root / ASSUMPTIONS).read_text(encoding="utf-8"))
    return {entry["id"]: entry.get("status") for entry in doc.get("assumption", [])}


def check_ratios(label, prose, quantities, problems):
    """Hold every `N of M` in `prose` to the quantities it can be about.

    The register's headline sentence is "213 of the 446 wipes sit below an early
    exit", and it is the finding this file reports. A finding written as a number
    beside a derivation that produces the same number is exactly the shape the
    `sites` field is held for; this holds the prose the same way, and only in the
    one spelling that cannot be domain vocabulary.
    """
    for part, whole in RATIO.findall(prose):
        stray = [n for n in (part, whole) if int(n) not in quantities]
        if stray:
            problems.append(
                f"{label}: its reason says `{part} of {whole}` and"
                f" {', '.join(stray)} is not a number this register derives"
                f" ({sorted(quantities)}) — re-read the derivation, do not re-type it"
            )
        elif int(part) > int(whole):
            # Membership alone let `22 of its 28` become `28 of its 22`, measured
            # at exit 0: both numbers are derived, and the RELATION is the claim.
            problems.append(
                f"{label}: its reason says `{part} of {whole}`, and a part larger than"
                " its whole is not a count of anything"
            )


def check_rows(register, derived, wipers, problems):
    """The register's rows against the derivation, both ways."""
    rows = register.get("secret", [])
    owned = {}
    for index, row in enumerate(rows):
        if stray := sorted(set(row) - set(SECRET_FIELDS)):
            problems.append(f"{REGISTER}: entry #{index + 1} carries {stray}, which nothing reads")
        rel = row.get("file")
        if not rel:
            problems.append(f"{REGISTER}: entry #{index + 1} has no 'file'")
            continue
        if rel in owned:
            problems.append(f"{rel}: owned twice in {REGISTER}")
            continue
        owned[rel] = row

    for rel in sorted(set(derived) - set(owned)):
        found = derived[rel]
        problems.append(
            f"{rel} carries key-grade material ({found['sites']} wipe(s),"
            f" {found['wraps']} wrapper(s), bearers {found['bearers'] or 'none'}) and"
            f" {REGISTER} does not answer for it — a secret arrived unowned"
        )
    for rel in sorted(set(owned) - set(derived)):
        problems.append(
            f"{REGISTER} answers for {rel}, which wipes nothing and defines no"
            " self-wiping type — either the secret left or the row is stale"
        )

    for rel in sorted(set(owned) & set(derived)):
        row, found = owned[rel], derived[rel]
        if row.get("sites") != found["sites"]:
            problems.append(
                f"{rel}: the register states {row.get('sites')} wipe(s) and the file"
                f" has {found['sites']} — re-read the file, do not re-type the number"
            )
        if sorted(row.get("bearers", [])) != found["bearers"]:
            problems.append(
                f"{rel}: the register states bearers {sorted(row.get('bearers', []))}"
                f" and the file defines {found['bearers']}"
            )
        if row.get("skippable") != found["skippable"]:
            problems.append(
                f"{rel}: the register states {row.get('skippable')} wipe(s) below an"
                f" early exit and the file has {found['skippable']}"
            )
        # Derived and, until a review said so, compared to nothing: three rows'
        # reasoning rests on `Zeroizing` as the thing covering their early
        # returns, and all 23 mentions could leave `rsk-rsa/src/key.rs` without
        # moving a held number.
        if row.get("wraps") != found["wraps"]:
            problems.append(
                f"{rel}: the register states {row.get('wraps')} `Zeroizing` mention(s)"
                f" and the file has {found['wraps']}"
            )
        if not row.get("secret", "").strip():
            problems.append(f"{rel}: a row that does not say what the secret is is not one")
        why = row.get("why", "")
        if not why.strip():
            problems.append(f"{rel}: an answer with no reason is not one — 'why' is empty")
        check_ratios(
            rel,
            why,
            {
                found["sites"],
                found["skippable"],
                found["sites"] - found["skippable"],
                len(found["bearers"]),
            },
            problems,
        )
        for exit_name in EXITS:
            answer = row.get(exit_name)
            if answer not in ANSWERS:
                problems.append(
                    f"{rel}: {exit_name} answers `{answer}`, which is not one of {list(ANSWERS)}"
                )
                continue
            if answer not in ALLOWED[exit_name]:
                problems.append(
                    f"{rel}: {exit_name} answers `{answer}`, which that exit does not"
                    f" take — it takes {list(ALLOWED[exit_name])}"
                )
                continue
            if answer == "explicit" and not found["sites"]:
                problems.append(
                    f"{rel}: {exit_name} claims an explicit wipe and the file has none"
                )
            if answer == "on-drop" and not found["bearers"]:
                problems.append(
                    f"{rel}: {exit_name} claims a wipe on drop and the file defines no"
                    " self-wiping type"
                )
            if (
                exit_name in EARLY_EXITS
                and answer in ("explicit", "on-drop")
                and found["skippable"]
            ):
                problems.append(
                    f"{rel}: {exit_name} claims every wipe runs and {found['skippable']}"
                    " of them sit below an early exit of their own function — the"
                    " answer there is `partial` with a residual, not a claim"
                )
            if answer == "partial" and not found["skippable"]:
                problems.append(
                    f"{rel}: {exit_name} is recorded `partial` and no wipe sits below an"
                    " early exit — the file caught up with the register"
                )
            if exit_name == "cancel" and (answer == "n/a") == found["cancellable"]:
                problems.append(
                    f"{rel}: cancel answers `{answer}` and the file"
                    f" {'takes' if found['cancellable'] else 'takes no'} PIN entry or"
                    " cancel frame — a cancel this source never sees cannot be wiped"
                    " on, and one it does see cannot be `n/a`"
                )
            if answer in OPEN and exit_name != "cancel" and exit_name not in why.lower():
                problems.append(
                    f"{rel}: {exit_name} is left `{answer}` and the reason never names"
                    f" the {exit_name} exit — say what happens there"
                )
        # WHICH scrub, not "one of them". `any(w in why …)` was membership rather
        # than correspondence: a review re-pointed five wiper rows at
        # `core1::scrub` and the row stayed green while the message said "say
        # WHICH one reaches this secret". The named scrub is held to the derived
        # list, so deleting it from the reboot path reddens the rows by name.
        named = row.get("wiper")
        if row.get("reboot") == "wiper":
            if named not in (wipers or []):
                problems.append(
                    f"{rel}: reboot rests on `{named}`, which is not one of the scrubs"
                    f" the reboot path calls ({wipers})"
                )
            elif named not in why:
                problems.append(
                    f"{rel}: reboot rests on `{named}` and the reason never names it"
                )
        elif named is not None:
            problems.append(
                f"{rel}: names a reboot scrub and its reboot answer is"
                f" `{row.get('reboot')}` — only a `wiper` row rests on one"
            )
    return owned


def register_quantities(derived, owned, wipers, outside):
    """What a residual's prose is allowed to state a count of."""
    return {
        len(derived),
        len(owned),
        sum(f["sites"] for f in derived.values()),
        sum(f["skippable"] for f in derived.values()),
        sum(1 for f in derived.values() if f["skippable"]),
        sum(1 for r in owned.values() if r.get("reboot") == "platform"),
        sum(1 for r in owned.values() if r.get("reboot") == "wiper"),
        len(wipers or []),
        outside,
    }


def check_residuals(
    register, owned, panic_silent, problems, quantities=frozenset(), registered=None
):
    """Residuals: reasoned, triggered, pointed at, and covering the panic exit."""
    registered = {} if registered is None else registered
    residuals = {}
    for index, entry in enumerate(register.get("residual", [])):
        if stray := sorted(set(entry) - set(RESIDUAL_FIELDS)):
            problems.append(
                f"{REGISTER}: residual #{index + 1} carries {stray}, which nothing reads"
            )
        rid = entry.get("id")
        if not rid:
            problems.append(f"{REGISTER}: residual #{index + 1} has no 'id'")
            continue
        if rid in residuals:
            problems.append(f"{rid}: declared twice in {REGISTER}")
            continue
        residuals[rid] = entry
        if not entry.get("why", "").strip():
            problems.append(f"{rid}: a residual with no reason is not one — 'why' is empty")
        if not entry.get("revalidate", "").strip():
            problems.append(
                f"{rid}: a residual with no revalidation trigger cannot go stale — say"
                " what change would make this reasoning wrong"
            )
        if not entry.get("what", "").strip():
            problems.append(f"{rid}: a residual that does not say what is left resident is not one")
        prose = " ".join(entry.get(f, "") for f in ("what", "why", "revalidate"))
        check_ratios(rid, prose, quantities, problems)
        for plat in sorted(set(PLAT.findall(prose))):
            if plat not in registered:
                problems.append(
                    f"{rid}: rests on `{plat}`, which {ASSUMPTIONS} does not register"
                    " — a residual handed to a board question nobody owns is a blank"
                )
        bad = sorted(set(entry.get("paths", [])) - set(EXITS) - {"panic"})
        if bad:
            problems.append(f"{rid}: names exits {bad}, which are not exits")
        if not entry.get("paths"):
            problems.append(f"{rid}: names no exit, so nothing it says is about a lifetime")
        if entry.get("applies") not in APPLIES:
            problems.append(
                f"{rid}: `applies` is `{entry.get('applies')}` and must be one of"
                f" {list(APPLIES)} — a residual nothing says the scope of is not held"
            )

    cited = {rid for row in owned.values() for rid in row.get("residual", [])}
    for rid in sorted(cited - set(residuals)):
        problems.append(f"{REGISTER}: a row cites residual {rid}, which is not declared")
    # A `register` residual is INHERITED, never cited: it is a fact about every
    # row at once, so citing one is not an argument about this row. Without the
    # rule, `RES-COMPILER-ELIDES` (paths success/error/cancel) discharged a
    # `not-wiped` on the device master seed's error exit at exit 0 — measured.
    for rid in sorted(cited):
        if residuals.get(rid, {}).get("applies") == "register":
            problems.append(
                f"{REGISTER}: a row cites {rid}, which applies to the whole register"
                " — every row inherits it, so citing it discharges nothing"
            )
    # `paths` against the exits some row actually leaves open, which is what the
    # docstring promised and nothing implemented: a residual could be pointed at
    # by a row whose every exit is answered, and one naming an exit no row leaves
    # open stood green. Both were measured.
    open_exits = {
        exit_name
        for row in owned.values()
        for exit_name in EXITS
        if row.get(exit_name) in NEEDS_RESIDUAL
    }
    for rid, entry in sorted(residuals.items()):
        if entry.get("applies") == "register":
            continue
        paths = set(entry.get("paths", []))
        if rid not in cited:
            problems.append(
                f"{rid}: no row rests on it — a residual nothing points at is a claim"
                " about a lifetime this register no longer has"
            )
        elif not paths & open_exits:
            problems.append(
                f"{rid}: names {sorted(paths)} and no row leaves any of those open"
                " — the residual outlived the answer it was written for"
            )
    for rel, row in sorted(owned.items()):
        left = [e for e in EXITS if row.get(e) in NEEDS_RESIDUAL]
        if not left:
            continue
        if not row.get("residual"):
            problems.append(
                f"{rel}: {', '.join(left)} left unwiped and the row names no residual —"
                " an unwiped secret is a finding or a stated risk, never a blank"
            )
            continue
        covered = {
            p
            for rid in row["residual"]
            for p in residuals.get(rid, {}).get("paths", [])
        }
        if missing := [e for e in left if e not in covered]:
            problems.append(
                f"{rel}: leaves {', '.join(missing)} unwiped and cites"
                f" {row['residual']}, none of which is about that exit"
            )

    panic_residuals = [
        rid
        for rid, entry in residuals.items()
        if "panic" in entry.get("paths", []) and entry.get("applies") == "register"
    ]
    if panic_silent and len(panic_residuals) != 1:
        problems.append(
            f"the panic exit wipes nothing and {len(panic_residuals)} residual(s) name"
            " it — it owes exactly one, so the silence the roadmap found here cannot"
            " come back as a second silence"
        )
    if not panic_silent and panic_residuals:
        problems.append(
            f"{panic_residuals} still records the panic exit as unwiped, and the"
            " firmware now wipes on it — re-judge every row rather than keep the residual"
        )
    return residuals


def audit(root):
    problems = []
    register = tomllib.loads((root / REGISTER).read_text(encoding="utf-8"))
    derived = derive(root)
    if stray := sorted(set(register) - set(TABLES)):
        problems.append(
            f"{REGISTER} carries {stray}, which nothing reads — a key added here is"
            " held by no rule and shown to no reader"
        )
    if len(derived) < FLOOR_ROWS:
        problems.append(
            f"{len(derived)} secret-bearing source(s) derived, under the floor of"
            f" {FLOOR_ROWS} — the derivation stopped reading the tree, so every rule"
            " below passed over (almost) an empty roster"
        )
        return problems, ""
    sites = sum(found["sites"] for found in derived.values())
    types = sorted(b for found in derived.values() for b in found["bearers"])
    if sites < FLOOR_SITES:
        problems.append(f"{sites} wipe(s) derived, under the floor of {FLOOR_SITES}")
    if len(types) < FLOOR_BEARERS:
        problems.append(
            f"{len(types)} self-wiping type(s) derived, under the floor of {FLOOR_BEARERS}"
        )

    wipers = reboot_wipers(root)
    if wipers is None:
        problems.append(
            f"{REBOOT_FILE} defines no `reboot` — the reboot exit's wipes are derived"
            " from its body, so every row resting on one rests on nothing"
        )
    elif wipers != register.get("reboot_wipers", []):
        problems.append(
            f"the reboot path calls {wipers} and {REGISTER} records"
            f" {register.get('reboot_wipers', [])} — a wipe left the reboot path"
        )

    for rel, found in unscoped(root):
        problems.append(
            f"{rel} carries key-grade material ({found} wipe(s)) and is in neither"
            f" {list(SCOPE)} nor {list(OUT_OF_SCOPE)} — a secret in a directory the"
            " scope never named is answered for by nothing"
        )

    outside = sum(found["sites"] for found in derive(root, OUT_OF_SCOPE).values())
    if outside != register.get("out_of_scope_sites"):
        problems.append(
            f"{list(OUT_OF_SCOPE)} carries {outside} wipe(s) and {REGISTER} states"
            f" {register.get('out_of_scope_sites')} — the exclusion is stated so it"
            " cannot be silent, which means the number has to move with the tree"
        )

    clause = register.get("clause", "")
    ident = clause.rsplit("#", 1)[-1] if "#" in clause else ""
    declared = clauses(root)
    if ident not in declared:
        problems.append(
            f"{REGISTER} sources its rows to `{clause}`, which {CLAUSES} does not"
            " declare — the register is then anchored to a threat nobody registered"
        )
    elif declared[ident].get("kind") != "defence":
        problems.append(
            f"{REGISTER} sources its rows to `{ident}`, a"
            f" `{declared[ident].get('kind')}` clause — a defence is the only kind a"
            " wipe can serve"
        )
    elif not declared[ident].get("rests_on"):
        problems.append(
            f"{ident} carries no `rests_on` pin, and every sentence this register"
            " answers is BELOW its locked first line — unpinned, the page can be"
            " rewritten under 56 rows with the threat gate green"
        )

    panic_open, panic_why = panic_wipes(root)
    owned = check_rows(register, derived, wipers, problems)
    registered = assumptions(root)
    residuals = check_residuals(
        register,
        owned,
        not panic_open,
        problems,
        register_quantities(derived, owned, wipers, outside),
        registered,
    )
    if panic_open:
        problems.append(
            f"the panic exit is no longer a silence: {panic_why} — every row's success,"
            " error and cancel answers were judged against a halt that runs nothing,"
            " and each needs re-reading"
        )

    skippable = sum(found["skippable"] for found in derived.values())
    #: The board questions the reboot answers hand their reasoning to, printed
    #: with their live status: an `accepted` reading `pending` is what the reader
    #: is owed, and the status is read out of the platform registry each run.
    rests = sorted(
        {
            plat
            for entry in residuals.values()
            for plat in PLAT.findall(
                " ".join(entry.get(f, "") for f in ("what", "why", "revalidate"))
            )
        }
    )
    summary = (
        f"secrets-gate: ok — {len(derived)} secret-bearing source(s), {sites} explicit"
        f" wipe(s) ({skippable} below an early exit), {len(types)} self-wiping type(s),"
        f" {len(wipers or [])} reboot scrub(s), {outside} wipe(s) out of scope;"
        f" panic wipes nothing on all {len(owned)} row(s)"
        + (
            "; rests on " + ", ".join(f"{p} [{registered.get(p)}]" for p in rests)
            if rests
            else ""
        )
    )
    return problems, summary


def run(root):
    try:
        problems, summary = audit(root)
    except (KeyError, OSError, tomllib.TOMLDecodeError) as error:
        problems, summary = [f"{REGISTER} cannot be read as a secret register: {error}"], ""
    if problems:
        print("secrets-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nEvery source that holds key-grade material owes an answer for the\n"
            "exits a request can take — success, error, cancel, panic, reboot — and\n"
            "every exit it is not wiped on owes a reason and a trigger that would\n"
            f"make that reason stale. Decide it in {REGISTER}; a count typed there\n"
            "is not a measurement, and a blank is not a residual.",
            file=sys.stderr,
        )
        return 1
    print(summary)
    return 0


def main():
    if sys.argv[1:]:
        print("usage: secrets_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
