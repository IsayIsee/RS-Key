# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `counter_writers_gate.py` was verified against, kept.

The guard exists because a proof's stated scope was smaller than its sentence:
`counter_kani.rs` named four writers of the OTP use counter while the tree had
eight. So the table below breaks that defect shape in a fixture checkout, one at
a time, and asserts the MESSAGE rather than a count — a red for the wrong reason
proves as little as a green, and this tree has measured 2 of 24 co-refutation
kills firing on the inverse defect.

Every case goes through `Tree.edit`, which asserts its anchor resolved exactly
once. A `str.replace` that matches nothing leaves the fixture unpatched, and the
case then proves that a clean tree is clean — which is the previous case's job.

Both directions, because a guard that cannot go green is deleted as fast as one
that cannot go red: the clean fixture passes, this checkout's own ledger passes,
`check.sh` is asserted to run the row, and [`test_a_control_mutant_stays_green`]
edits the fixture's *code* in the largest way that must not move the roster — so
the table is shown to measure the writer set rather than the spelling of the
file it lives in.
"""

import pathlib
import subprocess

import pytest

import counter_writers_gate as gate
import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A fixture crate shaped like `rsk-otp`: a persist helper that other persist
#: sites forward through (so `kind` has both values to derive), a writer that
#: steps the counter directly, one that reaches the step through a callee, and
#: two that do not step it at all.
LIB = """\
fn put_slot(&self, fs: &mut Fs, fid: u16, data: &[u8]) -> bool {
    seal::seal_put(dev, fs, rng, KeyFid::new(fid), data)
}

fn button_ticket(&mut self, fs: &mut Fs) -> Option<usize> {
    let t = ticket::build(&buf, self.session_counter[idx])?;
    let _ = self.put_slot(fs, fid, &rec);
    Some(0)
}

fn cmd_configure(&mut self, fs: &mut Fs) -> Sw {
    if !self.put_slot(fs, fid, &rec) {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

fn cmd_swap(&mut self, fs: &mut Fs) -> Sw {
    if !self.put_slot(fs, fid1, &b[..n]) {
        return Sw::MEMORY_FAILURE;
    }
    Sw::OK
}

pub fn power_up_bump(dev: &Device, fs: &mut Fs, rng: &mut dyn Rng) {
    if let Some(counter) = counter::boot_use_counter(stored) {
        let _ = seal::seal_put(dev, fs, rng, KeyFid::new(fid), &rec);
    }
}
"""

TICKET = """\
use crate::{SLOT_SIZE, counter::next_use_counter};

pub fn build(slot: &[u8; SLOT_SIZE], session: u8) -> Option<Typed> {
    let (counter, new_session, bumped) = next_use_counter(counter, session);
    Some(Typed { new_session })
}
"""

COUNTER = """\
//! The rule, in one place. `assurance/otp_counter_writers.toml` is the roster.

pub(crate) fn next_use_counter(counter: u16, session: u8) -> (u16, u8, bool) {
    (counter, session, false)
}

pub(crate) fn boot_use_counter(stored: u16) -> Option<u16> {
    Some(stored)
}
"""

PROOF = """\
//! Scope is derived into `assurance/otp_counter_writers.toml`, not counted here.

#[kani::proof]
fn use_counter_climbs_and_stops_at_the_ceiling() {
    let (pressed, _, persist) = next_use_counter(stored, session);
    assert_eq!(persist, pressed != stored);
    assert!(boot_use_counter(stored).is_some());
}
"""

LEDGER = """\
[scope]
writers = 4
forwarders = 1
stepped = 2

[[site]]
file = "crates/rsk-otp/src/lib.rs"
ordinal = 0
verb = "seal_put"
fn = "put_slot"
kind = "forwarder"
proved = "no"
why = "the shared helper; it decides no byte."

[[site]]
file = "crates/rsk-otp/src/lib.rs"
ordinal = 0
verb = "put_slot"
fn = "button_ticket"
kind = "writer"
proved = "partial"
via = "build"
why = "the per-press writer, stepped through ticket::build."

[[site]]
file = "crates/rsk-otp/src/lib.rs"
ordinal = 0
verb = "put_slot"
fn = "cmd_configure"
kind = "writer"
proved = "no"
why = "a fresh zeroed record; the base case."

[[site]]
file = "crates/rsk-otp/src/lib.rs"
ordinal = 0
verb = "put_slot"
fn = "cmd_swap"
kind = "writer"
proved = "no"
why = "relocates the other slot's counter verbatim."

[[site]]
file = "crates/rsk-otp/src/lib.rs"
ordinal = 0
verb = "seal_put"
fn = "power_up_bump"
kind = "writer"
proved = "yes"
why = "the boot bump, decided entirely by counter.rs."
"""


class Tree:
    """A checkout shaped like this one: the OTP crate and nothing else."""

    def __init__(self, root):
        self.root = root
        self.write("crates/rsk-otp/src/lib.rs", LIB)
        self.write("crates/rsk-otp/src/ticket.rs", TICKET)
        self.write("crates/rsk-otp/src/counter.rs", COUNTER)
        self.write("crates/rsk-otp/src/counter_kani.rs", PROOF)
        self.write("assurance/otp_counter_writers.toml", LEDGER)
        # `sources` asks git what the tree is, so the fixture must be a checkout
        # — and one that ignores build output, like the real one.
        self.write(".gitignore", "target/\n")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it.

        The assertion is the point: an anchor that matches nothing leaves the
        fixture unpatched, and the case then measures a clean tree.
        """
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def run(self):
        return gate.run(self.root)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    # The shipped floor is about the real checkout's nine sites. Scaled to the
    # fixture's five so the emptying case below still has one to trip.
    monkeypatch.setattr(gate, "FLOOR_SITES", 3)
    return Tree(tmp_path)


def red(tree, capsys):
    """Run the guard, require it red, and hand back what it said."""
    assert tree.run() == 1
    return capsys.readouterr().err


# --- both directions, and the wiring ------------------------------------------


def test_the_clean_fixture_passes(tree):
    assert tree.run() == 0


def test_this_checkout_passes():
    """The guard has to be green on the tree it ships in, or it is not a row."""
    assert gate.run(ROOT) == 0


def test_check_sh_runs_the_row():
    """A guard nothing invokes can have its whole table deleted, suite green."""
    text = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(text, "scripts/counter_writers_gate.py")


def summary(tree, capsys):
    """Run the guard green and hand back the one line it prints."""
    assert tree.run() == 0
    return capsys.readouterr().out.strip()


def test_a_control_mutant_stays_green(tree, capsys):
    """The control: the largest edit to the code that must NOT move the roster.

    Twelve lines inserted above every site — the shape that shifts every line
    number in the file. The assertion is that the summary is UNCHANGED, compared
    against the clean run rather than against a literal: the previous version
    asserted `"8 writers" not in out` over a fixture that prints four, so it
    could not fail. That is the same vacuity this row exists to catch, in the
    row's own table.
    """
    before = summary(tree, capsys)
    tree.edit("crates/rsk-otp/src/lib.rs", "fn put_slot(", "//\n" * 12 + "fn put_slot(")
    assert summary(tree, capsys) == before
    assert "4 writers" in before, before


def test_renaming_a_local_at_a_call_site_stays_green(tree, capsys):
    """The control a spelling-measuring gate fails. Keyed on the call TEXT, this
    rename — same file, same function, same count — reported BOTH "does not list
    it" and "which persists nothing" at EXIT=1. Any `rustfmt` reflow was a false
    red the same way, which is why the key is `(file, fn, ordinal)` now."""
    before = summary(tree, capsys)
    tree.edit(
        "crates/rsk-otp/src/lib.rs",
        "    if !self.put_slot(fs, fid, &rec) {",
        "    if !self.put_slot(fs, fid, &record) {",
    )
    assert summary(tree, capsys) == before


def test_a_bare_call_is_a_writer(tree, capsys):
    """M1. `PERSIST` used to demand a `.`/`::` receiver, so a bare
    `seal_put(dev, …)` — this tree's own style in `crates/rsk-piv/src/seal.rs` —
    left the row at EXIT=0 still reporting the old count. The green was the
    spelling, not the behaviour."""
    tree.write(
        "crates/rsk-otp/src/evil.rs",
        "use crate::seal::seal_put;\n\n"
        "pub fn evil(dev: &Device, fs: &mut Fs) {\n"
        "    let _ = seal_put(dev, fs, rng, KeyFid::new(fid), &rec);\n"
        "}\n",
    )
    said = red(tree, capsys)
    assert "does not list it" in said, said
    assert "evil" in said, said


def test_an_aliased_call_is_a_writer(tree, capsys):
    """The other half of M1: `use … as` renames the verb, and a roster that knows
    only the two spellings stops seeing the call."""
    tree.write(
        "crates/rsk-otp/src/evil.rs",
        "use crate::seal::seal_put as sp;\n\n"
        "pub fn evil(dev: &Device, fs: &mut Fs) {\n"
        "    let _ = sp(dev, fs, rng, KeyFid::new(fid), &rec);\n"
        "}\n",
    )
    assert "does not list it" in red(tree, capsys)


def test_a_grouped_import_reaches_the_seal(tree, capsys):
    """M3. `use rsk_otp::{Rng as _R, seal};` is this tree's own style
    (`fuzz/fuzz_targets/otp_apdu.rs`), and `\\brsk_otp::seal\\b` missed it — a
    writer in `firmware/` imported that way passed at EXIT=0."""
    tree.write(
        "firmware/src/otp_kbd.rs",
        "use rsk_otp::{Rng as _R, seal};\n\n"
        "fn kbd() { let _ = seal::seal_put(&dev, fs, rng, fid, &rec); }\n",
    )
    assert "reach `rsk_otp::seal` from outside" in red(tree, capsys)


# --- the roster, both directions ----------------------------------------------


def test_a_new_writer_with_no_entry_is_rejected(tree, capsys):
    """The finding itself: a ninth writer arrives and the roster does not move.

    This is what neither replaced sentence could do — `cmd_swap` and
    `migrate_seal` were writers for their whole lives with the prose green.
    """
    tree.edit(
        "crates/rsk-otp/src/lib.rs",
        "pub fn power_up_bump",
        "fn cmd_update(&mut self, fs: &mut Fs) -> Sw {\n"
        "    if !self.put_slot(fs, fid, &merged) {\n"
        "        return Sw::MEMORY_FAILURE;\n"
        "    }\n"
        "    Sw::OK\n"
        "}\n\n"
        "pub fn power_up_bump",
    )
    said = red(tree, capsys)
    assert "does not list it" in said, said
    assert "cmd_update" in said, said


def test_an_entry_for_a_writer_that_is_gone_is_rejected(tree, capsys):
    tree.edit(
        "crates/rsk-otp/src/lib.rs",
        "    if !self.put_slot(fs, fid1, &b[..n]) {\n",
        "    if !nothing() {\n",
    )
    assert "which persists nothing" in red(tree, capsys)


def test_a_forwarder_relabelled_as_a_writer_is_rejected(tree, capsys):
    """`kind` is read from the tree, so the count cannot be padded or trimmed by
    editing the ledger — which is the move a hand-kept roster invites."""
    tree.edit("assurance/otp_counter_writers.toml", 'kind = "forwarder"', 'kind = "writer"')
    said = red(tree, capsys)
    assert "derives as a forwarder and is listed as a writer" in said, said


# --- the proof's scope, held to the code --------------------------------------


def test_a_stepper_demoted_to_unproved_is_rejected(tree, capsys):
    """A proof quietly narrowed. `power_up_bump` calls `boot_use_counter`, so
    calling it unproved has to be red rather than a label nobody re-reads."""
    tree.edit(
        "assurance/otp_counter_writers.toml",
        'proved = "yes"\nwhy = "the boot bump',
        'proved = "no"\nwhy = "the boot bump',
    )
    assert "listed as unproved" in red(tree, capsys)


def test_a_site_claiming_a_proof_that_does_not_reach_it_is_rejected(tree, capsys):
    """The inverse direction, and the one the original defect took: a writer
    listed inside the proof's scope while nothing steps its bytes."""
    tree.edit(
        "assurance/otp_counter_writers.toml",
        'kind = "writer"\nproved = "no"\nwhy = "a fresh zeroed record',
        'kind = "writer"\nproved = "yes"\nwhy = "a fresh zeroed record',
    )
    said = red(tree, capsys)
    assert "counter_kani.rs does not reach it" in said, said


def test_an_invented_via_hop_is_rejected(tree, capsys):
    tree.edit("assurance/otp_counter_writers.toml", 'via = "build"', 'via = "imagine"')
    assert "does not call `imagine`" in red(tree, capsys)


def test_a_site_cannot_attach_itself_to_a_hop_it_never_calls(tree, capsys):
    """M5, and the inverse of the defect this row exists for. `covered` and
    `[scope] stepped` used to be computed from the ledger's own `via`, so the
    roster graded its own homework: `cmd_swap` claiming `via = "build"` bought
    `proved = "yes"` at EXIT=0 while calling neither the rule nor `build`. Both
    are read out of the call graph now."""
    tree.edit(
        "assurance/otp_counter_writers.toml",
        'kind = "writer"\nproved = "no"\nwhy = "relocates',
        'kind = "writer"\nproved = "yes"\nvia = "build"\nwhy = "relocates',
    )
    tree.edit("assurance/otp_counter_writers.toml", "stepped = 2", "stepped = 3")
    said = red(tree, capsys)
    assert "does not call `build`" in said, said
    assert "counter_kani.rs does not reach it" in said, said
    assert "[scope] stepped = 3 and the tree has 2" in said, said


def test_a_stepper_in_another_file_does_not_cover_this_one(tree, capsys):
    """M9. `steppers()` returned bare names, so an unrelated `cmd_swap` in
    `hid.rs` that steps the counter made `lib.rs`'s own `cmd_swap` read as
    covered — EXIT=0, "3 functions take their step". Keyed on `(file, fn)`."""
    tree.write(
        "crates/rsk-otp/src/hid.rs",
        "fn cmd_swap() { let _ = crate::counter::next_use_counter(0, 0); }\n",
    )
    tree.edit(
        "assurance/otp_counter_writers.toml",
        'kind = "writer"\nproved = "no"\nwhy = "relocates',
        'kind = "writer"\nproved = "yes"\nwhy = "relocates',
    )
    assert "counter_kani.rs does not reach it" in red(tree, capsys)
    assert ("crates/rsk-otp/src/lib.rs", "cmd_swap") not in gate.steppers(tree.root)


def test_a_via_hop_that_stops_stepping_is_rejected(tree, capsys):
    """The hop is a fact about `ticket::build`, not about the ledger: take the
    step out of the callee and the site it covers must stop reading as covered."""
    tree.edit("crates/rsk-otp/src/ticket.rs", "next_use_counter(counter, session)", "(0, 0, false)")
    assert "does not reach it" in red(tree, capsys)


def test_the_definition_of_the_rule_is_not_a_caller_of_it(tree, capsys):
    """`fn next_use_counter(` matches the call pattern too. Without the
    definition-line skip the two rules derive as their own callers, the stepper
    set is four instead of two, and `[scope] stepped` is wrong in the safe-looking
    direction — more coverage claimed than exists."""
    assert gate.steppers(tree.root) == {
        ("crates/rsk-otp/src/ticket.rs", "build"),
        ("crates/rsk-otp/src/lib.rs", "power_up_bump"),
    }


# --- the scope table, and the citations that replaced the sentence -------------


def test_a_scope_count_that_disagrees_with_the_tree_is_rejected(tree, capsys):
    tree.edit("assurance/otp_counter_writers.toml", "writers = 4", "writers = 3")
    said = red(tree, capsys)
    assert "[scope] writers = 3 and the tree has 4" in said, said


def test_a_proof_that_stops_citing_the_ledger_is_rejected(tree, capsys):
    """The repair itself: the harness's scope is a file the gate reads, so
    deleting the pointer puts it back to being a sentence."""
    tree.edit(
        "crates/rsk-otp/src/counter_kani.rs",
        "assurance/otp_counter_writers.toml",
        "four writers, and that is all of them",
    )
    assert "its scope is a sentence again" in red(tree, capsys)


def test_both_harnesses_deleted_is_rejected(tree, capsys):
    """The hole this rule closes, measured on the shipped guard first: deleting
    both `#[kani::proof]`s from the real `counter_kani.rs` was EXIT=0 here, the
    row still printing "2 functions take their step from counter.rs" over an
    empty proof. Every other clause reads production code, so none of them could
    fall. (`kani_gate.py` does go red on that one — by a crate-wide harness
    floor that names no property and no rule.)"""
    tree.edit(
        "crates/rsk-otp/src/counter_kani.rs",
        "#[kani::proof]\nfn use_counter_climbs_and_stops_at_the_ceiling() {",
        "fn nothing_at_all() {",
    )
    said = red(tree, capsys)
    assert "no `#[kani::proof]`" in said, said
    assert "'boot_use_counter', 'next_use_counter'" in said, said


def test_a_harness_that_stops_reaching_one_rule_is_rejected(tree, capsys):
    """The direction, and the reason the message names the rules rather than
    counting them: half a proof must report the half that went, not that
    something is wrong. `next_use_counter` is still reached and must NOT be
    named — a red that says both is a red for the wrong reason."""
    tree.edit(
        "crates/rsk-otp/src/counter_kani.rs",
        "    assert!(boot_use_counter(stored).is_some());\n",
        "",
    )
    said = red(tree, capsys)
    assert "['boot_use_counter']" in said, said
    assert "next_use_counter" not in said, said


def test_a_rule_named_only_in_the_scope_prose_is_rejected(tree, capsys):
    """The evasion a substring match admits. The real file's doc comment
    discusses both rules by name directly above the harness, so a rule "reached"
    by a comment would make this row green over a proof that calls neither."""
    tree.edit(
        "crates/rsk-otp/src/counter_kani.rs",
        "    let (pressed, _, persist) = next_use_counter(stored, session);\n"
        "    assert_eq!(persist, pressed != stored);\n"
        "    assert!(boot_use_counter(stored).is_some());\n",
        "    // next_use_counter(stored, session) and boot_use_counter(stored)\n",
    )
    said = red(tree, capsys)
    assert "'boot_use_counter', 'next_use_counter'" in said, said


def test_a_harness_with_the_proof_attribute_stripped_is_rejected(tree, capsys):
    """A `fn` Kani never runs is not a proof, and it is the quietest way to lose
    one: the body still reads as a proof to anyone opening the file."""
    tree.edit("crates/rsk-otp/src/counter_kani.rs", "#[kani::proof]\n", "")
    assert "no `#[kani::proof]`" in red(tree, capsys)


def test_a_renamed_harness_stays_green(tree, capsys):
    """CONTROL. This row measures what the proof REACHES, not what it is called
    — so a rename must not move it, and the summary is compared against the
    clean run rather than a literal. Said plainly because it is a live hole one
    row over: `assurance_gate.py` forces `BOUNDED` from a harness NAME, so
    renaming this one after a property would move that status with nothing here
    or there noticing. That is a finding about the status ladder, not a rule
    this roster can carry."""
    before = summary(tree, capsys)
    tree.edit(
        "crates/rsk-otp/src/counter_kani.rs",
        "fn use_counter_climbs_and_stops_at_the_ceiling()",
        "fn otp_counter_never_repeats_anything()",
    )
    assert summary(tree, capsys) == before


def test_a_writer_added_outside_the_crate_is_rejected(tree, capsys):
    """`rsk_otp::seal` is `pub`, so a ninth writer could be added where this
    roster does not look. The derivation cannot see it; the ban can."""
    tree.write("firmware/src/main.rs", "let _ = rsk_otp::seal::seal_put(&dev, fs, rng, fid, &rec);\n")
    assert "reach `rsk_otp::seal` from outside" in red(tree, capsys)


def test_a_cfg_gated_sibling_is_not_a_writer(tree, capsys):
    """The other direction of that rule, so it is a scope and not a blanket ban:
    cfg-gated code never reaches the image, so a persist call in a `_tests.rs`
    sibling writes no device's counter and must not join the roster."""
    tree.write(
        "crates/rsk-otp/src/lib_tests.rs",
        "fn t() { let _ = seal::seal_put(dev, fs, rng, fid, &whatever); }\n",
    )
    tree.write("tools/emu/src/device_tests.rs", "use rsk_otp::seal::seal_put;\n")
    assert tree.run() == 0
    capsys.readouterr()


def test_a_reason_that_is_blank_is_rejected(tree, capsys):
    tree.edit(
        "assurance/otp_counter_writers.toml",
        'why = "the shared helper; it decides no byte."',
        'why = "   "',
    )
    assert "with no reason is not a judgement" in red(tree, capsys)


def test_an_invented_vocabulary_is_rejected(tree, capsys):
    tree.edit("assurance/otp_counter_writers.toml", 'proved = "partial"', 'proved = "probably"')
    assert "is not one of" in red(tree, capsys)


def test_a_key_nothing_reads_is_rejected(tree, capsys):
    """Measured on the guard this is modelled on before the rule went in: an
    invented key was read by nothing, printed by nothing, and exited 0."""
    tree.edit(
        "assurance/otp_counter_writers.toml",
        'kind = "forwarder"',
        'kind = "forwarder"\nseverity = "low"',
    )
    assert "which nothing reads" in red(tree, capsys)


def test_an_emptied_derivation_is_rejected(tree, capsys):
    """A derivation that finds nothing satisfies every rule above — the failure
    mode a verdict column cannot show."""
    tree.write("crates/rsk-otp/src/lib.rs", "fn nothing() {}\n")
    assert "under the floor" in red(tree, capsys)


def test_a_ledger_that_cannot_be_read_is_rejected(tree, capsys):
    tree.write("assurance/otp_counter_writers.toml", "[scope\n")
    assert "cannot be read as a writer roster" in red(tree, capsys)
