# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `partition_routing_gate.py` was verified against, kept.

The guard exists because a routing table is spelled by hand in four places and
nothing links any of them to the constants they copy. So the table below breaks
that defect shape in a fixture checkout, one copy at a time, and asserts the
MESSAGE rather than a count — a red for the wrong reason proves as little as a
green, and this tree has measured 2 of 24 co-refutation kills firing on the
inverse defect.

Every case goes through `Tree.edit`, which asserts its anchor resolved exactly
once. A `str.replace` that matches nothing leaves the fixture unpatched, and the
case then proves that a clean tree is clean — which is the first case's job.

Both directions, because a guard that cannot go green is deleted as fast as one
that cannot go red: the clean fixture passes, this checkout passes, `check.sh` is
asserted to run the row, and the controls edit the fixture in the largest ways
that must NOT move the answer: twelve lines above every copy, an `#[inline]`
between the doc comment and the function, a `pub(crate)` home, an underscored
literal, a reduced index written inline, and — in the fuzz mirror, whose comment
is read as code and blanked — an old literal left in the drift story above it.
"""

import pathlib
import subprocess

import pytest

import gate_lines
import partition_routing_gate as gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The table and the prose that names its constants' homes.
STORE = """\
/// Route the hot per-operation counters to the dedicated counter partition so their
/// churn never reclaims a credential/key page in the main partition. Values are
/// `EF_COUNTER` (FIDO 0xC000), `EF_CRED_CTR` (FIDO per-credential signature counters,
/// 0xC001 — rewritten on every getAssertion), `EF_SIG_COUNT` (OpenPGP 0x0093) and the
/// vendor test counter `COUNTER_FID` (0xCC01).
pub fn is_counter_fid(fid: u16) -> bool {
    matches!(fid, 0xC000 | 0xC001 | 0x0093 | 0xCC01)
}
"""

#: The host copy: one loop per side of the split.
STORE_TESTS = """\
#[test]
fn only_the_four_hot_counters_leave_the_main_partition() {
    // The `power_cut` target's mirror was missing 0xC001.
    for fid in [0xC000, 0xC001, 0x0093, 0xCC01] {
        assert!(is_counter_fid(fid), "{fid:#06x} must be a counter");
    }
    for fid in [0xBFFF, 0xC002, 0x0092, 0x0094, 0xCC00, 0xCC02, CRED] {
        assert!(!is_counter_fid(fid), "{fid:#06x} must stay in main");
    }
}
"""

#: The homes, one per applet crate.
FIDO = """\
pub const EF_DEVICE_PIN: u16 = 0xCE20;
pub const EF_COUNTER: u16 = 0xC000; // global signature counter (U2F + migration seed)
/// Per-credential signature counters, a packed `u32`-LE array.
pub const EF_CRED_CTR: u16 = 0xC001;
pub const EF_CRED: u16 = 0xCF00; // resident credentials, 0xCF00..0xCFFF
"""

OPENPGP = """\
pub const EF_SEC_TPL: u16 = 0x007a; // C — security support template
pub const EF_SIG_COUNT: u16 = 0x0093; // S — signature counter (3 bytes)
"""

VENDOR = """\
/// Dynamic file holding the counter; `Fs::scan` rediscovers it after a reboot.
pub const COUNTER_FID: u16 = 0xCC01;
"""

#: The fuzz mirror, with the drift its own comment records written above it —
#: which is what makes the comment-literal control below worth having.
POWER_CUT = """\
// Five main-partition FIDs plus every counter-routed one
// (`rsk_store::is_counter_fid`) — both partitions get torn. The mirror this
// replaced listed only three of the four; `EF_CRED_CTR` (0xC001), rewritten on
// every getAssertion, was the one it missed.
const FIDS: [u16; 9] = [
    0xB000, 0xB001, 0xB002, 0xB003, 0xB004, 0xC000, 0xC001, 0x0093, 0xCC01,
];

fn step(b: u8) -> u16 {
    let index = (b >> 3) as usize % FIDS.len();
    FIDS[index]
}
"""


class Tree:
    """A checkout shaped like this one: the four copies and the four homes."""

    def __init__(self, root):
        self.root = root
        self.write("crates/rsk-store/src/lib.rs", STORE)
        self.write("crates/rsk-store/src/tests.rs", STORE_TESTS)
        self.write("crates/rsk-fido/src/consts.rs", FIDO)
        self.write("crates/rsk-openpgp/src/consts.rs", OPENPGP)
        self.write("crates/rsk-vendor/src/lib.rs", VENDOR)
        self.write("fuzz/fuzz_targets/power_cut.rs", POWER_CUT)
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
def tree(tmp_path):
    return Tree(tmp_path)


def red(tree, capsys):
    """Run the guard, require it red, and hand back what it said."""
    assert tree.run() == 1
    return capsys.readouterr().err


def summary(tree, capsys):
    """Run the guard green and hand back the one line it prints."""
    assert tree.run() == 0
    return capsys.readouterr().out.strip()


# --- both directions, and the wiring ------------------------------------------


def test_the_clean_fixture_passes(tree):
    assert tree.run() == 0


def test_this_checkout_passes():
    """The guard has to be green on the tree it ships in, or it is not a row."""
    assert gate.run(ROOT) == 0


def test_check_sh_runs_the_row():
    """A guard nothing invokes can have its whole table deleted, suite green."""
    text = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(text, "scripts/partition_routing_gate.py")


def test_a_control_mutant_stays_green(tree, capsys):
    """The control: the largest edit that must NOT move the derived set.

    Twelve lines above every copy — the shape that shifts every line number in
    every file. The summary is compared against the clean run rather than
    against a literal, so the case cannot pass by asserting something absent.
    """
    before = summary(tree, capsys)
    for rel, anchor in (
        ("crates/rsk-store/src/lib.rs", "/// Route the hot per-operation"),
        ("crates/rsk-fido/src/consts.rs", "pub const EF_DEVICE_PIN"),
        ("fuzz/fuzz_targets/power_cut.rs", "const FIDS"),
    ):
        tree.edit(rel, anchor, "//\n" * 12 + anchor)
    assert summary(tree, capsys) == before
    assert "EF_CRED_CTR 0xC001" in before, before


def test_a_stale_literal_in_a_comment_stays_green(tree, capsys):
    """The fuzz mirror's comment is read as CODE and blanked. Read raw it would
    count `0xC001` as a member, and a member deleted from the array below it
    would still read as listed. The doc comment over `is_counter_fid` is the one
    comment read raw, and it has its own control below."""
    before = summary(tree, capsys)
    tree.edit(
        "fuzz/fuzz_targets/power_cut.rs",
        "`EF_CRED_CTR` (0xC001), rewritten on",
        "`EF_CRED_CTR` (0xBEEF), rewritten on",
    )
    assert summary(tree, capsys) == before


# --- a literal changed in each of the four copies ------------------------------


def test_a_literal_changed_in_the_doc_comment_is_rejected(tree, capsys):
    """Copy 1. The prose that sends the next reader to the constants' homes, and
    the copy the derivation reads its NAMES out of — so its numbers have to be
    the numbers those names resolve to."""
    tree.edit("crates/rsk-store/src/lib.rs", "(OpenPGP 0x0093)", "(OpenPGP 0x0094)")
    said = red(tree, capsys)
    assert "comment over `is_counter_fid` does not list ['0x0093']" in said, said


def test_a_literal_changed_in_the_matches_arm_is_rejected(tree, capsys):
    """Copy 2, and the routing itself: this arm is what `read` and `write`
    branch on, so a wrong number here IS the misroute."""
    tree.edit("crates/rsk-store/src/lib.rs", "0xC000 | 0xC001", "0xC000 | 0xC005")
    said = red(tree, capsys)
    assert "`matches!` does not list ['0xC001']" in said, said
    assert "EF_CRED_CTR" in said, said
    assert "`matches!` lists ['0xC005']" in said, said


def test_a_literal_changed_in_the_host_test_is_rejected(tree, capsys):
    """Copy 3. It is what holds the table against a wrong edit today — and it
    would move WITH one, which is the whole reason this row exists."""
    tree.edit("crates/rsk-store/src/tests.rs", "[0xC000, 0xC001, 0x0093, 0xCC01]",
              "[0xC000, 0xC001, 0x0093, 0xCC02]")
    said = red(tree, capsys)
    assert "counter loop does not list ['0xCC01']" in said, said
    assert "COUNTER_FID" in said, said


def test_a_literal_changed_in_the_fuzz_mirror_is_rejected(tree, capsys):
    """Copy 4, the one an earlier draft of the registry row missed."""
    tree.edit("fuzz/fuzz_targets/power_cut.rs", "0xC000, 0xC001, 0x0093, 0xCC01",
              "0xC000, 0xC001, 0x0093, 0xCC09")
    said = red(tree, capsys)
    assert "`FIDS` does not list ['0xCC01']" in said, said
    assert "the target then tears no record of that partition" in said, said


# --- the two directions of the roster ------------------------------------------


def test_a_copy_dropping_a_member_is_rejected(tree, capsys):
    """The historical shape: the mirror listed three of the four. Dropping a
    member is not a wrong number anywhere — every literal still resolves — so
    only the derived-side comparison can see it."""
    tree.edit("fuzz/fuzz_targets/power_cut.rs", "0xC000, 0xC001, 0x0093, 0xCC01,",
              "0xC000, 0x0093, 0xCC01, 0xB005,")
    said = red(tree, capsys)
    assert "`FIDS` does not list ['0xC001']" in said, said
    assert "EF_CRED_CTR" in said, said


def test_a_constant_named_over_the_table_and_listed_nowhere_is_rejected(tree, capsys):
    """The other direction, and the one no copy can raise on its own: a fifth
    counter FID is declared at its home AND named over the table, and the three
    code copies go on routing four. Named over the table is the whole reach — the
    roster is that doc comment, so a constant nobody names there derives
    nothing."""
    tree.edit("crates/rsk-fido/src/consts.rs", "pub const EF_CRED: u16 = 0xCF00;",
              "pub const EF_LARGE_CTR: u16 = 0xC003;\npub const EF_CRED: u16 = 0xCF00;")
    tree.edit("crates/rsk-store/src/lib.rs", "vendor test counter `COUNTER_FID` (0xCC01).",
              "vendor test counter `COUNTER_FID` (0xCC01) and `EF_LARGE_CTR` (0xC003).")
    said = red(tree, capsys)
    assert "`matches!` does not list ['0xC003']" in said, said
    assert "counter loop does not list ['0xC003']" in said, said
    assert "`FIDS` does not list ['0xC003']" in said, said


def test_a_renamed_constant_is_rejected(tree, capsys):
    """A rename moves no value, so every copy still holds four numbers that are
    still right — and the prose pointing at the home is the only thing that
    breaks. Nothing but resolving the name notices."""
    tree.edit("crates/rsk-fido/src/consts.rs", "pub const EF_CRED_CTR: u16 = 0xC001;",
              "pub const EF_CRED_COUNTER: u16 = 0xC001;")
    said = red(tree, capsys)
    assert "names `EF_CRED_CTR`, which no crate outside" in said, said


def test_a_home_inside_the_table_crate_is_refused(tree, capsys):
    """The derivation has to read the APPLET crates. A constant moved next to
    the table would make the table its own source of truth, and the row would go
    on printing four members over a set nothing else owns."""
    tree.edit("crates/rsk-vendor/src/lib.rs", "pub const COUNTER_FID: u16 = 0xCC01;", "")
    tree.edit("crates/rsk-store/src/lib.rs", "/// Route the hot per-operation",
              "pub const COUNTER_FID: u16 = 0xCC01;\n/// Route the hot per-operation")
    said = red(tree, capsys)
    assert "names `COUNTER_FID`, which no crate outside crates/rsk-store/" in said, said


def test_two_homes_disagreeing_is_rejected(tree, capsys):
    """A name is a home, not a spelling: two crates defining it differently makes
    "the value" a choice, and taking either one silently is the wrong answer."""
    tree.edit("crates/rsk-openpgp/src/consts.rs", "pub const EF_SEC_TPL: u16 = 0x007a;",
              "pub const EF_COUNTER: u16 = 0x00C4;")
    said = red(tree, capsys)
    assert "`EF_COUNTER` resolves to more than one value" in said, said


# --- the clauses each copy owns ------------------------------------------------


def test_a_member_moved_into_the_must_stay_in_main_loop_is_rejected(tree, capsys):
    """The host test's other half. Its negative loop asserts a FID stays in the
    credential pages, so a member sliding into it turns the routing test into an
    assertion of the misroute."""
    tree.edit("crates/rsk-store/src/tests.rs", "[0xBFFF, 0xC002,", "[0xBFFF, 0x0093,")
    said = red(tree, capsys)
    assert "asserts ['0x0093'] must stay in main" in said, said


def test_a_masked_selector_is_rejected(tree, capsys):
    """The fuzz mirror's second drift, and the one a list check cannot see: with
    `& 7` over nine entries the ninth is listed and unreachable, so the sweep
    asserted a whole partition's routing absent on every input."""
    tree.edit("fuzz/fuzz_targets/power_cut.rs", "as usize % FIDS.len()", "as usize & 7")
    said = red(tree, capsys)
    assert "selects `FIDS[index]` from 1 binding(s)" in said, said
    assert "the mirror was `& 7` over nine entries once" in said, said


def test_an_unreadable_matches_arm_is_reported(tree, capsys):
    """An arm this cannot parse is a copy that has stopped being checked. It is
    reported rather than skipped, because skipping is how that happens quietly."""
    tree.edit("crates/rsk-store/src/lib.rs", "0x0093 | 0xCC01", "0x0093 | 0xCC00..=0xCC01")
    said = red(tree, capsys)
    assert "not a bare FID literal" in said, said


def test_a_doc_comment_naming_nothing_trips_the_floor(tree, capsys):
    """A derivation that resolves nothing compares an empty set to an empty set,
    and every rule above is then green over an unguarded table."""
    tree.edit("crates/rsk-store/src/lib.rs", "`EF_COUNTER` (FIDO 0xC000), `EF_CRED_CTR` ", "")
    tree.edit("crates/rsk-store/src/lib.rs", "`EF_SIG_COUNT` (OpenPGP 0x0093)", "the OpenPGP one")
    tree.edit("crates/rsk-store/src/lib.rs", "`COUNTER_FID` ", "")
    said = red(tree, capsys)
    assert "under the floor" in said, said


def test_a_table_with_no_doc_comment_is_rejected(tree, capsys):
    """Deleting the prose is the cheapest way past a guard that reads it, and it
    must not read as a table with nothing to check."""
    for line in STORE.splitlines(keepends=True):
        if line.startswith("///"):
            tree.edit("crates/rsk-store/src/lib.rs", line, "")
    said = red(tree, capsys)
    assert "no doc comment over `pub fn is_counter_fid`" in said, said


def test_a_mirror_nothing_indexes_is_rejected(tree, capsys):
    """`FIDS` listing every member buys nothing if no input selects from it."""
    tree.edit("fuzz/fuzz_targets/power_cut.rs", "    FIDS[index]\n", "    0xB000\n")
    said = red(tree, capsys)
    assert "never indexes `FIDS`" in said, said


# --- the clauses an adversarial review found unheld, and its six ways past -----


def test_a_mask_after_the_modulo_is_rejected(tree, capsys):
    """The review's first finding, and the guard's own headline defect: with the
    reduction tested as a SUBSTRING, `& 7` came straight back by leaving the
    modulo in front of it. Measured rc 0 then; the rule anchors at the end now."""
    tree.edit("fuzz/fuzz_targets/power_cut.rs", "let index = (b >> 3) as usize % FIDS.len();",
              "let index = ((b >> 3) as usize % FIDS.len()) & 7;")
    said = red(tree, capsys)
    assert "from 1 binding(s), not all of which END in `% FIDS.len()`" in said, said


def test_dividing_the_reduced_index_is_rejected(tree, capsys):
    """The same family with no mask: half the array is unreachable and the
    modulo is still there to be found by a substring test."""
    tree.edit("fuzz/fuzz_targets/power_cut.rs", "as usize % FIDS.len();", "as usize % FIDS.len() / 2;")
    assert "END in `% FIDS.len()`" in red(tree, capsys)


def test_a_second_binding_of_the_index_is_rejected(tree, capsys):
    """One reduced `let` used to vouch for every `FIDS[index]` in the file, so a
    masked second site passed at rc 0. Every binding of the name is required."""
    tree.edit("fuzz/fuzz_targets/power_cut.rs", "    FIDS[index]\n",
              "    let index = (b & 7) as usize;\n    FIDS[index]\n")
    said = red(tree, capsys)
    assert "from 2 binding(s)" in said, said


def test_an_index_written_inline_stays_green(tree, capsys):
    """The control the clause above needs: a reduced index needs no `let`, and
    reading that as "never indexes `FIDS`" was a false red the review measured."""
    before = summary(tree, capsys)
    tree.edit("fuzz/fuzz_targets/power_cut.rs",
              "    let index = (b >> 3) as usize % FIDS.len();\n    FIDS[index]\n",
              "    FIDS[(b >> 3) as usize % FIDS.len()]\n")
    assert summary(tree, capsys) == before


def test_a_decoy_matches_above_the_table_does_not_take_its_place(tree, capsys):
    """The arms were read by the FIRST `matches!` in the file, so a sibling
    predicate carrying the right ones let the real table route `0xCC02` at rc 0.
    They come out of `is_counter_fid`'s own body now."""
    tree.edit("crates/rsk-store/src/lib.rs", "0x0093 | 0xCC01", "0x0093 | 0xCC02")
    tree.edit("crates/rsk-store/src/lib.rs", "/// Route the hot per-operation",
              "pub fn is_warm_fid(fid: u16) -> bool {\n"
              "    matches!(fid, 0xC000 | 0xC001 | 0x0093 | 0xCC01)\n"
              "}\n\n/// Route the hot per-operation")
    said = red(tree, capsys)
    assert "`matches!` does not list ['0xCC01']" in said, said


def test_a_second_fids_array_is_rejected(tree, capsys):
    """The mirror was read by the first `const FIDS` too, so a decoy above it hid
    a member dropped from the real one."""
    tree.edit("fuzz/fuzz_targets/power_cut.rs", "const FIDS: [u16; 9] = [",
              "#[cfg(test)]\nconst FIDS: [u16; 4] = [0xC000, 0xC001, 0x0093, 0xCC01];\n"
              "const FIDS: [u16; 9] = [")
    said = red(tree, capsys)
    assert "declares 2 `const FIDS: [u16; N]`, not one" in said, said


def test_a_table_written_as_a_match_is_reported(tree, capsys):
    """A clause the first table left unheld: co-refutation silenced it and
    NOTHING failed, so it could have been deleted with the suite green."""
    tree.edit("crates/rsk-store/src/lib.rs", "    matches!(fid, 0xC000 | 0xC001 | 0x0093 | 0xCC01)\n",
              "    match fid {\n"
              "        0xC000 | 0xC001 | 0x0093 | 0xCC01 => true,\n"
              "        _ => false,\n"
              "    }\n")
    said = red(tree, capsys)
    assert "no `matches!(fid, …)` inside `is_counter_fid`" in said, said


def test_a_renamed_fids_array_is_reported(tree, capsys):
    """The second unheld clause. Renaming the mirror leaves nothing to hold the
    set against, which must not read as a mirror that agrees."""
    tree.edit("fuzz/fuzz_targets/power_cut.rs", "const FIDS: [u16; 9]", "const TORN: [u16; 9]")
    said = red(tree, capsys)
    assert "declares 0 `const FIDS: [u16; N]`, not one" in said, said


def test_a_deleted_host_loop_is_reported(tree, capsys):
    """The third. The counter loop deleted is the routing test quietly halved,
    and the clause that says so was itself untested."""
    tree.edit("crates/rsk-store/src/tests.rs",
              "    for fid in [0xC000, 0xC001, 0x0093, 0xCC01] {\n"
              "        assert!(is_counter_fid(fid), \"{fid:#06x} must be a counter\");\n"
              "    }\n", "")
    said = red(tree, capsys)
    assert "has 0 `for fid in [ … ]` loops asserting `is_counter_fid`" in said, said


def test_a_home_spelled_as_an_expression_says_so(tree, capsys):
    """`pub const EF_X: u16 = BASE;` is this tree's own spelling (`rsk-ui`), and
    calling that "no crate defines it" is a false red stating something untrue.
    It is still a red — the copies hold numbers — under its own message."""
    tree.edit("crates/rsk-openpgp/src/consts.rs", "pub const EF_SIG_COUNT: u16 = 0x0093;",
              "pub const SIG_BASE: u16 = 0x0093;\npub const EF_SIG_COUNT: u16 = SIG_BASE;")
    said = red(tree, capsys)
    assert "defines as an expression rather than a literal" in said, said


def test_an_attribute_between_the_doc_and_the_function_stays_green(tree, capsys):
    """A false red the review measured: `#[inline]` there read as "no doc comment
    over `pub fn is_counter_fid`", which is both wrong and the loudest message
    this guard has."""
    before = summary(tree, capsys)
    tree.edit("crates/rsk-store/src/lib.rs", "pub fn is_counter_fid",
              "#[inline]\npub fn is_counter_fid")
    assert summary(tree, capsys) == before


def test_a_pub_crate_home_stays_green(tree, capsys):
    """A home does not stop being one because the crate keeps it to itself."""
    before = summary(tree, capsys)
    tree.edit("crates/rsk-vendor/src/lib.rs", "pub const COUNTER_FID",
              "pub(crate) const COUNTER_FID")
    assert summary(tree, capsys) == before


def test_an_underscored_literal_stays_green(tree, capsys):
    """`0x00_93` is this tree's own spelling in `crates/rsk-rescue`. Read four
    digits deep it vanished from the set and the copy read as missing it."""
    before = summary(tree, capsys)
    tree.edit("crates/rsk-openpgp/src/consts.rs", "= 0x0093;", "= 0x00_93;")
    tree.edit("crates/rsk-store/src/lib.rs", "(OpenPGP 0x0093)", "(OpenPGP 0x00_93)")
    assert summary(tree, capsys) == before


def test_the_drift_story_in_the_doc_comment_stays_green(tree, capsys):
    """The doc comment is the one read raw, and it carries prose: the drift story
    quoting `0x0821` belongs directly above `is_counter_fid`. Held both ways, that
    sentence was a red claiming the applet crates had drifted."""
    before = summary(tree, capsys)
    tree.edit("crates/rsk-store/src/lib.rs", "/// Route the hot per-operation",
              "/// `EF_CRED_CTR` joined this table at 0x0821, after 0x081D had been\n"
              "/// writing it to main.\n/// Route the hot per-operation")
    assert summary(tree, capsys) == before
