# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `docs_constants.py` was carved out of a roster for lacking.

The guard's whole subject is a copy that goes on asserting a value after the code
moved — `MAX_DYNAMIC_FILES` as 256 while the code said 1280, `MAX_LARGE_BLOB_SIZE`
as 2048 in two *published* metadata statements. A guard against silent copies
that was itself held only by "the constants it happens to read today"
(`test_gate_scripts.UNROSTERED`, verbatim) is the same failure one layer up: the
scanner can stop matching a source and pass whatever it is shown.

Every case drives the row's own entry point — `python scripts/docs_constants.py`,
as `check.sh` spells it — over a fixture checkout, and reads the process exit
code, since that code is the whole of what the row reads. The guard is written
into the fixture rather than imported so a deletion arm is the source cut a
deletion actually is.

The fixture is large where the guard's floors are: `MIN_PAIRS` demands 44 pairs
out of `tests/` before the row will believe it read anything, so the fixture
generates them. That is the point of the floors, not an accident of them.
"""

import json
import pathlib
import subprocess
import sys

import pytest

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / "scripts/docs_constants.py"

DOC = "docs/fixture.md"
TESTS = "tests/00_fixture.py"
LIB = "crates/rsk-fixture/src/lib.rs"
OTHER = "crates/rsk-other/src/lib.rs"
META = "metadata/rs-key.metadata.json"
META2 = "metadata/rs-key.u2f.metadata.json"

#: The FIDO names the statements publish, with the value the fixture's code says.
#: All nine of `docs_constants.METADATA_CONSTANTS`, because a mapping entry with
#: no pair behind it is an entry nothing would notice losing.
METADATA = {
    "maxCredentialCountInList": ("MAX_CREDENTIAL_COUNT_IN_LIST", 16),
    "maxCredentialIdLength": ("MAX_CRED_ID_LENGTH", 128),
    "maxSerializedLargeBlobArray": ("MAX_LARGE_BLOB_SIZE", 2046),
    "minPINLength": ("MIN_PIN_LENGTH", 4),
    "maxCredBlobLength": ("MAX_CREDBLOB_LENGTH", 32),
    "maxRPIDsForSetMinPINLength": ("MAX_MIN_PIN_RPIDS", 8),
    "remainingDiscoverableCredentials": ("MAX_RESIDENT_CREDENTIALS", 100),
    "maxMsgSize": ("CTAP_MAX_MESSAGE", 1200),
    "maxPINLength": ("MAX_PIN_LENGTH", 63),
}

#: The four spellings the docs state a value in, one per shape the reader takes:
#: a parenthesised decimal with thousands separators, a parenthesised hex in
#: backticks, an `=`, and an `is`.
DOC_PAIRS = [
    ("MAX_FIXTURE_FILES", "(1,280)"),
    ("FIXTURE_FID", "(`0x1091`)"),
    ("MIN_FIXTURE_PIN", "= 4"),
    ("MAX_FIXTURE_BLOB", "is 2046"),
    ("DUAL_FIXTURE_LIMIT", "(9)"),
    ("MAX_PIN_LENGTH", "(63)"),
    ("MAX_CRED_ID_LENGTH", "(128)"),
]

#: How many generated pairs the `tests` floor needs before it will believe the
#: scanner read anything. One over, so a case can take one away without the
#: floor firing in place of the clause under test.
GENERATED = 45


class Tree:
    """A checkout shaped like this one: a crate of constants, a docs page, an
    on-device suite holding fixture copies, and two published statements."""

    def __init__(self, root):
        self.root = root
        consts = [
            "pub const MAX_FIXTURE_FILES: usize = 1280;",
            "pub const FIXTURE_FID: KeyFid = KeyFid::new(0x1091);",
            "pub const MIN_FIXTURE_PIN: u8 = 4;",
            # The shape the large-blob drift hid in: the docs name the alias and
            # the literal is a hop away, in another crate.
            "pub const MAX_FIXTURE_BLOB: usize = rsk_other::MAX_FIXTURE_VALUE;",
            "pub const DUAL_FIXTURE_LIMIT: u8 = 9;",
        ]
        consts += [f"pub const {name}: usize = {value};" for name, value in METADATA.values()]
        consts += [f"pub const FIXTURE_T{i:02}: usize = {i + 100};" for i in range(GENERATED)]
        self.write(LIB, "\n".join(consts) + "\n")
        self.write(
            OTHER,
            "pub const MAX_FIXTURE_VALUE: usize = 2046;\npub const DUAL_FIXTURE_LIMIT: u8 = 8;\n",
        )
        self.write("firmware/src/main.rs", "fn main() {}\n")
        self.write(DOC, self.page())
        self.write(TESTS, self.suite())
        self.write(META, self.statement(list(METADATA)))
        self.write(META2, self.statement(list(METADATA)[:4]))

    def page(self):
        lines = [f"- `{name}` {value} is the fixture's own." for name, value in DOC_PAIRS]
        # A name the tree does not define as a literal: the guard is deliberately
        # narrow, and prose it cannot check must not be prose it fails on.
        lines.append("- `NOT_A_CONSTANT_HERE` (77) is nothing of ours.")
        return "# Fixture\n\n" + "\n".join(lines) + "\n"

    def suite(self):
        body = [f"FIXTURE_T{i:02} = {i + 100}" for i in range(GENERATED)]
        body.append("MAX_FIXTURE_FILES = 1280")
        body.append("FIXTURE_FID = 0x1091")
        # Indented, so it is a local and not the fixture the assertions read. The
        # value is deliberately wrong: a scanner that reads it goes red here.
        body.append("def local_is_not_a_fixture():\n    MIN_FIXTURE_PIN = 999\n")
        return "\n".join(body) + "\n"

    def statement(self, keys):
        return json.dumps(
            {
                "description": "RS-Key fixture",
                **{key: METADATA[key][1] for key in keys},
                "attachmentHint": ["external"],
            },
            indent=2,
        )

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def run(self, *cuts):
        """The row, as `check.sh` runs it, with the guard optionally cut.

        Each cut is (anchor, replacement) applied to the guard's own source with
        the anchor asserted present, so a deletion arm whose anchor moved reads
        as a moved anchor rather than as a kill.
        """
        src = GUARD.read_text()
        for old, new in cuts:
            assert src.count(old) == 1, f"anchor moved: {old!r}"
            src = src.replace(old, new)
        self.write("scripts/docs_constants.py", src)
        return subprocess.run(
            [sys.executable, "scripts/docs_constants.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
        )


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


# --- both directions, and the wiring ------------------------------------------


def test_the_clean_fixture_is_green(tree):
    """A guard that cannot go green gets deleted as fast as one that cannot go red."""
    result = tree.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "docs-constants: ok" in result.stdout
    assert f"7 docs, {GENERATED + 2} tests, 13 metadata" in result.stdout


def test_this_checkout_is_green():
    """The control the fixture cannot be: the row over the tree it guards."""
    result = subprocess.run(
        [sys.executable, str(GUARD)], cwd=ROOT, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "docs-constants: ok" in result.stdout


def test_check_sh_runs_the_row():
    """A guard nothing invokes can be deleted with the whole suite still green."""
    check = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(check, "scripts/docs_constants.py")


# --- one arm per source, the way the drift actually happens --------------------


def test_a_docs_copy_the_code_moved_out_from_under_fails_the_row(tree):
    """`architecture.md` said 256 through the whole capacity era. The code moves
    here, not the copy — that is the motion, and the copy is what goes stale."""
    tree.edit(LIB, "MAX_FIXTURE_FILES: usize = 1280", "MAX_FIXTURE_FILES: usize = 2560")
    result = tree.run()
    assert result.returncode == 1
    assert "docs/fixture.md" in result.stderr
    assert "MAX_FIXTURE_FILES copied as 1,280, code says 2560" in result.stderr


def test_a_test_fixture_copy_that_stopped_matching_fails_the_row(tree):
    """`tests/25_large_blobs.py` held a 2048 the code had left; an on-device suite
    asserting the old value passes against a device that no longer means it."""
    tree.edit(TESTS, "MAX_FIXTURE_FILES = 1280", "MAX_FIXTURE_FILES = 999")
    result = tree.run()
    assert result.returncode == 1
    assert "tests/00_fixture.py" in result.stderr
    assert "MAX_FIXTURE_FILES copied as 999, code says 1280" in result.stderr


def test_a_published_metadata_value_that_drifted_fails_the_row(tree):
    """The source that joined after the drift reached relying parties rather than
    just CI: a statement is published, and a wrong number in one is shipped."""
    tree.edit(LIB, "MAX_LARGE_BLOB_SIZE: usize = 2046", "MAX_LARGE_BLOB_SIZE: usize = 2048")
    result = tree.run()
    assert result.returncode == 1
    assert "metadata/rs-key.metadata.json" in result.stderr
    assert "MAX_LARGE_BLOB_SIZE copied as 2046, code says 2048" in result.stderr


def test_a_hex_copy_is_compared_and_reported_in_hex(tree):
    """Every file id is declared through a newtype, and a fid stated in the wire
    spec is one a third-party tool inherits. Decimal in the message would be
    unreadable against the page it is about."""
    tree.edit(LIB, "KeyFid::new(0x1091)", "KeyFid::new(0x1092)")
    result = tree.run()
    assert result.returncode == 1
    assert "FIXTURE_FID copied as 0x1091, code says 0x1092" in result.stderr


def test_a_copy_that_drifted_through_an_alias_fails_the_row(tree):
    """The large-blob shape exactly: the docs name the alias, the literal is a hop
    away, and a scanner that only reads literals had nothing to say about it."""
    tree.edit(OTHER, "MAX_FIXTURE_VALUE: usize = 2046", "MAX_FIXTURE_VALUE: usize = 2044")
    result = tree.run()
    assert result.returncode == 1
    assert "MAX_FIXTURE_BLOB copied as 2046, code says 2044" in result.stderr


def test_a_stale_copy_in_a_test_file_does_not_vouch_for_a_doc(tree):
    """audit run-37: a name defined twice accepts either value, so a `_tests.rs`
    holding the OLD number goes on vouching for the doc after the real constant
    moved. The fixture files are skipped, so the finding stands."""
    tree.write(
        "crates/rsk-fixture/src/lib_tests.rs", "const MAX_FIXTURE_FILES: usize = 1280;\n"
    )
    tree.edit(LIB, "MAX_FIXTURE_FILES: usize = 1280", "MAX_FIXTURE_FILES: usize = 2560")
    result = tree.run()
    assert result.returncode == 1
    assert "MAX_FIXTURE_FILES copied as 1,280, code says 2560" in result.stderr


def test_every_wrong_copy_is_reported_not_just_the_first(tree):
    """One constant moving rots the docs page and the suite together; reporting
    one sends you round the loop once per copy."""
    tree.edit(LIB, "MAX_FIXTURE_FILES: usize = 1280", "MAX_FIXTURE_FILES: usize = 2560")
    tree.edit(LIB, "MIN_FIXTURE_PIN: u8 = 4", "MIN_FIXTURE_PIN: u8 = 6")
    result = tree.run()
    assert result.returncode == 1
    assert result.stderr.count("FAIL:") == 3  # the doc pair twice over, the suite once
    assert "3 copied constant(s) no longer match the code" in result.stderr


# --- the floors: a scanner that matches nothing passes whatever it is shown ----


def test_a_source_that_went_quiet_fails_the_row(tree):
    """audit run-34 #9. Every value in the page stops being stated the way the
    scanner reads, every comparison passes, and the row is green over nothing."""
    tree.write(DOC, "# Fixture\n\nMAX_FIXTURE_FILES is one thousand two hundred and eighty.\n")
    result = tree.run()
    assert result.returncode == 1
    assert "only 0 constant(s) found in docs (expected >= 5)" in result.stderr
    assert "passing vacuously" in result.stderr


def test_the_floors_are_per_source_so_one_cannot_hide_behind_another(tree):
    """45 test pairs would carry a metadata source that had gone silent, if the
    floor were a total. Two keys away is under 12 with the others untouched."""
    tree.edit(META, '  "maxMsgSize": 1200,\n', "")
    tree.edit(META, '  "maxPINLength": 63,\n', "")
    result = tree.run()
    assert result.returncode == 1
    assert "only 11 constant(s) found in metadata (expected >= 12)" in result.stderr
    assert "found in docs" not in result.stderr and "found in tests" not in result.stderr


# --- the controls: what the guard is right to be indifferent to ----------------


def test_a_name_the_tree_does_not_define_is_not_a_finding(tree):
    """Deliberately narrow: it compares integers to integers, and prose it cannot
    check must not be prose it fails on. Defined, the same 77 goes red — which is
    what says the green above is the name and not the sentence."""
    assert tree.run().returncode == 0
    tree.edit(LIB, "pub const MIN_FIXTURE_PIN",
              "pub const NOT_A_CONSTANT_HERE: u8 = 5;\npub const MIN_FIXTURE_PIN")
    assert "NOT_A_CONSTANT_HERE copied as 77, code says 5" in tree.run().stderr


def test_a_name_two_crates_define_accepts_either_value(tree):
    """`DUAL_FIXTURE_LIMIT` is 8 in one crate and 9 in the other; the docs rarely
    say which crate they mean, and a guard that guessed would cry wolf."""
    tree.edit(DOC, "`DUAL_FIXTURE_LIMIT` (9)", "`DUAL_FIXTURE_LIMIT` (8)")
    assert tree.run().returncode == 0


def test_a_local_inside_a_test_function_is_not_the_fixture(tree):
    """The suite's constant is module-level by definition. The fixture's local
    says 999 against a code value of 4; dedented it is a fixture and goes red, so
    the green above is the indentation and not a comparison that never ran."""
    assert tree.run().returncode == 0
    tree.edit(TESTS, "    MIN_FIXTURE_PIN = 999", "MIN_FIXTURE_PIN = 999")
    assert "MIN_FIXTURE_PIN copied as 999, code says 4" in tree.run().stderr


def test_a_metadata_key_the_mapping_does_not_name_is_not_compared(tree):
    """Only what `METADATA_CONSTANTS` links back to code; every other number in a
    statement is FIDO's, not this repo's. Mapped, the same 7 is compared and goes
    red, so the green is the mapping and not a scan that stopped."""
    tree.edit(META, '  "description": "RS-Key fixture",', '  "authenticatorVersion": 7,')
    assert tree.run().returncode == 0
    cut = ('"maxCredBlobLength": "MAX_CREDBLOB_LENGTH"',
           '"authenticatorVersion": "MAX_CREDBLOB_LENGTH",'
           ' "maxCredBlobLength": "MAX_CREDBLOB_LENGTH"')
    assert "MAX_CREDBLOB_LENGTH copied as 7, code says 32" in tree.run(cut).stderr


# --- the deletion arms: one clause at a time ----------------------------------


def test_deleting_the_comparison_takes_every_finding_with_it(tree):
    """The clause the guard is FOR. Cut, the stale docs page above is green."""
    tree.edit(LIB, "MAX_FIXTURE_FILES: usize = 1280", "MAX_FIXTURE_FILES: usize = 2560")
    assert tree.run().returncode == 1
    cut = ("            if value not in actual:", "            if False:")
    assert tree.run(cut).returncode == 0


def test_deleting_the_floors_lets_a_dead_scanner_pass(tree):
    """What the floors are worth: without them the row is green over a page it
    has stopped reading, which is the state the guard was written in."""
    tree.write(DOC, "# Fixture\n\nMAX_FIXTURE_FILES is one thousand two hundred and eighty.\n")
    assert tree.run().returncode == 1
    assert tree.run(("        if checked[source] < floor:", "        if False:")).returncode == 0


def test_deleting_the_test_file_skip_lets_a_fixture_vouch_for_a_doc(tree):
    """The run-37 repair, falsified: with `_tests.rs` back in the index the old
    value is still defined, `1,280` matches it, and the stale doc is green."""
    tree.write(
        "crates/rsk-fixture/src/lib_tests.rs", "const MAX_FIXTURE_FILES: usize = 1280;\n"
    )
    tree.edit(LIB, "MAX_FIXTURE_FILES: usize = 1280", "MAX_FIXTURE_FILES: usize = 2560")
    assert tree.run().returncode == 1
    cut = ('        if src.name.endswith("_tests.rs") or src.name in ("tests.rs", "kani.rs"):\n'
           "            continue\n", "")
    assert tree.run(cut).returncode == 0


def test_deleting_the_alias_walk_takes_the_aliased_copy_out_of_scope(tree):
    """One indirection is resolved because that is where the value hid. Cut, the
    alias resolves to nothing, the pair is never made, and the drift is green."""
    tree.edit(OTHER, "MAX_FIXTURE_VALUE: usize = 2046", "MAX_FIXTURE_VALUE: usize = 2044")
    assert tree.run().returncode == 1
    cut = ("    for _ in range(len(aliases) + 1):", "    for _ in range(0):")
    assert tree.run(cut).returncode == 0


def test_deleting_a_mapping_entry_is_caught_by_the_floor_it_drops_below(tree):
    """The clause that does NOT need its own arm, measured rather than assumed.

    A statement key is only compared because `METADATA_CONSTANTS` links it to a
    constant, so cutting the entry should take its comparison with it. It does —
    and the row still goes red, because the two pairs it removes drop the source
    under `MIN_PAIRS`. That is the floor doing the job it was added for, and the
    reason a mapping entry cannot rot quietly.
    """
    tree.edit(LIB, "MAX_LARGE_BLOB_SIZE: usize = 2046", "MAX_LARGE_BLOB_SIZE: usize = 2048")
    assert "MAX_LARGE_BLOB_SIZE copied as 2046" in tree.run().stderr
    cut = ('    "maxSerializedLargeBlobArray": "MAX_LARGE_BLOB_SIZE",\n', "")
    result = tree.run(cut)
    assert result.returncode == 1
    assert "MAX_LARGE_BLOB_SIZE copied as" not in result.stderr
    assert "only 11 constant(s) found in metadata (expected >= 12)" in result.stderr


def test_deleting_the_metadata_source_takes_its_floor_with_it(tree):
    """The deletion arm done the way a deletion happens: the scan AND the floor
    that would notice it stopped, which is what says the source is load-bearing
    rather than decorative. Cut, a published statement drifts unwatched."""
    tree.edit(LIB, "MAX_LARGE_BLOB_SIZE: usize = 2046", "MAX_LARGE_BLOB_SIZE: usize = 2048")
    assert tree.run().returncode == 1
    cut = tree.run(
        ('("docs", scan_docs), ("tests", scan_tests), ("metadata", scan_metadata)',
         '("docs", scan_docs), ("tests", scan_tests)'),
        ('MIN_PAIRS = {"docs": 5, "tests": 44, "metadata": 12}',
         'MIN_PAIRS = {"docs": 5, "tests": 44}'),
    )
    assert cut.returncode == 0, cut.stderr
