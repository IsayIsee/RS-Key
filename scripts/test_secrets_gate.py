# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `secrets_gate.py` was verified against, kept.

The register this guards is a set of judgements about what happens to a secret
on each way out of a request, and a judgement is worth exactly the roster under
it. There was no roster at all before this: the tree's own count of self-wiping
types was read off a `ZeroizeOnDrop` grep and came back TWO, where the answer is
eleven, because nine of them are hand-written `Drop` impls.

So the table below breaks one real defect shape at a time in a fixture checkout
and asserts the MESSAGE, not a count — a red for the wrong reason proves as
little as a green. Both directions, because a guard that cannot go green is
deleted as fast as one that cannot go red: the clean fixture passes, this
checkout's own register passes, `check.sh` is asserted to run the row, and two
cases exist only to stay green (a wipe named in a comment is not a wipe, and
inserting lines above everything moves nothing, because this register is keyed
on content and not on line numbers).
"""

import pathlib
import subprocess

import pytest

import gate_lines
import secrets_gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A bearer and an explicit wipe in one file, with the explicit one below a `?`
#: so the `skippable` axis has something to count.
KEYS = """\
//! A key store.
use zeroize::Zeroize;

pub struct Key([u8; 32]);

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn load(fs: &mut Fs) -> Result<Key> {
    let mut raw = fs.get(FID)?;
    let key = Key(raw);
    raw.zeroize();
    Ok(key)
}
"""

#: The only fixture source that observes a cancel, so the derived half of the
#: cancel rule has both arms in the tree.
PAD = """\
//! The PIN pad.
use zeroize::Zeroize;

fn gate(ui: &mut Ui) -> bool {
    let mut pin = [0u8; 8];
    let entry = ui.collect_pin(&mut pin);
    let ok = matches!(entry, PinEntry::Entered(_));
    pin.zeroize();
    ok
}
"""

WORKER = """\
//! The worker.
use zeroize::Zeroize;

fn roundtrip(ex: &mut Exchange) {
    ex.resp.zeroize();
}

async fn reboot(&mut self) -> ! {
    self.ctap.scrub_secrets();
    otp_kbd::scrub();
    loop {}
}
"""

HOST = """\
//! A host tool, out of scope.
fn main() {
    let mut pin = [0u8; 8];
    pin.zeroize();
}
"""

MANIFEST = '[dependencies]\npanic-halt = "1"\n'

PLATFORM = """\
[[assumption]]
id = "PLAT-MEM-001"
class = "memory"
status = "pending"
"""

CLAUSES = """\
[[clause]]
id = "TM-ZEROIZATION"
kind = "defence"
where = "## Zeroization"
rests_on = ["Key-grade material in RAM is wiped when its use ends."]

[[clause]]
id = "TM-ASSETS"
kind = "context"
where = "## Assets"
"""

REGISTER = """\
clause = "docs/threat-model.md#TM-ZEROIZATION"
reboot_wipers = ["ctap.scrub_secrets", "otp_kbd::scrub"]
out_of_scope_sites = 1

[[residual]]
id = "RES-PANIC"
applies = "register"
paths = ["panic"]
what = "every secret live in a frame at the moment of a panic."
why = "the image links a halting panic runtime, so nothing unwinds."
revalidate = "a #[panic_handler] appearing under firmware/src."

[[residual]]
id = "RES-EARLY"
applies = "rows"
paths = ["error", "cancel"]
what = "the wipes that sit below an early exit of their own function."
why = "the count is syntax and no per-statement analysis has been run."
revalidate = "the count moving, which the gate holds per row."

[[residual]]
id = "RES-SRAM"
applies = "rows"
paths = ["reboot"]
what = "whatever is still in a stack frame when the device reboots."
why = "the platform is assumed to clear SRAM across the drop — PLAT-MEM-001."
revalidate = "a different stepping or boot configuration."

[[secret]]
file = "crates/rsk-app/src/keys.rs"
secret = "the stored key and the raw buffer it is read into"
bearers = ["Key"]
sites = 2
skippable = 1
wraps = 0
success = "explicit"
error = "partial"
cancel = "n/a"
reboot = "platform"
residual = ["RES-EARLY", "RES-SRAM"]
why = "the type wipes on drop; the raw read buffer's wipe is below the store's `?`."

[[secret]]
file = "crates/rsk-app/src/pad.rs"
secret = "the PIN buffer the pad collects into"
bearers = []
sites = 1
skippable = 0
wraps = 0
success = "explicit"
error = "explicit"
cancel = "explicit"
reboot = "platform"
residual = ["RES-SRAM"]
why = "one buffer, wiped on the one tail every outcome reaches."

[[secret]]
file = "firmware/src/worker.rs"
secret = "the static exchange buffers"
bearers = []
sites = 1
skippable = 0
wraps = 0
success = "explicit"
error = "explicit"
cancel = "n/a"
reboot = "wiper"
wiper = "otp_kbd::scrub"
residual = []
why = "the roundtrip wipes both ends, and the reboot path runs `otp_kbd::scrub`."
"""


class Tree:
    """A checkout shaped like this one: two crate sources, a firmware, a tool."""

    def __init__(self, root):
        self.root = root
        self.write("crates/rsk-app/src/keys.rs", KEYS)
        self.write("crates/rsk-app/src/pad.rs", PAD)
        self.write("firmware/src/worker.rs", WORKER)
        self.write("firmware/Cargo.toml", MANIFEST)
        self.write("tools/host/src/main.rs", HOST)
        self.write("assurance/threat_clauses.toml", CLAUSES)
        self.write("assurance/platform.toml", PLATFORM)
        self.write("assurance/secrets.toml", REGISTER)
        # `sources` asks git what the tree is, so the fixture must be a checkout
        # — and one that ignores build output, like the real one.
        self.write(".gitignore", "target/\n")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)

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

    def run(self):
        return secrets_gate.run(self.root)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    # The shipped floors are about the real checkout's 56 rows over 446 wipes.
    # Scaled to the fixture so the emptying case below still has one to trip.
    monkeypatch.setattr(secrets_gate, "FLOOR_ROWS", 2)
    monkeypatch.setattr(secrets_gate, "FLOOR_SITES", 2)
    monkeypatch.setattr(secrets_gate, "FLOOR_BEARERS", 1)
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
    assert secrets_gate.run(ROOT) == 0


def test_check_sh_runs_the_row():
    """A guard nothing invokes can have its whole table deleted, suite green."""
    text = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(text, "scripts/secrets_gate.py")


def test_inserting_lines_above_everything_stays_green(tree):
    """The control that says what this register is NOT keyed on. `deleters.toml`
    stores a line per site and a shifted citation reddens it; this stores none,
    so a comment added at the top of a source must be invisible here."""
    tree.edit("crates/rsk-app/src/keys.rs", "//! A key store.", "// a line arrives\n//! A key store.")
    assert tree.run() == 0


def test_a_wipe_named_in_a_comment_is_not_a_wipe(tree):
    """The lexer control. `zeroized on drop` is the phrase half the rustdoc in
    this tree opens with, and a raw scan reads the sentence about a wipe as one
    — which would move a count nobody changed."""
    tree.edit(
        "crates/rsk-app/src/pad.rs",
        "//! The PIN pad.",
        '//! The PIN pad. The buffer is pin.zeroize()d on the way out.\n//! See `let s = "x.zeroize()";`.',
    )
    assert tree.run() == 0


# --- the roster, both directions ----------------------------------------------


def test_a_new_secret_bearing_source_with_no_row_is_rejected(tree, capsys):
    tree.write("crates/rsk-app/src/seal.rs", "fn f(k: &mut [u8]) { k.zeroize(); }\n")
    assert "a secret arrived unowned" in red(tree, capsys)


def test_a_wipe_in_a_directory_the_scope_never_named_is_rejected(tree, capsys):
    """Two tuples answer for what is inside them. `rsk-wipe/` links the same
    halting panic runtime and would have been invisible to every rule above."""
    tree.write("rsk-wipe/src/main.rs", "fn f(k: &mut [u8]) { k.zeroize(); }\n")
    assert "is in neither" in red(tree, capsys)


def test_a_row_over_a_source_that_wipes_nothing_is_rejected(tree, capsys):
    tree.edit("crates/rsk-app/src/pad.rs", "    pin.zeroize();\n", "")
    assert "either the secret left or the row is stale" in red(tree, capsys)


def test_the_derivation_finding_nothing_is_rejected(tree, capsys):
    """A floor, because every rule above passes over an empty roster."""
    tree.edit("crates/rsk-app/src/keys.rs", "        self.0.zeroize();\n", "")
    tree.edit("crates/rsk-app/src/keys.rs", "    raw.zeroize();\n", "")
    tree.edit("crates/rsk-app/src/pad.rs", "    pin.zeroize();\n", "")
    assert "under the floor" in red(tree, capsys)


# --- the counts, derived rather than read -------------------------------------


def test_a_site_count_that_drifted_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", "sites = 2", "sites = 3")
    said = red(tree, capsys)
    assert "the register states 3 wipe(s) and the file has 2" in said
    assert "do not re-type the number" in said


def test_a_wipe_deleted_from_a_source_moves_its_count(tree, capsys):
    """The other direction of the same rule: the register stands still and the
    file moves."""
    tree.edit("crates/rsk-app/src/keys.rs", "    raw.zeroize();\n", "")
    assert "the register states 2 wipe(s) and the file has 1" in red(tree, capsys)


def test_a_skippable_count_that_drifted_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", "skippable = 1", "skippable = 0")
    assert "wipe(s) below an early exit and the file has 1" in red(tree, capsys)


def test_a_count_stated_in_the_prose_that_drifted_is_rejected(tree, capsys):
    """The headline of this register is a number in a sentence, so the sentence
    is held too. The rule found its first error the hour it was written: the
    shipped residual said 30 sources where the derivation says 34."""
    tree.edit("assurance/secrets.toml", 'why = "the type wipes on drop;', 'why = "1 of the 9 wipes here; the type wipes on drop;')
    said = red(tree, capsys)
    assert "is not a number this register derives" in said


def test_domain_vocabulary_is_not_read_as_a_count(tree):
    """The control that keeps the rule from being a false-alarm machine: the
    rows are full of `P-256`, `ML-DSA-87` and `audit run-34 #23`, and reading
    every integer as a count is the version `docstring_count_gate.py` refused."""
    tree.edit(
        "assurance/secrets.toml",
        'secret = "the PIN buffer the pad collects into"',
        'secret = "the P-256 and ML-DSA-87 material, per audit run-34 #23 and CTAP 2.3 §12.4"',
    )
    assert tree.run() == 0


def test_a_bearer_that_stopped_wiping_is_rejected(tree, capsys):
    """A `Drop` that releases a peripheral is not a secret bearer, so the impl
    counts only while its body wipes — dropping the wipe drops the bearer."""
    tree.edit("crates/rsk-app/src/keys.rs", "        self.0.zeroize();\n", "        self.0 = [1; 32];\n")
    assert "the file defines []" in red(tree, capsys)


# --- the exits, held to the derivation ----------------------------------------


def test_claiming_an_explicit_wipe_where_there_is_none_is_rejected(tree, capsys):
    """A source can stay in the roster on its `Zeroizing` alone, and then an
    `explicit` answer is a claim about a statement that is not there."""
    tree.edit("crates/rsk-app/src/pad.rs", "    pin.zeroize();\n", "    let _held = Zeroizing::new(pin);\n")
    tree.edit(
        "assurance/secrets.toml",
        'sites = 1\nskippable = 0\nwraps = 0\nsuccess = "explicit"\nerror = "explicit"\ncancel = "explicit"',
        'sites = 0\nskippable = 0\nwraps = 1\nsuccess = "explicit"\nerror = "explicit"\ncancel = "explicit"',
    )
    assert "claims an explicit wipe and the file has none" in red(tree, capsys)


def test_claiming_a_drop_wipe_with_no_bearer_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'error = "explicit"\ncancel = "explicit"', 'error = "on-drop"\ncancel = "explicit"')
    assert "claims a wipe on drop and the file defines no self-wiping type" in red(tree, capsys)


def test_claiming_the_error_exit_over_a_skippable_wipe_is_rejected(tree, capsys):
    """The rule the threat model's own sentence needed: "wiped at end of scope
    including error paths" is not free where a wipe sits below a `?`."""
    tree.edit("assurance/secrets.toml", 'error = "partial"', 'error = "explicit"')
    said = red(tree, capsys)
    assert "1 of them sit below an early exit" in said
    assert "not a claim" in said


def test_a_partial_answer_over_no_skippable_wipe_is_rejected(tree, capsys):
    """The other direction: the file was fixed and the register still records
    the debt."""
    tree.edit("crates/rsk-app/src/keys.rs", "    let mut raw = fs.get(FID)?;\n", "    let mut raw = [0u8; 32];\n")
    tree.edit("assurance/secrets.toml", "skippable = 1", "skippable = 0")
    assert "the file caught up with the register" in red(tree, capsys)


def test_a_reboot_word_on_a_request_exit_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'success = "explicit"\nerror = "partial"', 'success = "platform"\nerror = "partial"')
    assert "which that exit does not take" in red(tree, capsys)


def test_a_request_word_on_the_reboot_exit_is_rejected(tree, capsys):
    """The other direction, and the hole a review drove through: `explicit` on
    the reboot exit escapes the wiper rule AND the residual rule at once,
    because neither is about `explicit`."""
    tree.edit("assurance/secrets.toml", 'reboot = "platform"\nresidual = ["RES-SRAM"]\nwhy = "one buffer', 'reboot = "explicit"\nresidual = []\nwhy = "one buffer')
    assert "which that exit does not take" in red(tree, capsys)


def test_n_a_on_an_exit_nothing_derives_it_for_is_rejected(tree, capsys):
    """`n/a` is a DERIVED word and it is derived for the cancel exit alone. A
    review flipped the master seed's error answer to `n/a` and passed."""
    tree.edit("assurance/secrets.toml", 'error = "partial"', 'error = "n/a"')
    assert "which that exit does not take" in red(tree, capsys)


def test_a_partial_answer_on_the_success_exit_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'success = "explicit"\nerror = "partial"', 'success = "partial"\nerror = "partial"')
    assert "which that exit does not take" in red(tree, capsys)


def test_a_word_that_is_not_an_answer_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'cancel = "n/a"\nreboot = "platform"', 'cancel = "probably"\nreboot = "platform"')
    assert "which is not one of" in red(tree, capsys)


# --- the cancel exit, derived from what the source can observe -----------------


def test_a_source_that_starts_taking_a_pin_entry_may_not_stay_n_a(tree, capsys):
    tree.edit(
        "crates/rsk-app/src/keys.rs",
        "    let key = Key(raw);\n",
        "    let key = Key(raw);\n    let _ = fs.collect_pin();\n",
    )
    said = red(tree, capsys)
    assert "cancel answers `n/a`" in said
    assert "takes PIN entry" in said


def test_a_source_that_never_sees_a_cancel_may_not_claim_one(tree, capsys):
    tree.edit("crates/rsk-app/src/pad.rs", "    let entry = ui.collect_pin(&mut pin);\n", "    let entry = ui.read(&mut pin);\n")
    tree.edit("crates/rsk-app/src/pad.rs", "    let ok = matches!(entry, PinEntry::Entered(_));\n", "    let ok = entry > 0;\n")
    assert "takes no PIN entry or cancel frame" in red(tree, capsys)


# --- the reboot path, derived from its own body -------------------------------


def test_a_scrub_dropped_from_the_reboot_path_is_rejected(tree, capsys):
    """`otp_kbd::scrub` was added to the real reboot for the reflash case (audit
    run-34). Deleting one has to be a finding rather than an edit."""
    tree.edit("firmware/src/worker.rs", "    otp_kbd::scrub();\n", "")
    assert "a wipe left the reboot path" in red(tree, capsys)


def test_a_reboot_with_no_such_function_is_rejected(tree, capsys):
    tree.edit("firmware/src/worker.rs", "async fn reboot(&mut self) -> ! {", "async fn shutdown(&mut self) -> ! {")
    assert "the reboot exit's wipes are derived from its body" in red(tree, capsys)


def test_a_wiper_answer_whose_reason_never_names_its_scrub_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", "and the reboot path runs `otp_kbd::scrub`.", "and the reboot path handles it.")
    assert "the reason never names it" in red(tree, capsys)


def test_a_wiper_row_pointed_at_another_rows_scrub_is_rejected(tree, capsys):
    """Membership, not correspondence, was the hole: a review re-pointed five
    wiper rows at one scrub and the row stayed green while the message said
    "say WHICH one reaches this secret"."""
    tree.edit("assurance/secrets.toml", 'wiper = "otp_kbd::scrub"', 'wiper = "sd_card::scrub"')
    assert "which is not one of the scrubs the reboot path calls" in red(tree, capsys)


def test_a_named_scrub_on_a_row_that_does_not_rest_on_one_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'reboot = "platform"\nresidual = ["RES-SRAM"]\nwhy = "one buffer', 'reboot = "platform"\nwiper = "otp_kbd::scrub"\nresidual = ["RES-SRAM"]\nwhy = "one buffer')
    assert "only a `wiper` row rests on one" in red(tree, capsys)


# --- the panic exit, derived once for every row -------------------------------


def test_the_panic_residual_going_missing_is_rejected(tree, capsys):
    tree.edit(
        "assurance/secrets.toml",
        '[[residual]]\nid = "RES-PANIC"\napplies = "register"\npaths = ["panic"]\n'
        'what = "every secret live in a frame at the moment of a panic."\n'
        'why = "the image links a halting panic runtime, so nothing unwinds."\n'
        'revalidate = "a #[panic_handler] appearing under firmware/src."\n\n',
        "",
    )
    said = red(tree, capsys)
    assert "0 residual(s) name" in said
    assert "cannot come back as a second silence" in said


def test_a_second_panic_residual_is_rejected(tree, capsys):
    tree.edit(
        "assurance/secrets.toml",
        '[[secret]]\nfile = "crates/rsk-app/src/keys.rs"',
        '[[residual]]\nid = "RES-PANIC-TOO"\napplies = "register"\npaths = ["panic"]\n'
        'what = "the same thing again."\nwhy = "the same reason again."\n'
        'revalidate = "the same trigger again."\n\n'
        '[[secret]]\nfile = "crates/rsk-app/src/keys.rs"',
    )
    assert "2 residual(s) name" in red(tree, capsys)


def test_a_panic_handler_appearing_reopens_every_row(tree, capsys):
    """The revalidation trigger, made mechanical: a handler that could wipe
    makes every `explicit` and `on-drop` answer worth re-reading."""
    tree.write("firmware/src/panic.rs", "#[panic_handler]\nfn ph(_: &PanicInfo) -> ! { loop {} }\n")
    said = red(tree, capsys)
    assert "the panic exit is no longer a silence" in said
    assert "defines a #[panic_handler] of its own" in said


def test_a_halting_panic_runtime_leaving_the_manifest_reopens_every_row(tree, capsys):
    tree.edit("firmware/Cargo.toml", 'panic-halt = "1"\n', "")
    assert "links no halting panic strategy" in red(tree, capsys)


# --- residuals: reasoned, triggered, pointed at -------------------------------


def test_a_residual_with_no_reason_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'why = "the count is syntax and no per-statement analysis has been run."', 'why = "  "')
    assert "a residual with no reason is not one" in red(tree, capsys)


def test_a_residual_with_no_revalidation_trigger_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'revalidate = "a different stepping or boot configuration."', 'revalidate = ""')
    assert "cannot go stale" in red(tree, capsys)


def test_a_residual_nothing_rests_on_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", '"RES-EARLY", "RES-SRAM"', '"RES-SRAM"')
    said = red(tree, capsys)
    assert "no row rests on it" in said


def test_a_residual_about_an_exit_no_row_leaves_open_is_rejected(tree, capsys):
    """The docstring promised this and nothing implemented it: a residual could
    be pointed at by a row and still name an exit every row has answered."""
    tree.edit("assurance/secrets.toml", 'paths = ["error", "cancel"]', 'paths = ["success"]')
    said = red(tree, capsys)
    assert "no row leaves any of those open" in said


def test_a_row_citing_a_register_wide_residual_is_rejected(tree, capsys):
    """A `register` residual is inherited, never cited. A review discharged a
    `not-wiped` on the device master seed by pointing at one."""
    tree.edit("assurance/secrets.toml", 'residual = ["RES-EARLY", "RES-SRAM"]', 'residual = ["RES-PANIC", "RES-EARLY", "RES-SRAM"]')
    assert "citing it discharges nothing" in red(tree, capsys)


def test_a_not_wiped_answer_with_a_residual_that_covers_it_passes(tree):
    """The only answer word that names a real finding, exercised in the green
    direction — no case touched it before a review said so."""
    tree.edit("assurance/secrets.toml", 'error = "partial"', 'error = "not-wiped"')
    tree.edit("assurance/secrets.toml", "the raw read buffer's wipe is below the store's `?`.", "on the error exit the buffer stays resident.")
    assert tree.run() == 0


def test_a_not_wiped_answer_with_no_residual_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'error = "partial"', 'error = "not-wiped"')
    tree.edit("assurance/secrets.toml", "the raw read buffer's wipe is below the store's `?`.", "on the error exit the buffer stays resident.")
    tree.edit("assurance/secrets.toml", 'residual = ["RES-EARLY", "RES-SRAM"]', 'residual = ["RES-SRAM"]')
    assert "none of which is about that exit" in red(tree, capsys)


def test_a_row_citing_an_undeclared_residual_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", '"RES-EARLY", "RES-SRAM"', '"RES-INVENTED", "RES-SRAM"')
    assert "which is not declared" in red(tree, capsys)


def test_an_open_exit_with_no_residual_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'residual = ["RES-EARLY", "RES-SRAM"]', "residual = []")
    assert "never a blank" in red(tree, capsys)


def test_a_residual_that_is_not_about_the_open_exit_is_rejected(tree, capsys):
    """The half a citation alone would miss: pointing at a residual is not the
    same as pointing at one that answers for this exit."""
    tree.edit("assurance/secrets.toml", 'residual = ["RES-EARLY", "RES-SRAM"]', 'residual = ["RES-EARLY"]')
    said = red(tree, capsys)
    assert "leaves reboot unwiped" in said
    assert "none of which is about that exit" in said


def test_a_residual_resting_on_an_unregistered_board_question_is_rejected(tree, capsys):
    """`citation_gate.py` reads `.rs`/`.sh`/`.txt`/`.py` and does not read
    `assurance/*.toml` outside `bundle/`, so a `PLAT-…` written here would be
    held by nothing at all. The reboot answer of most rows rests on one."""
    tree.edit("assurance/secrets.toml", "PLAT-MEM-001.", "PLAT-MEM-009.")
    said = red(tree, capsys)
    assert "which assurance/platform.toml does not register" in said


def test_a_residual_with_no_scope_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'id = "RES-SRAM"\napplies = "rows"', 'id = "RES-SRAM"')
    assert "a residual nothing says the scope of is not held" in red(tree, capsys)


# --- the clause, and the shape of the file ------------------------------------


def test_a_clause_no_registry_declares_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", "#TM-ZEROIZATION", "#TM-WIPING")
    assert "anchored to a threat nobody registered" in red(tree, capsys)


def test_a_context_clause_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", "#TM-ZEROIZATION", "#TM-ASSETS")
    assert "a defence is the only kind a wipe can serve" in red(tree, capsys)


def test_a_clause_with_its_pins_stripped_is_rejected(tree, capsys):
    """Every sentence the register answers is BELOW the clause's locked first
    line, so without the pins the page can be rewritten under all of it."""
    tree.edit("assurance/threat_clauses.toml", 'rests_on = ["Key-grade material in RAM is wiped when its use ends."]\n', "")
    assert "carries no `rests_on` pin" in red(tree, capsys)


def test_an_out_of_scope_count_that_drifted_is_rejected(tree, capsys):
    """The exclusion is stated so it cannot be silent, which means the number
    has to move with the tree."""
    tree.write("tools/host/src/other.rs", "fn f(k: &mut [u8]) { k.zeroize(); }\n")
    assert "the exclusion is stated so it" in red(tree, capsys)


def test_a_field_nothing_reads_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'skippable = 1\n', 'skippable = 1\nseverity = "high"\n')
    assert "which nothing reads" in red(tree, capsys)


def test_a_table_nothing_reads_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", "out_of_scope_sites = 1", 'out_of_scope_sites = 1\nnotes = "free text"')
    assert "held by no rule and shown to no reader" in red(tree, capsys)


def test_two_rows_over_one_source_is_rejected(tree, capsys):
    tree.edit(
        "assurance/secrets.toml",
        '[[secret]]\nfile = "crates/rsk-app/src/pad.rs"',
        '[[secret]]\nfile = "crates/rsk-app/src/keys.rs"\nsecret = "a"\nbearers = ["Key"]\n'
        'sites = 2\nskippable = 1\nsuccess = "explicit"\nerror = "partial"\ncancel = "n/a"\n'
        'reboot = "platform"\nresidual = ["RES-EARLY", "RES-SRAM"]\nwhy = "a"\n\n'
        '[[secret]]\nfile = "crates/rsk-app/src/pad.rs"',
    )
    assert "owned twice" in red(tree, capsys)


def test_a_row_with_no_reason_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'why = "one buffer, wiped on the one tail every outcome reaches."', 'why = " "')
    assert "an answer with no reason is not one" in red(tree, capsys)


def test_a_row_that_does_not_say_what_the_secret_is_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'secret = "the PIN buffer the pad collects into"', 'secret = ""')
    assert "does not say what the secret is" in red(tree, capsys)


def test_an_unreadable_register_is_reported_rather_than_raised(tree, capsys):
    tree.edit("assurance/secrets.toml", "out_of_scope_sites = 1", "out_of_scope_sites = ")
    assert "cannot be read as a secret register" in red(tree, capsys)


# --- the rules a review found untested, and the derivation's own edges ---------


def test_an_open_exit_whose_reason_never_names_it_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'error = "partial"', 'error = "not-wiped"')
    assert "the reason never names the error exit" in red(tree, capsys)


def test_a_residual_naming_an_exit_that_is_not_one_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'paths = ["reboot"]', 'paths = ["reboot", "teardown"]')
    assert "which are not exits" in red(tree, capsys)


def test_a_residual_about_no_exit_at_all_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'paths = ["reboot"]', "paths = []")
    assert "nothing it says is about a lifetime" in red(tree, capsys)


def test_a_residual_that_never_says_what_stays_resident_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'what = "whatever is still in a stack frame when the device reboots."', 'what = " "')
    assert "does not say what is left resident" in red(tree, capsys)


def test_a_residual_field_nothing_reads_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'id = "RES-SRAM"', 'id = "RES-SRAM"\nseverity = "low"')
    assert "residual #3 carries" in red(tree, capsys)


def test_a_residual_id_declared_twice_is_rejected(tree, capsys):
    tree.edit(
        "assurance/secrets.toml",
        '[[secret]]\nfile = "crates/rsk-app/src/keys.rs"',
        '[[residual]]\nid = "RES-SRAM"\napplies = "rows"\npaths = ["reboot"]\n'
        'what = "a."\nwhy = "b."\nrevalidate = "c."\n\n'
        '[[secret]]\nfile = "crates/rsk-app/src/keys.rs"',
    )
    assert "declared twice" in red(tree, capsys)


def test_a_row_with_no_file_is_rejected(tree, capsys):
    tree.edit("assurance/secrets.toml", 'file = "crates/rsk-app/src/pad.rs"', 'files = "crates/rsk-app/src/pad.rs"')
    assert "has no 'file'" in red(tree, capsys)


def test_the_wipe_floor_is_a_floor(tree, capsys, monkeypatch):
    monkeypatch.setattr(secrets_gate, "FLOOR_SITES", 99)
    assert "under the floor of 99" in red(tree, capsys)


def test_the_bearer_floor_is_a_floor(tree, capsys, monkeypatch):
    monkeypatch.setattr(secrets_gate, "FLOOR_BEARERS", 9)
    assert "under the floor of 9" in red(tree, capsys)


def test_a_wraps_count_that_drifted_is_rejected(tree, capsys):
    """Derived and, until a review said so, compared to nothing — while three
    rows' reasoning rests on `Zeroizing` as the mechanism covering their early
    returns."""
    tree.edit("crates/rsk-app/src/pad.rs", "    let mut pin = [0u8; 8];", "    let mut pin = Zeroizing::new([0u8; 8]);")
    assert "`Zeroizing` mention(s) and the file has 1" in red(tree, capsys)


def test_a_part_larger_than_its_whole_is_rejected(tree, capsys):
    """Membership alone let `22 of its 28` become `28 of its 22` at exit 0."""
    tree.edit("assurance/secrets.toml", 'why = "the type wipes on drop;', 'why = "2 of the 1 wipes; the type wipes on drop;')
    assert "a part larger than its whole" in red(tree, capsys)


def test_an_inline_cfg_test_wipe_does_not_count_as_shipped(tree):
    """`CFG_GATED` is a filename rule; this is the other half. The real
    `seed.rs` carries an inline `#[cfg(test)] fn` whose two wipes were counted,
    so the tree's highest-value row read 37 where the image has 35."""
    tree.edit(
        "crates/rsk-app/src/keys.rs",
        "fn load(fs: &mut Fs) -> Result<Key> {",
        "#[cfg(test)]\nfn fixture(k: &mut [u8]) {\n    k.zeroize();\n}\n\nfn load(fs: &mut Fs) -> Result<Key> {",
    )
    assert tree.run() == 0


def test_a_ufcs_wipe_is_a_wipe(tree, capsys):
    """A source whose only wipes are `Zeroize::zeroize(k)` was in no roster and
    owed no row — measured before the second alternative went in."""
    tree.write("crates/rsk-app/src/ufcs.rs", "fn f(k: &mut [u8; 4]) { Zeroize::zeroize(k); }\n")
    assert "a secret arrived unowned" in red(tree, capsys)


def test_a_bearer_behind_a_nested_generic_bound_is_still_a_bearer(tree):
    """`<[^>]*>` stopped at the first `>`, so `impl<T: AsRef<[u8]>> Drop for …`
    derived no bearer at all — the row then read as a stale `bearers = ["Key"]`
    and the file could never answer `on-drop`. Green is the assertion here: the
    bearer survives the bound, so the register does not have to move."""
    tree.edit("crates/rsk-app/src/keys.rs", "impl Drop for Key {", "impl<T: AsRef<[u8]>> Drop for Key {")
    assert secrets_gate.derive(tree.root)["crates/rsk-app/src/keys.rs"]["bearers"] == ["Key"]
    assert tree.run() == 0


def test_a_status_word_return_is_an_early_exit(tree, capsys):
    """The card applets do not return `Result`. Reading `return Err` only left
    `rsk-piv/src/lib.rs` deriving ZERO early exits over eleven real ones."""
    tree.edit(
        "crates/rsk-app/src/pad.rs",
        "    let entry = ui.collect_pin(&mut pin);",
        "    let entry = ui.collect_pin(&mut pin);\n    if entry.bad() {\n        return Sw::MEMORY_FAILURE;\n    }",
    )
    assert "the register states 0 wipe(s) below an early exit and the file has 1" in red(tree, capsys)


def test_a_panic_handler_outside_the_firmware_directory_still_counts(tree, capsys):
    """Panic behaviour is a property of the image, not of one directory: a
    handler in a crate the firmware links is the same handler."""
    tree.write("crates/rsk-app/src/panic.rs", "#[panic_handler]\nfn ph(_: &PanicInfo) -> ! { loop {} }\n")
    assert "defines a #[panic_handler] of its own" in red(tree, capsys)
