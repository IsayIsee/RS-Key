# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `display_borrow_gate.py` is verified against.

One mutation per rule that must make the row RED, one CONTROL per rule that must
leave it GREEN, and — the family this tree keeps shipping guards with — an arm
for each derivation that can stop finding anything, since a guard looping over an
empty set exits 0 and prints a cheerful line.

The four floors are PARAMETERS of the fixture rather than globals a case reaches
in and lowers: the shipped numbers are about a crate with 38 reachable functions
and 34 borrowing ones, and the fixture has eleven and three.

Measured on the real checkout, not only on this fixture, before either existed:

* the #107 borrow put back in the pad → rc 1, naming `collect_pin` and the line;
* a `self.fs.borrow_mut()` added to `confirm_wait` → rc 1, naming that function;
* the same borrow added to a display-only screen → rc 0, summary unchanged;
* `ctap.rs` no longer holding `rng` → rc 0 over `fido_state/fs/presence`, 33
  display-only sites instead of 34. The rule follows the dispatch, which is the
  half that cannot be checked by reading this file.

And one defect this table found in its own subject before it shipped: the cells
were read from a fourteen-line WINDOW above the handoff, which excluded `hooks`
on the real `ctap.rs` by line spacing alone. [`test_a_borrow_of_a_cell_the_dispatch_does_not_hold`]
put the same borrow two lines out and the guard derived it as held, reddening a
display-only screen. The window is a brace-depth walk now.
"""

import pathlib
import subprocess

import pytest

import display_borrow_gate as gate
import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

DISPATCH = """\
// SPDX-License-Identifier: AGPL-3.0-only
impl Ctap {
    fn dispatch(&mut self, data: &[u8]) -> usize {
        self.hooks.borrow_mut().local_pin_changed();
        let n = {
            let mut fsb = self.fs.borrow_mut();
            let mut rngb = self.rng.borrow_mut();
            let mut presence = self.presence.borrow_mut();
            let mut stb = self.fido_state.borrow_mut();
            let mut ctx = rsk_fido::Ctx { fs: &mut *fsb, rng: &mut *rngb };
            rsk_fido::process_cbor(&mut ctx, data, &mut self.resp)
        };
        n
    }
}
"""

#: The handle. `new` is `pub` and is NOT a root: a dispatch holds one of these
#: and calls methods on it. `confirm_wait` is private and IS reached, through
#: `request` — which is what the walk is for.
HANDLE = """\
// SPDX-License-Identifier: AGPL-3.0-only
impl<'a, P> TouchPresence<'a, P> {
    pub fn new(ui: &'a RefCell<Ui>) -> Self {
        Self { ui }
    }

    fn confirm_wait(&mut self) -> Outcome {
        self.ui.borrow_mut().hold_to_confirm()
    }

    pub fn collect_pin_titled(&mut self, title: &'static str) -> PinEntry {
        self.ui.borrow_mut().collect_pin(title)
    }
}

impl<'a, P> rsk_sdk::UserPresence for TouchPresence<'a, P> {
    fn request(&mut self) -> Presence {
        self.confirm_wait()
    }

    fn collect_pin(&mut self, min_len: usize) -> PinEntry {
        self.ui.borrow_mut().collect_pin("FIDO PIN")
    }

    fn uv_available(&self) -> bool {
        true
    }

    fn shows_confirm(&self) -> bool {
        true
    }
}
"""

#: The panel. Three functions borrow a held cell and none of them is reachable —
#: the shape of the real crate, where 34 do and all 34 are device-raised screens.
PANEL = """\
// SPDX-License-Identifier: AGPL-3.0-only
impl Ui {
    pub(super) fn collect_pin(&mut self, title: &'static str) -> PinEntry {
        let entropy = self.shuffle_entropy();
        self.paint_pad(&entropy)
    }

    fn shuffle_entropy(&mut self) -> [u8; 8] {
        self.shuffle_ctr += 1;
        rsk_crypto::hmac_sha256(&self.shuffle_seed, &self.shuffle_ctr.to_le_bytes())
    }

    fn paint_pad(&mut self, entropy: &[u8]) -> PinEntry {
        self.panel.draw(entropy)
    }

    pub(super) fn hold_to_confirm(&mut self) -> Outcome {
        self.wait_release()
    }

    fn wait_release(&mut self) -> Outcome {
        Outcome::Confirmed
    }

    pub(super) fn run_delete(&mut self, fid: u16) {
        let mut fs = self.fs.borrow_mut();
        fs.delete(fid);
    }

    pub(super) fn run_set_pin(&mut self) {
        let mut fs = self.fs.borrow_mut();
        let mut rng = self.rng.borrow_mut();
    }

    pub(super) fn run_seal_backup(&mut self) {
        let mut rng = self.rng.borrow_mut();
    }
}
"""

#: A cfg-gated sibling: it never reaches the image, so a borrow here panics no
#: device and must not be derived as a site.
PANEL_TESTS = """\
// SPDX-License-Identifier: AGPL-3.0-only
impl Ui {
    pub(super) fn collect_pin(&mut self, title: &'static str) -> PinEntry {
        let mut rng = self.rng.borrow_mut();
        PinEntry::Cancelled
    }
}
"""


class Tree:
    """A checkout shaped like this one: the dispatch, the handle, the panel."""

    def __init__(self, root):
        self.root = root
        self.write(gate.DISPATCH.as_posix(), DISPATCH)
        self.write(gate.HANDLE, HANDLE)
        self.write(f"{gate.CRATE}/src/pin.rs", PANEL)
        self.write(f"{gate.CRATE}/src/pin_tests.rs", PANEL_TESTS)
        # `sources` asks git what the tree is, so the fixture has to be a checkout.
        self.write(".gitignore", "target/\n")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it.

        The assertion is the point: an anchor that matches nothing leaves the
        fixture unpatched and the case then measures a clean tree.
        """
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def run(self):
        return gate.run(self.root)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    # Scaled to the fixture: eleven reachable functions and three borrowing ones
    # against the real crate's 38 and 34. Nine, not six — the broken-walk arm
    # collapses the reach onto the roots and those resolve to SIX keys, not five
    # (`collect_pin` names a method on the handle and one on the panel), so a
    # floor of six let that mutation through green.
    monkeypatch.setattr(gate, "FLOOR_REACH", 9)
    monkeypatch.setattr(gate, "FLOOR_SITES", 2)
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
    assert gate_lines.runs(text, "scripts/display_borrow_gate.py")


# --- the rule itself ----------------------------------------------------------


def test_issue_107_itself(tree, capsys):
    """The defect this row exists for: the pad drawing from the shared DRBG."""
    tree.edit(
        f"{gate.CRATE}/src/pin.rs",
        "let entropy = self.shuffle_entropy();",
        "let mut entropy = [0u8; 8];\n        self.rng.borrow_mut().fill(&mut entropy);",
    )
    out = red(tree, capsys)
    assert "pin.rs" in out and "`collect_pin`" in out
    assert "self.rng.borrow_mut()" in out


def test_a_borrow_in_the_ceremony_itself(tree, capsys):
    """One hop from a root, in the handle rather than the panel."""
    tree.edit(
        gate.HANDLE,
        "    fn confirm_wait(&mut self) -> Outcome {",
        "    fn confirm_wait(&mut self) -> Outcome {\n        let _ = self.fs.borrow_mut();",
    )
    assert "`confirm_wait`" in red(tree, capsys)


def test_a_borrow_behind_the_ccid_entry_point(tree, capsys):
    """`collect_pin_titled` is `pub` and not in the trait — the CCID secure-PIN
    path reaches it from `firmware/src/worker.rs` directly, so a roots list that
    read only the trait impl would leave this whole branch unguarded."""
    tree.edit(
        gate.HANDLE,
        '    pub fn collect_pin_titled(&mut self, title: &\'static str) -> PinEntry {',
        '    pub fn collect_pin_titled(&mut self, title: &\'static str) -> PinEntry {\n'
        "        let _ = self.presence.borrow_mut();",
    )
    assert "`collect_pin_titled`" in red(tree, capsys)


def test_a_borrow_three_hops_down(tree, capsys):
    """The walk is transitive or it is a grep: `paint_pad` is root → `Ui::collect_pin`
    → here, and nothing above it names the cell."""
    tree.edit(
        f"{gate.CRATE}/src/pin.rs",
        "        self.panel.draw(entropy)",
        "        let _ = self.fs.borrow_mut();\n        self.panel.draw(entropy)",
    )
    assert "`paint_pad`" in red(tree, capsys)


# --- controls: the row must not cry wolf --------------------------------------


def test_a_display_only_borrow_stays_green(tree, capsys):
    """The control. 34 functions in the real crate borrow these cells and every
    one is a screen the DEVICE raises; a guard that reddens on those is a guard
    someone deletes."""
    before = summary(tree, capsys)
    tree.edit(
        f"{gate.CRATE}/src/pin.rs",
        "    pub(super) fn run_seal_backup(&mut self) {",
        "    pub(super) fn run_seal_backup(&mut self) {\n        let _ = self.fs.borrow_mut();",
    )
    assert summary(tree, capsys) == before


def test_a_cfg_gated_sibling_is_not_a_site(tree, capsys):
    """`pin_tests.rs` borrows the DRBG inside a name that IS reachable, and it
    never reaches the image. Deriving it would make the row red on every crate
    in the tree that tests its own panel."""
    assert tree.run() == 0


def test_a_borrow_of_a_cell_the_dispatch_does_not_hold(tree, capsys):
    """`hooks` is borrowed by `ctap.rs` OUTSIDE the block, and released before
    the handoff. A rule that swept every `self.X.borrow` would redden here."""
    tree.edit(
        f"{gate.CRATE}/src/pin.rs",
        "        self.panel.draw(entropy)",
        "        let _ = self.hooks.borrow_mut();\n        self.panel.draw(entropy)",
    )
    assert tree.run() == 0


# --- the cells are DERIVED, not listed ----------------------------------------


def test_the_rule_follows_the_dispatch(tree, capsys):
    """A cell the dispatch stops holding stops being guarded, the same day."""
    tree.edit(
        gate.DISPATCH.as_posix(),
        "            let mut rngb = self.rng.borrow_mut();\n",
        "",
    )
    tree.edit(
        f"{gate.CRATE}/src/pin.rs",
        "let entropy = self.shuffle_entropy();",
        "let mut entropy = [0u8; 8];\n        self.rng.borrow_mut().fill(&mut entropy);",
    )
    out = summary(tree, capsys)
    assert "rng" not in out.split("borrows ")[1].split(";")[0]


def test_a_cell_the_dispatch_starts_holding_is_guarded(tree, capsys):
    """The other direction, which is the whole reason the list is not typed in."""
    tree.edit(
        gate.DISPATCH.as_posix(),
        "            let mut stb = self.fido_state.borrow_mut();",
        "            let mut stb = self.fido_state.borrow_mut();\n"
        "            let mut hb = self.hooks.borrow_mut();",
    )
    tree.edit(
        f"{gate.CRATE}/src/pin.rs",
        "        self.panel.draw(entropy)",
        "        let _ = self.hooks.borrow_mut();\n        self.panel.draw(entropy)",
    )
    assert "`paint_pad`" in red(tree, capsys)


# --- the floors: every derivation can stop finding anything --------------------


def test_a_broken_dispatch_derivation_is_red(tree, capsys):
    """Not green. The handoff renamed, so the cells are whatever is left."""
    tree.edit(gate.DISPATCH.as_posix(), "rsk_fido::process_cbor(", "rsk_fido::dispatch_cbor(")
    assert "under the floor" in red(tree, capsys)


def test_a_broken_roots_derivation_is_red(tree, capsys):
    """The trait impl renamed: nothing is a root, so nothing can be reachable."""
    tree.edit(gate.HANDLE, "rsk_sdk::UserPresence for TouchPresence", "rsk_sdk::Presence for Touch")
    out = red(tree, capsys)
    assert "under the floor" in out and "collect_pin_titled" in out


def test_a_broken_call_walk_is_red(tree, capsys):
    """The edges stop resolving and the reach collapses onto the roots."""
    tree.edit(f"{gate.CRATE}/src/pin.rs", "impl Ui {", "impl Ui { // nothing below is walked")
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(gate, "CALLEE", gate.re.compile(r"\.\s*(zzz_no_such_name)\s*\("))
        assert "under the floor" in red(tree, capsys)


def test_a_broken_borrow_pattern_is_red(tree, capsys):
    """The intersection is empty for the wrong reason — the family this tree
    has shipped five guards with."""
    tree.edit(f"{gate.CRATE}/src/pin.rs", "let mut fs = self.fs.borrow_mut();\n        fs.delete(fid);", "")
    tree.edit(f"{gate.CRATE}/src/pin.rs", "        let mut rng = self.rng.borrow_mut();\n    }\n}", "    }\n}")
    assert "under the floor" in red(tree, capsys)


def test_an_unreadable_tree_is_red(tree, capsys):
    """A missing file is a failure to check, which is not a pass."""
    (tree.root / gate.HANDLE).unlink()
    assert "cannot be read" in red(tree, capsys)


def test_the_guard_refuses_arguments():
    """A row that grew an argument would otherwise run on a silently ignored one."""
    assert gate.main.__module__ == "display_borrow_gate"
    out = subprocess.run(
        ["python", str(ROOT / "scripts/display_borrow_gate.py"), "--all"],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 2
