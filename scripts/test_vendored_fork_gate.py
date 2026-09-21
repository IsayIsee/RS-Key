# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `vendored_fork_gate.py` was verified against, kept.

The guard exists because one vendored fork is wired into three manifests by hand
and nothing held the three together. So the table below unwires them in a fixture
checkout, one manifest at a time, and asserts the MESSAGE and its direction — a
red for the wrong reason proves as little as a green, and the two directions here
say opposite things: "that workspace resolves the crates.io copy" is the stanza
gone, "resolves `sequential-storage` from the registry" is the lock already
rewritten over it.

Every case goes through `Tree.edit`, which asserts its anchor resolved exactly
once. A `str.replace` that matches nothing leaves the fixture unpatched, and the
case then proves that a clean tree is clean — which is the first case's job.

Both directions, because a guard that cannot go green is deleted as fast as one
that cannot go red. Four fixtures must NOT move the answer: a workspace that does
not depend on the crate (`tools/tui`), a vendored directory that is not a crate
at all (the two pytest suites), an upstream lock shipped inside the vendored copy,
and prose added above every stanza.
"""

import pathlib
import subprocess

import pytest

import gate_lines
import vendored_fork_gate as gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The fork's own manifest: the crate NAME the derivation reads, and nothing that
#: says which directory it sits in.
VENDORED = """\
[package]
name = "sequential-storage"
version = "8.0.0"
edition = "2024"
"""

#: A lock as cargo writes one over a `[patch]`: no `source`, no `checksum`. The
#: registry crate beside it is what those two keys look like when they are there.
PATCHED_LOCK = """\
version = 4

[[package]]
name = "embedded-storage-async"
version = "0.4.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0e9f7c5b6b1b1f5b6dd3d0e9a7f2f7b1cbb9b8f9d1f3a5c7e9b1d3f5a7c9e1b3"

[[package]]
name = "sequential-storage"
version = "8.0.0"
dependencies = [
 "embedded-storage-async",
]
"""

#: The workspace that does not depend on the crate: no entry, no stanza, nothing
#: owed. It is the control the "every manifest must patch it" reading fails.
TUI_LOCK = """\
version = 4

[[package]]
name = "ratatui"
version = "0.30.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d3f"
"""


def manifest(name, patch_path):
    """A workspace manifest, with the stanza spelled from ITS own directory."""
    return f"""\
[package]
name = "{name}"
version = "0.1.0"
edition = "2024"

[dependencies]
sequential-storage = "8.0.0"

# One fork, three spellings of its path — which is why the guard resolves the
# path instead of comparing the string.
[patch.crates-io]
sequential-storage = {{ path = "{patch_path}" }}
"""


class Tree:
    """A checkout shaped like this one: one fork, four workspaces, one idle."""

    def __init__(self, root):
        self.root = root
        self.write("third_party/sequential-storage/Cargo.toml", VENDORED)
        self.write("third_party/sequential-storage/src/map.rs", "// the fork\n")
        self.write("third_party/sequential-storage.patch", "# item 2, item 3\n")
        # A vendored directory that is not a crate: it declares no `[package]`,
        # so nothing patches it and nothing is owed for it.
        self.write("third_party/pico-fido-tests/conftest.py", "# upstream's suite\n")
        self.write("Cargo.toml", manifest("rs-key", "third_party/sequential-storage"))
        self.write("Cargo.lock", PATCHED_LOCK)
        self.write("fuzz/Cargo.toml", manifest("fuzz", "../third_party/sequential-storage"))
        self.write("fuzz/Cargo.lock", PATCHED_LOCK)
        self.write("tools/emu/Cargo.toml", manifest("emu", "../../third_party/sequential-storage"))
        self.write("tools/emu/Cargo.lock", PATCHED_LOCK)
        self.write("tools/tui/Cargo.toml", "[package]\nname = \"tui\"\nversion = \"0.1.0\"\n")
        self.write("tools/tui/Cargo.lock", TUI_LOCK)
        # `forks` and `workspaces` ask git what the tree is, so the fixture must
        # be a checkout — and one that ignores build output, like the real one.
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
    assert gate_lines.runs(text, "scripts/vendored_fork_gate.py")


def test_the_summary_names_both_halves(tree, capsys):
    """A workspace dropping out of the linked half has to be visible in the line
    the row prints when it is happy, or the only signal is the red one."""
    said = summary(tree, capsys)
    assert "sequential-storage at third_party/sequential-storage" in said, said
    assert "linked by Cargo.toml, fuzz/Cargo.toml, tools/emu/Cargo.toml" in said, said
    assert "not depended on by tools/tui/Cargo.toml" in said, said


def test_a_control_mutant_stays_green(tree, capsys):
    """The control: the largest edit that must NOT move the answer.

    Prose above every stanza — the shape that shifts every line number in every
    manifest — plus a package appended to a lock. The summary is compared against
    the clean run rather than against a literal, so the case cannot pass by
    asserting something absent.
    """
    before = summary(tree, capsys)
    for rel in ("Cargo.toml", "fuzz/Cargo.toml", "tools/emu/Cargo.toml"):
        tree.edit(rel, "[patch.crates-io]", "# " + "\n# ".join(["why"] * 12) + "\n[patch.crates-io]")
    tree.edit("Cargo.lock", "version = 4\n", "version = 4\n\n[[package]]\nname = \"anyhow\"\nversion = \"1.0.100\"\n")
    assert summary(tree, capsys) == before


# --- the stanza gone, one manifest at a time ----------------------------------


def test_the_root_stanza_removed_is_rejected(tree, capsys):
    """The firmware's own workspace. Nothing else in the tree links this fork,
    so losing it here is the whole defect PLAT-STORE-001 names."""
    tree.edit("Cargo.toml", '[patch.crates-io]\nsequential-storage = { path = "third_party/sequential-storage" }\n', "")
    said = red(tree, capsys)
    assert "Cargo.toml depends on `sequential-storage` and carries no" in said, said
    assert "[patch.crates-io] entry" in said, said


def test_the_fuzz_stanza_removed_is_rejected(tree, capsys):
    """`fuzz/` is a detached workspace: it inherits no `[patch]` from the root,
    so the target that FOUND the torn-remove defect would run over the library
    that has it."""
    tree.edit("fuzz/Cargo.toml", 'sequential-storage = { path = "../third_party/sequential-storage" }\n', "")
    said = red(tree, capsys)
    assert "fuzz/Cargo.toml depends on `sequential-storage` and carries no" in said, said
    # …and the direction: the stanza, not the lock, and not the root's stanza.
    assert "from the registry" not in said, said
    assert "\n  Cargo.toml depends" not in said, said


def test_the_emu_stanza_removed_is_rejected(tree, capsys):
    """The emulator, and the one that HAS happened: without it the suites ran
    against a different store library from the device's."""
    tree.edit("tools/emu/Cargo.toml", 'sequential-storage = { path = "../../third_party/sequential-storage" }\n', "")
    said = red(tree, capsys)
    assert "tools/emu/Cargo.toml depends on `sequential-storage` and carries no" in said, said


def test_every_stanza_removed_names_every_workspace(tree, capsys):
    """All three at once: the report has to say which manifests, not that one of
    them is wrong. A message naming only the first is a repair done one third."""
    for rel, spelled in (
        ("Cargo.toml", "third_party/sequential-storage"),
        ("fuzz/Cargo.toml", "../third_party/sequential-storage"),
        ("tools/emu/Cargo.toml", "../../third_party/sequential-storage"),
    ):
        tree.edit(rel, f'sequential-storage = {{ path = "{spelled}" }}\n', "")
    said = red(tree, capsys)
    for rel in ("Cargo.toml", "fuzz/Cargo.toml", "tools/emu/Cargo.toml"):
        assert f"{rel} depends on `sequential-storage`" in said, said


# --- the lock, which is the half that cannot be talked round -------------------


def test_a_lock_resolved_from_the_registry_is_rejected(tree, capsys):
    """The stanza can stay exactly where it is: what a build LINKS is what the
    lock resolved, and a `source` plus a `checksum` is upstream 8.0.0."""
    tree.edit(
        "tools/emu/Cargo.lock",
        'name = "sequential-storage"\nversion = "8.0.0"\n',
        'name = "sequential-storage"\nversion = "8.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "aa1e3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d"\n',
    )
    said = red(tree, capsys)
    assert "tools/emu/Cargo.lock resolves `sequential-storage` 8.0.0 from the registry" in said, said
    assert "source, checksum" in said, said
    assert "builds upstream, not third_party/sequential-storage" in said, said


def test_a_lock_carrying_only_a_source_is_rejected(tree, capsys):
    """Either key alone, because either one alone says the same thing. A rule
    asking for both is satisfied by half a rewrite."""
    tree.edit(
        "Cargo.lock",
        'name = "sequential-storage"\nversion = "8.0.0"\n',
        'name = "sequential-storage"\nversion = "8.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
    )
    said = red(tree, capsys)
    assert "Cargo.lock resolves `sequential-storage` 8.0.0 from the registry" in said, said
    assert "it carries source, and" in said, said
    assert "source, checksum" not in said, said


def test_a_second_entry_of_the_same_name_is_read(tree, capsys):
    """Two versions resolve to two tables, and a reading keyed by name holds
    whichever came last while the other links the registry unread."""
    tree.edit(
        "Cargo.lock",
        'name = "sequential-storage"\nversion = "8.0.0"\n',
        'name = "sequential-storage"\nversion = "7.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "bb1e3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f3a5c7e9b1d"\n\n'
        '[[package]]\nname = "sequential-storage"\nversion = "8.0.0"\n',
    )
    said = red(tree, capsys)
    assert "resolves `sequential-storage` 7.0.0 from the registry" in said, said


# --- the path the stanza aims at ----------------------------------------------


def test_a_stanza_aimed_one_level_out_is_rejected(tree, capsys):
    """The way a stanza copied between manifests arrives: the path is relative to
    the workspace, and `fuzz/`'s `..` is one level the root's does not have."""
    tree.edit("Cargo.toml", 'path = "third_party/sequential-storage"', 'path = "../third_party/sequential-storage"')
    said = red(tree, capsys)
    assert "Cargo.toml patches `sequential-storage` to ../third_party/sequential-storage" in said, said
    assert "the vendored copy is third_party/sequential-storage" in said, said


def test_a_stanza_that_is_not_a_path_is_rejected(tree, capsys):
    """A `git` patch resolves to whatever that remote says today, which is not
    the file in this checkout the fork's repairs are in."""
    tree.edit(
        "fuzz/Cargo.toml",
        'sequential-storage = { path = "../third_party/sequential-storage" }',
        'sequential-storage = { git = "https://github.com/tweedegolf/sequential-storage" }',
    )
    said = red(tree, capsys)
    assert "fuzz/Cargo.toml patches `sequential-storage` with ['git']" in said, said
    assert "only a path reaches third_party/sequential-storage" in said, said


def test_a_stanza_written_as_a_version_string_is_rejected(tree, capsys):
    """`= "8.0.1"` is legal TOML and cargo refuses it. Read as a table it is a
    string to iterate the characters of, which reports the right finding under a
    message naming `['.', '0', '1', '8']` — a red nobody can act on."""
    tree.edit(
        "tools/emu/Cargo.toml",
        'sequential-storage = { path = "../../third_party/sequential-storage" }',
        'sequential-storage = "8.0.1"',
    )
    said = red(tree, capsys)
    assert "tools/emu/Cargo.toml patches `sequential-storage` with ['8.0.1']" in said, said


def test_one_crate_vendored_twice_is_rejected(tree, capsys):
    """Two directories declaring one `[package] name`: a `[patch]` path names one
    of them, and a derivation keyed by name would keep whichever came last while
    the other sat unbuilt and unmeasured."""
    tree.write("third_party/sequential-storage-old/Cargo.toml", VENDORED)
    said = red(tree, capsys)
    assert "`sequential-storage` is vendored twice" in said, said
    assert "third_party/sequential-storage and third_party/sequential-storage-old" in said, said


# --- the derivation itself -----------------------------------------------------


def test_a_fork_no_workspace_names_is_rejected(tree, capsys):
    """A crate vendored and linked by nothing: its repairs are in the tree and in
    no image. This is the arm a hardcoded `sequential-storage` would not have."""
    tree.write("third_party/critical-section/Cargo.toml", '[package]\nname = "critical-section"\nversion = "1.2.0"\n')
    said = red(tree, capsys)
    assert "third_party/critical-section vendors `critical-section`" in said, said
    assert "no workspace's Cargo.lock names it" in said, said


def test_the_crate_name_comes_from_its_own_manifest(tree, capsys):
    """Renaming the `[package]` and nothing else must move the derived name, so
    the fork reads as unlinked. The directory is unchanged, which is the whole
    point: what a `[patch]` key spells is the crate's name."""
    tree.edit("third_party/sequential-storage/Cargo.toml", 'name = "sequential-storage"', 'name = "seqstore"')
    said = red(tree, capsys)
    assert "third_party/sequential-storage vendors `seqstore`" in said, said


def test_a_vendored_directory_that_is_no_crate_is_not_a_fork(tree, capsys):
    """The control for the rule above: `third_party/` also holds two pytest
    suites and the generated font tables, and demanding a `[patch]` for those
    would be a red on directories that are right."""
    before = summary(tree, capsys)
    tree.write("third_party/ibm-plex/font_data.rs", "// generated\n")
    tree.write("third_party/openpgp-card-tests/card_const.py", "# upstream's suite\n")
    assert summary(tree, capsys) == before


def test_a_lock_inside_the_vendored_copy_is_not_a_workspace(tree, capsys):
    """Upstream ships its own lock, and it names its own crate. Read as one of
    this tree's workspaces it would demand that the fork patch itself."""
    before = summary(tree, capsys)
    tree.write("third_party/sequential-storage/Cargo.lock", PATCHED_LOCK)
    assert summary(tree, capsys) == before


def test_an_unreadable_manifest_is_reported_not_skipped(tree, capsys):
    """A manifest this cannot parse is a fork it cannot derive, and silence there
    is how a fork stops being checked without anyone deciding it."""
    tree.edit("third_party/sequential-storage/Cargo.toml", 'name = "sequential-storage"', 'name = "unterminated')
    said = red(tree, capsys)
    assert "third_party/sequential-storage/Cargo.toml cannot be read as TOML" in said, said


def test_the_fork_floor_refuses_an_empty_derivation(tree, capsys):
    """A finder that has stopped finding loops over nothing and exits 0."""
    (tree.root / "third_party/sequential-storage/Cargo.toml").unlink()
    said = red(tree, capsys)
    assert "no directory under third_party/ declares a `[package] name`" in said, said


def test_the_workspace_floor_refuses_a_single_lock(tree, capsys):
    """The same shape on the other derivation, and floored at two rather than one
    because the case this row is about is a DETACHED workspace."""
    for rel in ("fuzz/Cargo.lock", "tools/emu/Cargo.lock", "tools/tui/Cargo.lock"):
        (tree.root / rel).unlink()
    said = red(tree, capsys)
    assert f"the checkout has 1 Cargo.lock(s), under the floor of {gate.FLOOR_WORKSPACES}" in said, said


def test_a_workspace_that_does_not_depend_owes_nothing(tree, capsys):
    """The green control, and the reading that would break the tree: `tools/tui`
    has no entry and no stanza, and a rule demanding one from every workspace is
    a red on a manifest that is right. Driven by giving it a second sibling."""
    before = summary(tree, capsys)
    tree.write("tools/rescue/Cargo.toml", '[package]\nname = "rescue"\nversion = "0.1.0"\n')
    tree.write("tools/rescue/Cargo.lock", TUI_LOCK)
    said = summary(tree, capsys)
    assert said != before
    assert "not depended on by tools/rescue/Cargo.toml, tools/tui/Cargo.toml" in said, said
