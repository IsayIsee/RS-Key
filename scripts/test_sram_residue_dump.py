# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Where `tests/54_sram_residue.py` writes its dump when the caller does not say.

The default was `sram.bin` — relative — so a run left a 520 KiB image of main
SRAM, and the `.text`/`.pattern`/`.back` windows derived beside it, in whatever
directory it started from. For the recorded runs that was the repository root:
`spdx_gate.py` went red on four extensions it had never been told about, and that
redness was the small half. On a boot configuration that KEEPS SRAM the image
holds an unwrapped key, so the same default puts a secret one `git add -A` from a
public push. `.gitignore` carries the belt for an older checkout or an old command
line; these are the braces, and they hold the property the belt cannot: that a
plain invocation never names a path inside the checkout in the first place.
"""

import importlib.util
import os
import pathlib
import shutil
import stat
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "54_sram_residue.py"


def load():
    """The script as a module. Its name starts with a digit, so `import` cannot."""
    spec = importlib.util.spec_from_file_location("sram_residue", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = load()


def escapes_the_checkout(path):
    """Whether `path` is somewhere a `git add -A` in this checkout cannot reach.

    Absolute is not enough on its own: `target/` and `formal/out/` are ignored and
    still inside the tree, so a copy of the working directory — a tarball, an
    `rsync`, a tool that does not read `.gitignore` — carries the dump with it.
    """
    return os.path.isabs(path) and ROOT not in pathlib.Path(path).resolve().parents


def ignored(name):
    """Whether git would ignore `name` at the root of this checkout.

    128 is git failing rather than answering. Folded into `False` it would read
    as "not ignored", which is the direction that lets the not-a-blanket case
    below pass over a checkout where nothing was asked at all.
    """
    done = subprocess.run(["git", "check-ignore", "-q", name], cwd=ROOT)
    if done.returncode not in (0, 1):
        raise RuntimeError(f"git check-ignore said {done.returncode} for {name}")
    return done.returncode == 0


@pytest.fixture
def temps():
    """Collects the directories these cases make, and removes them.

    `check.sh` runs this file on every check, so a case that leaves its temp
    behind litters the developer's `TMPDIR` a few entries at a time — the same
    hygiene the subject is being fixed for. Only paths that pass the containment
    rule are removed, so a regression cannot turn this into a delete in the tree.
    """
    made = []
    yield made
    for path in made:
        if escapes_the_checkout(path):
            shutil.rmtree(pathlib.Path(path).parent, ignore_errors=True)


# --- the default ---------------------------------------------------------------

def test_the_default_escapes_the_checkout(temps):
    temps.append(made := mod.make_dump_path(None))
    assert escapes_the_checkout(made)


def test_the_predicate_rejects_every_default_this_one_replaced():
    """The arm. Each of these was a candidate; each must fail the rule above.

    `sram.bin` is what the default WAS. The two under the tree are the options
    weighed against it — an ignored directory is still inside the checkout, which
    is the whole reason the rule asks about containment and not about `.gitignore`.
    """
    assert not escapes_the_checkout("sram.bin")
    assert not escapes_the_checkout(str(ROOT / "sram.bin"))
    assert not escapes_the_checkout(str(ROOT / "target" / "sram.bin"))
    assert not escapes_the_checkout(str(ROOT / "formal" / "out" / "sram.bin"))


def test_the_default_directory_is_private(temps):
    """0700, because the system temp dir is world-readable and this may hold a key."""
    temps.append(made := mod.make_dump_path(None))
    assert stat.S_IMODE(pathlib.Path(made).parent.stat().st_mode) == 0o700


def test_each_default_is_a_fresh_directory(temps):
    """Two runs must not overwrite one another's evidence."""
    temps.append(first := mod.make_dump_path(None))
    temps.append(second := mod.make_dump_path(None))
    assert first != second


# --- and the caller's own path stays the caller's -------------------------------

def test_an_explicit_dump_is_honoured_verbatim():
    """Including a relative one: `--dump` is the caller saying where, and means it."""
    assert mod.make_dump_path("sram.bin") == "sram.bin"
    assert mod.make_dump_path("/var/tmp/mine.bin") == "/var/tmp/mine.bin"


def test_the_parser_carries_no_path_of_its_own():
    """The shape that made the old default land in the working directory."""
    assert mod.parse_args(["control"]).dump is None
    assert mod.parse_args(["residue"]).dump is None
    assert mod.parse_args(["control", "--dump", "x"]).dump == "x"


# --- the wiring, not the pieces -------------------------------------------------

def test_main_resolves_the_default_off_the_working_directory(monkeypatch, temps):
    """`main` is what turns an absent `--dump` into a path, so drive `main`."""
    seen = {}
    monkeypatch.setattr(mod, "cmd_control", lambda args: seen.update(dump=args.dump))
    monkeypatch.setattr(sys, "argv", ["54_sram_residue.py", "control"])
    monkeypatch.chdir(ROOT)  # the working directory the finding was measured from
    mod.main()
    temps.append(seen["dump"])
    assert escapes_the_checkout(seen["dump"])
    for window in (".text", ".pattern", ".back"):
        assert escapes_the_checkout(seen["dump"] + window)


def test_main_honours_an_explicit_dump(monkeypatch, tmp_path):
    """The other subcommand too — both share the parent that carries the flag."""
    seen, target = {}, tmp_path / "mine.bin"
    monkeypatch.setattr(mod, "cmd_residue", lambda args: seen.update(dump=args.dump))
    monkeypatch.setattr(sys, "argv",
                        ["54_sram_residue.py", "residue", "--dump", str(target)])
    mod.main()
    assert seen["dump"] == str(target)


# --- the belt -------------------------------------------------------------------

def test_the_old_default_is_ignored_at_the_root():
    """An older checkout, or a command line still spelling `--dump sram.bin`."""
    assert ignored("sram.bin")
    for window in (".text", ".pattern", ".back"):
        assert ignored("sram.bin" + window)


def test_the_belt_is_not_a_blanket():
    """It must not widen into files the tree deliberately leaves visible.

    A bare `*.bin` would have silenced `spdx_gate.py` for every future `.bin` as
    well, which is the guard that caught this in the first place.
    """
    assert not ignored("README.md")
    assert not ignored("AGENTS.md")
    assert not ignored("vectors.bin")
