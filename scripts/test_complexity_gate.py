# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `complexity_gate.sh` was carved out of a roster for lacking.

`test_gate_scripts.UNROSTERED` carved it out with the reason spelled: "a `run` row
with no mutation table. The `_gate.py` glob cannot see a `.sh` guard, which is the
blind spot `crate_graph.py` sat in wearing another suffix." A ratchet nothing
falsifies is the worst of the family — it prints a ranking on every run, so it
looks busy while the clause that could refuse a hotspot may not be wired at all.

Driven as a subprocess against the real script with a stand-in `nix` on PATH, the
way `test_kani_sh.py` drives `kani.sh` with a stub `cargo`: the mutations move the
ANALYSIS and the script under test is the one `check.sh` runs, down to its `find`,
its ceiling default and the real `metrics_complexity.py` behind it.

The ceiling is read out of the script rather than pinned here, so ratcheting it
down — which is the point of the row — moves the fixture with it.
"""

import os
import pathlib
import re
import subprocess

import pytest

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / "scripts/complexity_gate.sh"
RANKER = ROOT / "scripts/metrics_complexity.py"

#: The stand-in for `rust-code-analysis-cli`, reached exactly as the row reaches
#: it: `nix shell --inputs-from . nixpkgs#rust-code-analysis -c …`. It writes the
#: per-file JSON the real CLI writes (`<out>/<path>.rs.json`, a `unit` space whose
#: children are the functions) and records the `-p` list, which is the only way a
#: scope arm can tell "analysed and clean" from "never looked at".
#:
#: A fixture function is one line carrying the score the analyzer will report for
#: it — the SCOPE clauses are about which files it is pointed at, so the metrics
#: have to live where the files do.
NIX_STUB = '''\
#!/usr/bin/env python3
import json, os, pathlib, re, sys

argv = sys.argv[1:]
cmd = argv[argv.index("-c") + 1:]
out = pathlib.Path(cmd[cmd.index("-o") + 1])
paths = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-p"]
with open(os.environ["RCA_LOG"], "a") as log:
    log.write("\\n".join(paths) + "\\n")

# Nothing written on the way out: the realistic failure is `nix shell` never
# reaching the analyzer at all, and a half-written directory would be a
# different case than the one the arms below are about.
if int(os.environ.get("RCA_RC", "0")):
    raise SystemExit(int(os.environ["RCA_RC"]))

FN = re.compile(r"^fn (?P<name>\\w+)\\(\\) \\{\\}\\s*//\\s*cog=(?P<cog>\\d+)", re.M)
for path in paths:
    for src in sorted(pathlib.Path(path).rglob("*.rs")):
        spaces = [
            {
                "name": m["name"],
                "kind": "function",
                "start_line": src.read_text()[: m.start()].count("\\n") + 1,
                "spaces": [],
                "metrics": {
                    "cognitive": {"sum": float(m["cog"])},
                    "cyclomatic": {"sum": 1.0},
                    "loc": {"sloc": 1.0},
                    "nexits": {"sum": 0.0},
                },
            }
            for m in FN.finditer(src.read_text())
        ]
        dest = out / f"{src}.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps({"name": str(src), "kind": "unit", "spaces": spaces}))
raise SystemExit(int(os.environ.get("RCA_RC", "0")))
'''


#: The fixture's cool function, as a whole line: `cog=3` alone is a prefix of
#: the ceiling's own `cog=35`, and an anchor that matches two places is an
#: unproven mutation wearing a green tick.
HOTTEST = "fn cool_one() {} // cog=3"
#: Built rather than spelt, because `citation_gate` reads every `path:line`
#: in this file as a citation and would send a reader to a fixture crate.
HOT_FILE = "crates/rsk-a/src/lib.rs"


def ceiling():
    """The live ceiling, so a ratchet in `complexity_gate.sh` moves the fixture."""
    found = re.search(r'^COGNITIVE_CEILING="\$\{COGNITIVE_CEILING:-(\d+)\}"$',
                      GUARD.read_text(), re.M)
    assert found, "the ceiling's spelling moved"
    return int(found.group(1))


class Tree:
    """A checkout shaped like this one: crate libraries in scope, a firmware out
    of it, and one function sitting exactly ON the ceiling — which is where the
    tree this guards sits today, so the boundary is the case that matters."""

    def __init__(self, root):
        self.root = root
        self.write("crates/rsk-a/src/lib.rs",
                   f"fn cool_one() {{}} // cog=3\nfn at_the_ceiling() {{}} // cog={ceiling()}\n")
        self.write("crates/rsk-b/src/deep/mod.rs", "fn deep_one() {} // cog=5\n")
        self.write("firmware/src/main.rs", "fn hot_firmware() {} // cog=99\n")
        self.write("bin/nix", NIX_STUB)
        (root / "bin/nix").chmod(0o755)

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

    def run(self, *, cuts=(), ranker_cuts=(), rca_rc=0, env=None):
        """The row, as `check.sh` runs it, with the guard optionally cut.

        Each cut is (anchor, replacement) applied to the real source with the
        anchor asserted present, so a deletion arm whose anchor moved reads as a
        moved anchor rather than as a kill. `ranker_cuts` reaches the second half
        of the row: the ceiling comparison lives in `metrics_complexity.py`.
        """
        for rel, source, edits in (("scripts/complexity_gate.sh", GUARD, cuts),
                                   ("scripts/metrics_complexity.py", RANKER, ranker_cuts)):
            src = source.read_text()
            for old, new in edits:
                assert src.count(old) == 1, f"anchor moved: {old!r}"
                src = src.replace(old, new)
            self.write(rel, src)
        (self.root / "scripts/complexity_gate.sh").chmod(0o755)
        log = self.root / "rca.log"
        log.write_text("")
        return subprocess.run(
            [str(self.root / "scripts/complexity_gate.sh")],
            cwd=self.root,
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "PATH": f"{self.root / 'bin'}:{os.environ['PATH']}",
                "RCA_LOG": str(log),
                "RCA_RC": str(rca_rc),
                **(env or {}),
            },
        )

    def analysed(self):
        """The directories the analyzer was actually pointed at."""
        return sorted(p for p in (self.root / "rca.log").read_text().split("\n") if p)


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


# --- both directions, and the wiring ------------------------------------------


def test_the_clean_fixture_is_green_at_the_ceiling(tree):
    """The boundary the ratchet is written on: the peak IS the ceiling today, so
    `>` and `>=` are one commit apart and only this says which one shipped."""
    result = tree.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"OK: peak cognitive {ceiling()} <= ceiling {ceiling()}" in result.stdout


def test_check_sh_runs_the_row():
    """A guard nothing invokes can be deleted with the whole suite still green."""
    check = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(check, "scripts/complexity_gate.sh")


def test_one_function_over_the_ceiling_fails_the_row(tree):
    """The alarm itself: a new hotspot trips the row the moment it lands."""
    tree.edit("crates/rsk-a/src/lib.rs", HOTTEST, f"fn cool_one() {{}} // cog={ceiling() + 1}")
    result = tree.run()
    assert result.returncode == 1
    assert f"FAIL: 1 function(s) over the cognitive ceiling of {ceiling()}" in result.stdout
    assert "cool_one" in result.stdout
    assert f"{HOT_FILE}:1" in result.stdout


def test_the_ceiling_is_the_knob_the_environment_moves(tree):
    """`COGNITIVE_CEILING` is how deep-checks and a bisect drive the same script;
    a default that stopped being overridable is a ratchet that cannot be tested."""
    assert tree.run(env={"COGNITIVE_CEILING": "2"}).returncode == 1
    tree.edit("crates/rsk-a/src/lib.rs", HOTTEST, f"fn cool_one() {{}} // cog={ceiling() + 1}")
    assert tree.run(env={"COGNITIVE_CEILING": str(ceiling() + 1)}).returncode == 0


def test_a_source_deep_inside_a_crate_is_analysed(tree):
    """`-p crates/*/src` is a directory, and the analyzer walks it: a hotspot in a
    submodule is in scope like any other."""
    tree.edit("crates/rsk-b/src/deep/mod.rs", "cog=5", f"cog={ceiling() + 2}")
    result = tree.run()
    assert result.returncode == 1
    assert "deep_one" in result.stdout


def test_the_analyzer_failing_fails_the_row(tree):
    """`set -e`'s whole job here. The ranker would otherwise run over an empty
    directory and report a peak of 0, which is a green for having measured
    nothing — the shape four guards in this tree have shipped with."""
    result = tree.run(rca_rc=7)
    assert result.returncode == 7
    assert "OK: peak cognitive" not in result.stdout
    assert tree.analysed() == ["crates/rsk-a/src", "crates/rsk-b/src"]


# --- the controls: what the ratchet is right to be indifferent to --------------


def test_a_hotspot_in_the_firmware_is_out_of_scope(tree):
    """Stated in the script: `firmware/` is embedded glue plus the display state
    machines, whose reduction is a separate effort. The same function inside a
    crate goes red, so the green is the scope and not an analysis that stopped."""
    assert tree.run().returncode == 0
    assert tree.analysed() == ["crates/rsk-a/src", "crates/rsk-b/src"]
    tree.write("crates/rsk-a/src/board.rs", "fn hot_firmware() {} // cog=99\n")
    assert tree.run().returncode == 1


@pytest.mark.parametrize(
    "name", ["lib_tests.rs", "tests.rs", "kani.rs", "codec_kani.rs", "test_support.rs"]
)
def test_a_hotspot_in_a_test_or_proof_file_is_not_a_refactor_target(tree, name):
    """Every shape `is_test_or_proof` covers, because a table that drove one of
    them would leave the other four to rot. The same body in `lib.rs` is red."""
    tree.write(f"crates/rsk-a/src/{name}", "fn hot_fixture() {} // cog=99\n")
    assert tree.run().returncode == 0
    tree.write("crates/rsk-a/src/hot.rs", "fn hot_fixture() {} // cog=99\n")
    assert tree.run().returncode == 1


def test_a_src_below_the_crate_root_is_never_looked_at(tree):
    """Measured, not designed: `find crates -maxdepth 2` reaches `crates/*/src`
    and nothing deeper, so a crate laid out as `crates/x/nested/src` is invisible
    to the ratchet. No crate is laid out that way today; this is what it costs if
    one ever is."""
    tree.write("crates/rsk-b/nested/src/lib.rs", "fn hidden_hotspot() {} // cog=99\n")
    assert tree.run().returncode == 0
    assert tree.analysed() == ["crates/rsk-a/src", "crates/rsk-b/src"]


def test_an_analysis_of_nothing_is_green(tree):
    """The row's own hole, recorded rather than argued: there is no floor on how
    many functions were analysed, so a scope that stops matching passes as
    quietly as a clean tree. `docs_constants.py` grew `MIN_PAIRS` for exactly
    this shape after audit run-34 #9; this row has no equivalent.
    """
    for src in tree.root.glob("crates/*/src/**/*.rs"):
        src.unlink()
    result = tree.run()
    assert result.returncode == 0
    assert "functions analysed (non-test): 0" in result.stdout
    assert f"OK: peak cognitive 0 <= ceiling {ceiling()}" in result.stdout


# --- the deletion arms: one clause at a time ----------------------------------


def test_deleting_the_ceiling_flag_leaves_a_ranking_that_cannot_refuse(tree):
    """The clause the row IS. Cut, the hotspot still prints in the top-25 — the
    output looks like a gate that ran — and the row is green."""
    tree.edit("crates/rsk-a/src/lib.rs", HOTTEST, f"fn cool_one() {{}} // cog={ceiling() + 1}")
    assert tree.run().returncode == 1
    result = tree.run(cuts=[(' --max-cognitive "$COGNITIVE_CEILING"', "")])
    assert result.returncode == 0
    assert "cool_one" in result.stdout
    assert "over the cognitive ceiling" not in result.stdout


def test_deleting_the_errexit_turns_a_broken_analyzer_into_a_green_row(tree):
    """What `set -euo pipefail` is worth here, in the one motion that hides a
    failure: the ranker runs on the empty output directory and reports peak 0."""
    assert tree.run(rca_rc=7).returncode == 7
    result = tree.run(rca_rc=7, cuts=[("set -euo pipefail\n", "")])
    assert result.returncode == 0
    assert "OK: peak cognitive 0" in result.stdout


def test_deleting_the_crate_scope_takes_every_finding_with_it(tree):
    """The scope is a clause, not a detail: pointed elsewhere, the hotspot above
    is never analysed and the row is green having measured the tree the comment
    says is deliberately out of scope.

    The firmware fixture is cooled first, and that is the whole discipline: the
    arm went red on its first run for the OTHER hotspot, which would have read as
    a kill for a clause it says nothing about.
    """
    tree.edit("crates/rsk-a/src/lib.rs", HOTTEST, f"fn cool_one() {{}} // cog={ceiling() + 1}")
    tree.edit("firmware/src/main.rs", "cog=99", "cog=1")
    assert tree.run().returncode == 1
    result = tree.run(cuts=[("find crates -maxdepth 2", "find firmware -maxdepth 2")])
    assert result.returncode == 0
    assert tree.analysed() == ["firmware/src"]
    assert result.stdout.count("cool_one") == 0


def test_deleting_the_test_file_exclusion_makes_a_fixture_a_hotspot(tree):
    """The half of the row that lives in `metrics_complexity.py`. Cut, the control
    above goes red on a proof harness — which is how a correct ratchet gets
    'repaired' by raising the ceiling for a function nobody ships."""
    tree.write("crates/rsk-a/src/lib_tests.rs", "fn hot_fixture() {} // cog=99\n")
    assert tree.run().returncode == 0
    cut = [('code = [f for f in funcs if not is_test_or_proof(f["file"])]', "code = funcs")]
    result = tree.run(ranker_cuts=cut)
    assert result.returncode == 1
    assert "hot_fixture" in result.stdout
