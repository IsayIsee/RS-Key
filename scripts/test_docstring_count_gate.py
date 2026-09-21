# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `docstring_count_gate.py`, driven as a PROCESS.

Every case here runs the script and reads its exit code, because that is what
`check.sh` reads and because fourteen of thirty gates in this tree were measured
printing a finding and exiting 0. Nothing below calls `audit()` and inspects a
list.

The three reds are historical, not invented: each fixture is a real file at the
commit it carried the defect, reconstructed with `git show`. A rule that cannot
redden all three is not this rule, so they are the acceptance case rather than
an illustration.

The removal arms come in two directions and the difference is the point. No
clause below is needed to redden the three historical files — the bare
`count == items` does that on its own — so the arm that matters for each is the
other one: delete the clause and the CLEAN TREE goes red, or a block the tree
really contains stops being counted at all. A clause with neither arm would be a
comment with a type, and the intro-colon clause became one the moment the
`run_count_gate.py` miscount it was hiding was repaired: deleting it now reddens
nothing and keeping it costs two counted lists, so it is dropped rather than
tabled.
"""

from __future__ import annotations

import importlib.util
import pathlib
import shutil
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
GATE = HERE / "docstring_count_gate.py"

#: The three defects, as `(commit, script)`. Each shipped a spelled count over
#: the wrong number of bullets and each was found by hand on a different day.
HISTORICAL = (
    ("b819ee5", "platform_gate.py", "Seven rules"),
    ("9f49100", "threat_gate.py", "Three rules"),
    ("c4fb4ae", "elf_gate.py", "Two facts"),
)

#: The clauses, as the exact text one deletion takes out. Anchored on the source
#: so a rewrite that moves a clause breaks the table instead of silently taking
#: its arm with it.
PLURAL_GUARD = (
    '        if len(noun) < 3 or not noun.lower().endswith("s") or noun.lower().endswith(NOT_PLURAL):\n'
    "            return None  # a cardinal over a singular is a pronoun, not a count\n"
)
ANAPHORA_GUARD = (
    '        if before_word in DEFINITE and re.search(rf"\\b{re.escape(noun)}\\b", before, re.IGNORECASE):\n'
    '            return None  # "the N Xs" resuming an X above is a back-reference\n'
)
BLANK_RESUME = """        after = here + 1
        while after < len(lines) and not lines[after].strip():
            after += 1
        if after >= len(lines):
            break
        resumes = BULLET.match(lines[after])
        deeper = len(lines[after]) - len(lines[after].lstrip()) > indent
        if (resumes and len(resumes.group(1)) == indent) or deeper:
            here = after
        else:
            break"""

#: Each clause's removal, and the block in the real tree that stops being right
#: when it goes. Five of the six redden `scripts/` outright; the sixth is the
#: wrapped intro, which goes blind instead and has its own case below.
REDDENS_THE_TREE = {
    "first-cardinal-or-none": (
        "return None  # a cardinal over a singular is a pronoun, not a count",
        "continue",
        "test_gate_scripts.py",
    ),
    "plural-noun": (PLURAL_GUARD, "", "claims_gate.py"),
    "not-a-back-reference": (ANAPHORA_GUARD, "", "ct_gate.py"),
    "items-not-bullets": (
        "items = sum(names(BULLET.match(lines[at]).group(2)) for at in indices)",
        "items = len(indices)",
        "comutate.py",
    ),
    "blank-tolerant-block": (BLANK_RESUME, "        break", "comutate.py"),
}

#: The wrapped-intro clause and the read-on half of the first-cardinal one.
#: Neither reddens `scripts/` when deleted, so each is driven on ONE constructed
#: docstring of a shape the tree really carries, with the exit code it gets WITH
#: the clause and the one it gets without. The two must differ; which way round
#: they differ is the clause: the wrapped one goes from a caught miscount to a
#: block nobody reads, the back-reference one from a skip to a false red.
DECIDES_A_FIXTURE = {
    "wrapped-intro": (
        "while start > 0 and lines[start - 1].strip() and not BULLET.match(lines[start - 1]):",
        "while False:",
        '"""Rust cannot read the model. Three\nnumbers have to agree here:\n\n* one\n* two\n"""\n',
        (1, 0),
    ),
    "back-reference-stops-the-scan": (
        'return None  # "the N Xs" resuming an X above is a back-reference',
        "continue",
        '"""Two rules were named above.\n\nThis holds the two rules already named, in three ways:\n\n* one\n* two\n"""\n',
        (0, 1),
    ),
}


def tree(tmp_path, files):
    """A git checkout, because the corpus is `git ls-files` and not a walk."""
    root = tmp_path / "tree"
    (root / "scripts").mkdir(parents=True)
    for name, body in files.items():
        (root / name).write_text(body)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fixture"],
        cwd=root,
        check=True,
    )
    return root


def drive(root, gate=GATE):
    """Run the row the way `check.sh` does and hand back what it read."""
    done = subprocess.run(
        [sys.executable, str(gate), str(root)], capture_output=True, text=True
    )
    return done.returncode, done.stdout + done.stderr


def mutant(tmp_path, name, old, new):
    """A copy of the gate with one clause taken out, runnable as a process."""
    where = tmp_path / "mutant" / name
    where.mkdir(parents=True)
    source = GATE.read_text()
    assert old in source, f"the {name} anchor is no longer in the gate"
    (where / GATE.name).write_text(source.replace(old, new, 1))
    shutil.copy(HERE / "gate_lines.py", where / "gate_lines.py")
    return where / GATE.name


def historical(tmp_path, commit, script):
    """The defect as it really shipped, checked out of history."""
    body = subprocess.run(
        ["git", "show", f"{commit}:scripts/{script}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return tree(tmp_path, {f"scripts/{script}": body})


def test_the_tree_it_guards_is_green():
    """The row as `check.sh` runs it. Everything below is an arm off this."""
    code, said = drive(ROOT)
    assert code == 0, said
    assert "spelled list counts hold" in said


@pytest.mark.parametrize("commit,script,word", HISTORICAL)
def test_a_historical_miscount_reddens_the_row(tmp_path, commit, script, word):
    """The acceptance case: three real defects, three real reds, three exit 1s."""
    code, said = drive(historical(tmp_path, commit, script))
    assert code == 1, said
    assert word in said, said
    assert script in said, said


def test_the_corpus_is_not_empty():
    """A glob that matches nothing loops over nothing and exits 0 on anything."""
    import docstring_count_gate

    assert len(docstring_count_gate.corpus(ROOT)) >= 90
    counted = [b for b in docstring_count_gate.survey(ROOT) if b[5] is not None]
    assert len(counted) >= 18, counted


@pytest.mark.parametrize("clause", sorted(REDDENS_THE_TREE))
def test_removing_a_clause_reddens_the_tree(tmp_path, clause):
    """Delete the clause alone; the checkout it is green over goes red.

    This is the direction that matters here. None of these clauses is what
    reddens the three historical files — the bare comparison does that — so a
    clause surviving THIS arm would be decorative and would be dropped.
    """
    old, new, blames = REDDENS_THE_TREE[clause]
    code, said = drive(ROOT, mutant(tmp_path, clause, old, new))
    assert code == 1, f"{clause} survived its own deletion: {said}"
    assert blames in said, said


@pytest.mark.parametrize("clause", sorted(REDDENS_THE_TREE))
def test_no_clause_is_what_reddens_the_history(tmp_path, clause):
    """The other direction, stated rather than assumed.

    A reader who sees only the case above could take these clauses for the thing
    that catches the defect. They are not: with any one of them gone all three
    historical files still exit 1, and what would take that away is the
    comparison itself, which the case below removes.
    """
    old, new, _ = REDDENS_THE_TREE[clause]
    gate = mutant(tmp_path, f"{clause}-history", old, new)
    for index, (commit, script, _word) in enumerate(HISTORICAL):
        code, said = drive(historical(tmp_path / f"h{index}", commit, script), gate)
        assert code == 1, f"{clause} removed took {script} green: {said}"


def test_the_comparison_is_what_catches_them(tmp_path):
    """The red-bearing arm: neuter `count == items` and all three go green."""
    gate = mutant(
        tmp_path, "core", "if stated is None or stated[1] == items:", "if True:"
    )
    for index, (commit, script, _word) in enumerate(HISTORICAL):
        code, said = drive(historical(tmp_path / f"c{index}", commit, script), gate)
        assert code == 0, f"{script} still red with the comparison gone: {said}"


@pytest.mark.parametrize("clause", sorted(DECIDES_A_FIXTURE))
def test_a_silent_clause_still_has_an_arm(tmp_path, clause):
    """The two clauses today's tree does not exercise, driven on their own shape.

    Neither reddens `scripts/` when deleted — the wrapped one goes BLIND instead,
    and the read-on one meets no docstring carrying a second cardinal behind a
    back reference. Silent is not the same as inert, and this is the difference:
    one docstring, the verdict WITH the clause and the verdict without it, and
    they are not the same verdict.
    """
    old, new, body, (kept, gone) = DECIDES_A_FIXTURE[clause]
    root = tree(tmp_path, {"scripts/subject.py": body})
    code, said = drive(root)
    assert code == kept, f"{clause}: the gate itself read this wrong: {said}"
    code, said = drive(root, mutant(tmp_path, clause, old, new))
    assert code == gone, f"{clause} survived its own deletion: {said}"
    assert kept != gone


def test_the_wrapped_counts_are_read_and_not_skipped(tmp_path):
    """Control: two docstrings whose count sits on the line ABOVE the colon.

    Green, and not green by being invisible — the same clause removed leaves both
    uncounted, which is what this asserts by the total it prints.
    """
    import docstring_count_gate

    counted = {
        b[0].name: b[5]
        for b in docstring_count_gate.survey(ROOT)
        if b[5] is not None
    }
    assert counted["transport_bridge_gate.py"] == ("Three", 3, "numbers")
    assert counted["token_refinement_gate.py"] == ("four", 4, "causes")

    old, new, _body, _codes = DECIDES_A_FIXTURE["wrapped-intro"]
    blind = mutant(tmp_path, "wrapped-total", old, new)
    code, said = drive(ROOT, blind)
    assert code == 0, said  # green, and that is the finding: it went blind
    spec = importlib.util.spec_from_file_location("blind_gate", blind)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(blind.parent))
    try:
        spec.loader.exec_module(module)
        still = {b[0].name for b in module.survey(ROOT) if b[5] is not None}
    finally:
        sys.path.remove(str(blind.parent))
    assert "transport_bridge_gate.py" not in still
    assert "token_refinement_gate.py" not in still
    assert len(still) < len(counted)


def test_a_count_of_things_over_fewer_bullets_is_green():
    """Control: `comutate.py` says THREE families over TWO bullets and is right.

    The first bullet leads with two globs joined by "and". Derived from what the
    bullet says, so no file is exempted by name — which is the carve-out this
    tree keeps finding switched off.
    """
    import docstring_count_gate

    block = [
        b
        for b in docstring_count_gate.survey(ROOT)
        if b[0].name == "comutate.py" and b[5] and b[5][2] == "families"
    ]
    assert len(block) == 1, block
    _rel, _line, _sentence, bullets, items, stated = block[0]
    assert (bullets, items, stated[1]) == (2, 3, 3)


def test_a_colon_with_no_list_under_it_is_not_a_block(tmp_path):
    """Control: prose that ends in a colon and never lists anything.

    Green because nothing matches, and the pair below says so out loud: the same
    text with a list under it is read, and read wrongly on purpose.
    """
    prose = '"""Three rules, and the third is why this file exists:\n\nThey are written out in the page instead.\n"""\n'
    code, said = drive(tree(tmp_path / "prose", {"scripts/subject.py": prose}))
    assert code == 0, said
    assert "0 spelled list counts" in said, said

    listed = prose.replace("They are written out in the page instead.", "* only one\n")
    code, said = drive(tree(tmp_path / "listed", {"scripts/subject.py": listed}))
    assert code == 1, said


def test_a_digit_count_is_not_read(tmp_path):
    """The stated hole, so it is a decision and not an oversight.

    No block in the corpus writes its count in digits, so there is nothing to
    measure a rule for and none is written. This records which way that cuts.
    """
    body = '"""2 rules, and the second is why:\n\n* one\n* two\n* three\n"""\n'
    code, said = drive(tree(tmp_path, {"scripts/subject.py": body}))
    assert code == 0, said
