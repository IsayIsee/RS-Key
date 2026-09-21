# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `rollback_marker_gate.py` was verified against, kept.

The defect shape the guard exists for is a marker that is invisible when it is
wrong: an HTML comment renders as nothing whether or not a flasher can parse it,
so a misspelling in the CHANGELOG, a drifted grep in the workflow, and a doc
example the parser would reject all look identical to a reader — and all three
only surface on a release, after the tag is pushed.

So each case below breaks one of those in a fixture checkout, one at a time, and
asserts the MESSAGE rather than a count. A red for the wrong reason proves as
little as a green: this tree has measured 2 of 24 co-refutation kills firing on
the inverse defect.

Both directions, because a guard that cannot go green is deleted as fast as one
that cannot go red: the clean fixture passes, this checkout's own files pass,
`check.sh` is asserted to run the row, and [`test_a_control_mutant_stays_green`]
rewrites the fixture in the largest way that must NOT move the verdict — so the
table is shown to measure the marker rather than the spelling of the files it
lives in.
"""

import os
import pathlib
import re
import subprocess
import textwrap

import pytest

import gate_lines
import rollback_marker_gate as gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

CHANGELOG = """\
# Changelog

## [Unreleased]

### Fixed

- Something not worth a floor step.

## [0.9.0] - 2026-09-01

### Security

- A downgrade-exploitable bug, closed.

<!-- @increase-anti-rollback-epoch{"reason": "CVE-1234 was fixed"} -->

## [0.8.0] - 2026-08-01

### Added

- A feature.
"""

WORKFLOW = """\
name: release-build
jobs:
  build:
    steps:
      - name: extract release notes from CHANGELOG
        run: |
          awk -v v="$ver" '/^## \\[/ { print }' CHANGELOG.md > release-notes-full.md
          cp release-notes-full.md release-notes.md
          marker="$(grep -oE '<!-- @increase-anti-rollback-epoch([^>]*)-->' release-notes-full.md | head -n1 || true)"
          if [ -n "$marker" ] && ! grep -qF "$marker" release-notes.md; then
            printf '\\n%s\\n' "$marker" >> release-notes.md
          fi
"""

DOCS = """\
# Anti-rollback

#### The marker a tool can read

A downgrade-fix release carries an HTML comment in its release body — bare:

```text
<!-- @increase-anti-rollback-epoch -->
```

or with an optional JSON object whose `reason` is one sentence for the owner:

```text
<!-- @increase-anti-rollback-epoch{"reason": "CVE-1234 was fixed"} -->
```

A release without the marker is not a downgrade-fix.

```sh
rsk secure-boot status
```
"""


class Tree:
    """A checkout shaped like this one: the three files the marker lives in."""

    def __init__(self, root):
        self.root = root
        self.write(gate.CHANGELOG, CHANGELOG)
        self.write(gate.WORKFLOW, WORKFLOW)
        self.write(gate.DOCS, DOCS)

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
        return gate.audit(self.root)


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def only(errors):
    """The one complaint a case expects, so a second one is not swallowed."""
    assert len(errors) == 1, errors
    return errors[0]


def test_a_clean_fixture_passes(tree):
    assert tree.run() == []


def test_this_checkout_passes():
    """The row's real subject, not only the fixture."""
    assert gate.audit(ROOT) == []


def test_check_sh_runs_the_row():
    """A guard nothing invokes can be deleted with the suite green."""
    assert gate_lines.runs(
        (ROOT / "scripts/check.sh").read_text(), "scripts/rollback_marker_gate.py"
    )


# --- the CHANGELOG copy ------------------------------------------------------


def test_a_misspelled_marker_is_reported_not_skipped(tree):
    tree.edit(gate.CHANGELOG, "@increase-anti-rollback-epoch{", "@increase-anti-rollback-epochs{")
    assert "names the marker but is not one" in only(tree.run())


def test_a_space_before_the_metadata_is_reported(tree):
    """What a careful person writes by accident, and what no tool then reads."""
    tree.edit(gate.CHANGELOG, "epoch{\"reason\"", "epoch {\"reason\"")
    assert "names the marker but is not one" in only(tree.run())


def test_malformed_json_is_reported(tree):
    tree.edit(gate.CHANGELOG, '{"reason": "CVE-1234 was fixed"}', '{"reason": "CVE-1234 was fixed"')
    assert "names the marker but is not one" in only(tree.run())


def test_json_that_parses_but_is_not_an_object_is_reported(tree):
    tree.edit(gate.CHANGELOG, '{"reason": "CVE-1234 was fixed"}', '{}')
    tree.edit(gate.CHANGELOG, "<!-- @increase-anti-rollback-epoch{} -->", '<!-- @increase-anti-rollback-epoch{"reason": 1} -->')
    assert "non-empty string" in only(tree.run())


def test_an_unknown_metadata_key_is_reported(tree):
    tree.edit(gate.CHANGELOG, '{"reason": "CVE-1234 was fixed"}', '{"epoch": 3}')
    assert "unknown metadata key" in only(tree.run())


def test_an_empty_reason_is_reported(tree):
    tree.edit(gate.CHANGELOG, '"CVE-1234 was fixed"', '"   "')
    assert "non-empty string" in only(tree.run())


def test_two_markers_in_one_section_are_reported(tree):
    tree.edit(
        gate.CHANGELOG,
        "<!-- @increase-anti-rollback-epoch{\"reason\": \"CVE-1234 was fixed\"} -->",
        "<!-- @increase-anti-rollback-epoch -->\n<!-- @increase-anti-rollback-epoch -->",
    )
    assert "2 markers in one section" in only(tree.run())


def test_a_marker_in_a_second_section_is_not_a_duplicate(tree):
    """Per section, not per file — every release may flag itself."""
    tree.edit(gate.CHANGELOG, "- A feature.", "- A feature.\n\n<!-- @increase-anti-rollback-epoch -->")
    assert tree.run() == []


def test_a_backticked_example_is_reported(tree):
    """The mistake the entry introducing the marker made: the release step greps
    the section as text, so an example written to explain the format flags
    whatever release it sits in."""
    tree.edit(
        gate.CHANGELOG,
        "- Something not worth a floor step.",
        "- The marker is `<!-- @increase-anti-rollback-epoch -->`, for reference.",
    )
    assert "quoted as an example" in only(tree.run())


def test_a_backticked_near_miss_is_reported_too(tree):
    """`MENTION` and `MARKER` both miss a doubled-backtick span; the rule is about
    the NAME appearing quoted at all, since grep sees the whole line either way."""
    tree.edit(
        gate.CHANGELOG,
        "- Something not worth a floor step.",
        "- Named ``@increase-anti-rollback-epoch`` in the docs.",
    )
    assert "quoted as an example" in only(tree.run())


def test_naming_the_marker_in_prose_is_fine(tree):
    """The way an entry is supposed to refer to it: the name, not the spelling."""
    tree.edit(
        gate.CHANGELOG,
        "- Something not worth a floor step.",
        "- The anti-rollback marker is documented in docs/anti-rollback.md.",
    )
    assert tree.run() == []


def test_no_marker_at_all_is_fine(tree):
    """Absence is the answer for a release that is not a downgrade-fix."""
    tree.edit(gate.CHANGELOG, '\n<!-- @increase-anti-rollback-epoch{"reason": "CVE-1234 was fixed"} -->\n', "")
    assert tree.run() == []


# --- the workflow copy -------------------------------------------------------


def test_a_workflow_that_lost_the_marker_is_reported(tree):
    tree.edit(gate.WORKFLOW, "@increase-anti-rollback-epoch", "@increase-anti-rollback-era")
    assert "does not mention" in only(tree.run())


def test_a_grep_over_the_shortened_notes_is_reported(tree):
    """The shortening path cuts entries; a marker lifted after it is lost exactly
    when the section is long, which is when a release most needs one."""
    tree.edit(gate.WORKFLOW, "cp release-notes-full.md release-notes.md", "true")
    tree.edit(gate.WORKFLOW, "awk -v v=\"$ver\" '/^## \\[/ { print }' CHANGELOG.md > release-notes-full.md", "awk '{ print }' CHANGELOG.md > release-notes.md")
    tree.edit(gate.WORKFLOW, "release-notes-full.md | head", "release-notes.md | head")
    assert "full section" in only(tree.run())


def test_a_pattern_that_does_not_bracket_the_comment_is_reported(tree):
    """`grep -oE '@increase-anti-rollback-epoch'` matches the NAME and emits a
    string no flasher can parse back."""
    tree.edit(
        gate.WORKFLOW,
        "'<!-- @increase-anti-rollback-epoch([^>]*)-->'",
        "'@increase-anti-rollback-epoch'",
    )
    assert "does not bracket the marker" in only(tree.run())


def test_a_workflow_that_names_it_but_greps_nothing_is_reported(tree):
    tree.edit(gate.WORKFLOW, "marker=\"$(grep -oE", "marker=\"$(sed -n")
    assert "nothing greps for it" in only(tree.run())


# --- the docs copy -----------------------------------------------------------


def test_a_docs_example_the_parser_rejects_is_reported(tree):
    tree.edit(gate.DOCS, "<!-- @increase-anti-rollback-epoch -->", "<!-- increase-anti-rollback-epoch -->")
    assert "no example of the bare marker" in only(tree.run())


def test_a_docs_example_with_a_bad_reason_is_reported(tree):
    tree.edit(gate.DOCS, '{"reason": "CVE-1234 was fixed"}', '{"reason": true}')
    assert "non-empty string" in only(tree.run())


def test_docs_showing_only_the_bare_form_are_reported(tree):
    tree.edit(gate.DOCS, '<!-- @increase-anti-rollback-epoch{"reason": "CVE-1234 was fixed"} -->', "rsk otp rollback-require")
    assert "no example of the marker carrying a reason" in only(tree.run())


def test_docs_showing_only_the_metadata_form_are_reported(tree):
    tree.edit(gate.DOCS, "```text\n<!-- @increase-anti-rollback-epoch -->\n```", "nothing shown")
    assert "no example of the bare marker" in only(tree.run())


def test_docs_that_only_describe_the_marker_are_reported(tree):
    """Prose is not a spelling; the fenced example is what gets copied."""
    tree.edit(gate.DOCS, "```text\n<!-- @increase-anti-rollback-epoch -->\n```", "the bare marker")
    tree.edit(gate.DOCS, '```text\n<!-- @increase-anti-rollback-epoch{"reason": "CVE-1234 was fixed"} -->\n```', "the marker with a reason")
    assert "shows no marker example" in only(tree.run())


def test_a_control_mutant_stays_green(tree):
    """The largest edit that must not move the verdict: rewrite every file's
    prose, headings and unrelated commands, leaving only the markers standing."""
    tree.edit(gate.CHANGELOG, "- A downgrade-exploitable bug, closed.", "- Wording nobody parses.")
    tree.edit(gate.CHANGELOG, "## [0.9.0] - 2026-09-01", "## [1.2.3] - 2027-01-01")
    tree.edit(gate.WORKFLOW, "name: release-build", "name: something-else")
    tree.edit(gate.DOCS, "# Anti-rollback", "# A page by another name")
    tree.edit(gate.DOCS, "rsk secure-boot status", "rsk status")
    assert tree.run() == []


# --- the mechanism itself, not only its three copies -------------------------


def notes_step():
    """The `run:` body of the release job's notes step, dedented, with GitHub's
    `${{ … }}` expressions filled in — so what is executed below is the shell the
    release actually runs and not a paraphrase of it."""
    text = (ROOT / gate.WORKFLOW).read_text()
    body = re.search(
        r"- name: extract release notes from CHANGELOG\n\s+run: \|\n(.*?)(?=\n      - name:)",
        text,
        re.S,
    )
    assert body, "the notes step is no longer spelled the way this case finds it"
    script = textwrap.dedent(body.group(1))
    # Every `${{ … }}` becomes the same stand-in, the version among them: the step
    # assigns `ver` from one of these, and awk looks the section up by it.
    return re.sub(r"\$\{\{[^}]*\}\}", "9.9.9", script)


def run_notes_step(tmp_path, changelog):
    (tmp_path / "CHANGELOG.md").write_text(changelog)
    done = subprocess.run(
        ["sh", "-e", "-c", notes_step()],
        cwd=tmp_path,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    return (tmp_path / "release-notes.md").read_text()


MARKED = "<!-- @increase-anti-rollback-epoch{\"reason\": \"CVE-1234 was fixed\"} -->"


def section(entries, marker=""):
    return (
        "# Changelog\n\n## [9.9.9] - 2026-09-01\n\n### Security\n\n"
        + entries
        + ("\n" + marker + "\n" if marker else "")
        + "\n## [9.9.8] - 2026-08-01\n\n- older\n"
    )


def test_the_release_step_carries_a_marker_into_the_body(tmp_path):
    assert MARKED in run_notes_step(tmp_path, section("- **A fix.**\n", MARKED))


def test_the_release_step_adds_no_marker_when_the_section_has_none(tmp_path):
    assert "@increase-anti-rollback-epoch" not in run_notes_step(tmp_path, section("- **A fix.**\n"))


def test_the_release_step_writes_the_marker_once(tmp_path):
    """It is re-appended only when the shortening path dropped it; a section that
    kept its own must not end up carrying two."""
    assert run_notes_step(tmp_path, section("- **A fix.**\n", MARKED)).count(MARKED) == 1


def test_the_marker_survives_the_shortening_path(tmp_path):
    """The reason it is lifted out of the FULL section at all: over GitHub's body
    limit the notes are cut back to the TL;DR, which is where a marker written at
    the end of a long section disappears."""
    long_section = "### TL;DR\n\nA big release.\n\n### Security\n\n" + (
        "- **An entry.** " + "x" * 200 + "\n"
    ) * 700
    body = run_notes_step(tmp_path, section(long_section, MARKED))
    assert "Shortened to fit" in body, "the fixture must be over the limit for this to mean anything"
    assert MARKED in body
