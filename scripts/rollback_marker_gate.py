#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold the anti-rollback release marker to ONE definition.

`docs/anti-rollback.md` says the project's whole job is to flag which releases
fix a downgrade-exploitable bug; the owner decides whether to burn a floor step.
Issue #100 asked for that flag in a form a flasher can read, so a downgrade-fix
release carries an HTML comment in its body:

    <!-- @increase-anti-rollback-epoch -->
    <!-- @increase-anti-rollback-epoch{"reason": "CVE-1234 was fixed"} -->

Four files then know that spelling: this one, `CHANGELOG.md` where a release
writes its own, the shell in `.github/workflows/release-build.yml` that lifts the
marker out of the section, and the page that documents it for the tools reading
it. **That is the rot.** A marker is invisible when it is wrong — it renders as
nothing in Markdown either way — so a typo in the CHANGELOG, a drifted regex in
the workflow, or a doc example the tool would reject all fail exactly the same
way: silently, on a release, after the tag is pushed.

So [`MARKER`] below is the definition, and the other three are held to it:

1. **[`MARKER`] is the parser.** Every marker in `CHANGELOG.md` is parsed by it,
   and a comment that merely *looks* like one — the name misspelled, the JSON
   malformed, a `reason` that is not a string — is reported rather than skipped.
   A near-miss is the failure this exists to catch; skipping it would make the
   gate agree with the flasher about nothing.
2. **The workflow's copy must be the same pattern**, matched out of the YAML
   rather than re-derived from prose about it. The workflow greps with ERE and
   this file uses Python `re`; the shared subset is the literal name plus the
   comment delimiters, which is what is compared.
3. **Every example in the docs must parse.** A page that shows a spelling the
   parser rejects is worse than no page: it is a spelling somebody will copy.

Scope, deliberately: this says nothing about *whether* a release should carry the
marker. That is a security judgement about the entries in the section, and no
gate can make it. What it can say is that a marker somebody wrote is one a tool
will read, and that all three copies agree on what one looks like.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The three files, relative to a checkout root. Passed around rather than
#: resolved at import, so the mutation table can point the whole gate at a
#: fixture tree instead of at this one.
CHANGELOG = "CHANGELOG.md"
WORKFLOW = ".github/workflows/release-build.yml"
DOCS = "docs/anti-rollback.md"

#: The marker's name. Exact, and the one string every copy below is compared on.
NAME = "@increase-anti-rollback-epoch"

#: A well-formed marker — EXACTLY the two spellings the docs show, single spaces
#: and all, with no gap between the name and its metadata. Strict on purpose: the
#: workflow's grep and a third-party flasher's regex are the lenient readers, and
#: what this gate governs is what the project *writes*, where publishing a second
#: spelling is publishing an ambiguity somebody else has to guess at. The JSON is
#: captured rather than validated here so a malformed object is a REPORTED marker
#: and not an unmatched line.
MARKER = re.compile(r"<!-- " + re.escape(NAME) + r"(\{.*?\})? -->")

#: Anything that names the marker at all. The gap between this and [`MARKER`] is
#: where a typo lives, and reporting that gap is most of the job: `<!--
#: @increase-anti-rollback-epoch {"reason": 1} -->` is not a marker any tool
#: reads, and it is exactly what a careful person writes by accident.
MENTION = re.compile(r"<!--[^>]*" + re.escape(NAME) + r"[^>]*-->")

#: A marker inside a code span. Only this file cares: the release step greps the
#: section as plain text, so a backticked example is indistinguishable from the
#: flag itself — see [`check_changelog`].
QUOTED = re.compile(r"`+[^`\n]*" + re.escape(NAME) + r"[^`\n]*`+")

#: A CHANGELOG version heading — `## [0.4.11] - 2026-08-14` or `## [Unreleased]`.
SECTION = re.compile(r"^## \[([^\]]+)\]", re.M)

#: A fenced example in the docs. The page teaches the spelling by showing it, so
#: what is checked is the shown text and not a sentence describing it. Both
#: fences are anchored to a line start: without that the pattern pairs a block's
#: CLOSING fence with the next block's opening one, and the examples land in the
#: gaps between matches instead of inside them.
FENCE = re.compile(r"^```[a-z]*\n(.*?)^```", re.S | re.M)


def problems_with(marker, json_text):
    """What is wrong with one parsed marker, as a list of sentences."""
    out = []
    if json_text is None:
        return out
    try:
        payload = json.loads(json_text)
    except json.JSONDecodeError as e:
        return [f"its metadata is not JSON ({e.msg})"]
    if not isinstance(payload, dict):
        return [f"its metadata is {type(payload).__name__}, not an object"]
    for key, value in payload.items():
        if key != "reason":
            out.append(f"unknown metadata key {key!r} (only 'reason' is defined)")
        elif not isinstance(value, str) or not value.strip():
            out.append("'reason' must be a non-empty string")
    return out


def sections(text):
    """`(name, body)` for every version section of the changelog."""
    bounds = [(m.group(1), m.start()) for m in SECTION.finditer(text)]
    for i, (name, start) in enumerate(bounds):
        end = bounds[i + 1][1] if i + 1 < len(bounds) else len(text)
        yield name, text[start:end]


def check_changelog(root, errors):
    text = (root / CHANGELOG).read_text()
    for name, body in sections(text):
        good = MARKER.findall(body)
        seen = MENTION.findall(body)
        # An EXAMPLE of the marker is a live marker here, and this file is the one
        # place that is true: `release-build.yml` greps the section as text, so a
        # spelling written inside backticks to explain the format flags whatever
        # release the entry happens to sit in. Measured on the entry that
        # introduced the marker — two backticked examples in `[Unreleased]`.
        for raw in QUOTED.findall(body):
            errors.append(
                f"CHANGELOG [{name}]: {raw!r} is quoted as an example, and the "
                "release step cannot tell that from a flag — document the format "
                "in docs/anti-rollback.md and name it here without spelling it"
            )
        for raw in seen:
            m = MARKER.fullmatch(raw)
            if not m:
                errors.append(
                    f"CHANGELOG [{name}]: {raw!r} names the marker but is not one — "
                    "a flasher will not see it"
                )
                continue
            for why in problems_with(raw, m.group(1)):
                errors.append(f"CHANGELOG [{name}]: {raw!r} — {why}")
        if len(good) > 1:
            errors.append(
                f"CHANGELOG [{name}]: {len(good)} markers in one section; "
                "the release body carries one"
            )


def check_workflow(root, errors):
    text = (root / WORKFLOW).read_text()
    if NAME not in text:
        errors.append(
            f"{WORKFLOW} does not mention {NAME} — the marker "
            "would never reach a release body"
        )
        return
    # The step greps the FULL section, before the shortening path; a grep over the
    # already-shortened notes would drop the marker exactly when the section is
    # long, which is when a release most needs one.
    if "release-notes-full.md" not in text:
        errors.append(
            f"{WORKFLOW}: the marker must be lifted out of the "
            "full section (release-notes-full.md), not the shortened notes"
        )
    for line in text.splitlines():
        if NAME in line and "grep" in line:
            pattern = re.search(r"'([^']*" + re.escape(NAME) + r"[^']*)'", line)
            if not pattern:
                errors.append(f"{WORKFLOW}: cannot read the grep pattern from {line.strip()!r}")
            elif not (pattern.group(1).startswith("<!--") and pattern.group(1).endswith("-->")):
                errors.append(
                    f"{WORKFLOW}: the grep pattern {pattern.group(1)!r} "
                    "does not bracket the marker in comment delimiters"
                )
            return
    errors.append(f"{WORKFLOW}: {NAME} appears but nothing greps for it")


def check_docs(root, errors):
    text = (root / DOCS).read_text()
    shown = [
        line.strip()
        for fence in FENCE.findall(text)
        for line in fence.splitlines()
        if NAME in line
    ]
    if not shown:
        errors.append(
            f"{DOCS} shows no marker example — the spelling is "
            "what third-party tools copy"
        )
        return
    for line in shown:
        m = MARKER.fullmatch(line)
        if not m:
            errors.append(f"{DOCS}: the example {line!r} would be rejected by this gate")
            continue
        for why in problems_with(line, m.group(1)):
            errors.append(f"{DOCS}: the example {line!r} — {why}")
    # Both forms, because a page that only shows one teaches half the format and
    # the bare one is the form a release with no reason to give has to use.
    if not any(MARKER.fullmatch(line).group(1) is None for line in shown if MARKER.fullmatch(line)):
        errors.append(f"{DOCS}: no example of the bare marker (no metadata)")
    if not any(MARKER.fullmatch(line).group(1) for line in shown if MARKER.fullmatch(line)):
        errors.append(f"{DOCS}: no example of the marker carrying a reason")


def audit(root):
    """Every complaint about `root`, as sentences. Empty means the copies agree."""
    errors = []
    check_changelog(root, errors)
    check_workflow(root, errors)
    check_docs(root, errors)
    return errors


def main():
    errors = audit(ROOT)
    for e in errors:
        print(f"rollback-marker: {e}", file=sys.stderr)
    if errors:
        return 1
    print("rollback-marker: the marker's three copies agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
