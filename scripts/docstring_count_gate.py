#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold a docstring's spelled list count to the list underneath it.

Three module docstrings under `scripts/` have shipped a spelled cardinal over
the wrong number of bullets, each found by hand and each on a different day.
`platform_gate.py` said Seven where six bullets stood, and had since the commit
that moved the word without moving a bullet; `threat_gate.py` said Three over
four and `elf_gate.py` said Two over three, both the other way round — a bullet
appended and the count left alone. All three are right today and nothing held
them, which is `run_count_gate.py`'s subject one layer in: a number whose only
copy of the truth was the moment somebody typed it.

The rule itself is `count == items`. What earns the file is everything around
it, because a naive version is wrong on the tree it has to be green on — each
clause below was written against a real block here that the version without it
gets wrong, and each has its own arm in the table beside this file.

Six clauses:

* **the intro is a SENTENCE, joined across the lines it wraps.** The count sits
  on the wrapped line ABOVE the colon in `transport_bridge_gate.py` and in
  `token_refinement_gate.py`. A line-anchored matcher does not call those red —
  it stops reading them, which is worse: measured, 8 of the 23 counted lists go
  silently uncounted without this clause, `comutate.py`'s among them.
* **the count is the FIRST spelled cardinal of that sentence, or there is
  none.** Not the first one that happens to fit: `test_gate_scripts.py` reaches
  "breaks three ways at once" over five bullets, and scanning on until something
  fits is how a stray word becomes a verdict.
* **it must quantify a plural noun.** Nine intros here open on a stray "one"
  ("a trick one", "each one", "ONE defect shape", "one edit", "the last one"
  among them), and a count of one over ten bullets is a pronoun, not a list.
* **`the N Xs` whose noun is already in the docstring is a back-reference.**
  `ct_gate.py` writes "the two sentences" over three bullets, and the two
  sentences are the ones its paragraph above quotes. Derived from the text
  rather than exempted by name, because the same shape says "the three
  corrections" over three bullets one file away and means it.
* **a bullet may name more than one thing.** `comutate.py` counts THREE families
  over TWO bullets, and it is right: the first bullet leads with two globs joined
  by "and". So the assertion is against ITEMS — a bullet whose lead is exactly a
  list of literal spans names that many — and an exemption by file name would
  have been the shape this tree keeps finding switched off.
* **the block tolerates blank lines between bullets.** `comutate.py` spaces its
  two bullets apart; strict contiguity sees one bullet there and reads the whole
  block as a miscount.

What this cannot say is whether the list is RIGHT — only that its own prose and
its own bullets agree. It is also deliberately silent wherever no cardinal
survives the clauses above, which is most of the corpus; the success line prints
both totals so the silent half is a number a reader can watch rather than a
claim. A count written in digits ("2 rules") is not read at all, because no
block in the tree writes one and a rule with no instance is a rule with no arm.

An intro line need not end in a colon, and the corpus is wider for it. What
that width costs is one block: `test_claims_gate.py`'s hard-wrapped `268.` is
a bullet to [`BULLET`] under an intro whose "one was" is a count to [`count`],
and the two wrong readings agree at 1, so it is green by luck, not by rule.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Spelled cardinals, value included. Twenty is the ceiling because the longest
#: list in the corpus is twelve bullets; a longer one spelled out would go
#: uncounted rather than wrong, and that is the safe direction.
CARDINALS = {
    word: value
    for value, word in enumerate(
        "zero one two three four five six seven eight nine ten eleven twelve "
        "thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty".split()
    )
}
CARDINAL = re.compile(r"\b(" + "|".join(CARDINALS) + r")\b", re.IGNORECASE)

#: A bullet at any indent, in either of the two spellings the tree uses.
BULLET = re.compile(r"^(\s*)(?:[*+-]|\d+[.)])\s+(\S.*)$")

#: A literal span a bullet can LEAD with -- `code` or **bold**. The lead is what
#: names the thing; the prose after it describes the thing.
SPAN = re.compile(r"`[^`]+`|\*\*[^*]+\*\*")

#: What may sit between two spans of one lead and still leave them one list.
#: A possessive does not: `Transport.cfg`'s `Cap` is ONE number named twice over.
JOINER = re.compile(r"\s*(?:,|,?\s*(?:and|or))\s*")

#: The determiners that make a noun phrase point BACKWARDS. Indefinite ones do
#: not, which is the whole distinction: "the two sentences" resumes a pair the
#: page already named, "two rules" introduces one.
DEFINITE = {"the", "this", "that", "these", "those"}

#: Endings that make a word look plural without being one.
NOT_PLURAL = ("ss", "us", "is")

#: Sentence boundary: a terminator followed by something that can open a
#: sentence. Deliberately not a period alone -- `docs/threat-model.md#ID` and
#: `0.4.10` are periods this must not split a wrapped intro on.
SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z`*\"(])")

#: Prose this repo does not own. The vendored suites are edited for harness
#: defects only (CONTRIBUTING.md), so a rule about how their authors spell a
#: count would be a finding nobody here may act on.
NOT_OURS = ("third_party/",)


def bullets(lines, start):
    """Indices of the bullets at `start`'s indent, and where the block ends.

    Blank lines stay INSIDE the block while it resumes -- at a bullet of the same
    indent, or at a continuation indented past it. Strict contiguity reads
    `comutate.py`'s blank-separated pair as a single bullet, which is a miscount
    of a correct docstring rather than a miss.
    """
    indent = len(BULLET.match(lines[start]).group(1))
    found, here = [], start
    while here < len(lines):
        bullet = BULLET.match(lines[here])
        if bullet and len(bullet.group(1)) == indent:
            found.append(here)
            here += 1
            continue
        if lines[here].strip():
            if len(lines[here]) - len(lines[here].lstrip()) > indent:
                here += 1
                continue
            break
        after = here + 1
        while after < len(lines) and not lines[after].strip():
            after += 1
        if after >= len(lines):
            break
        resumes = BULLET.match(lines[after])
        deeper = len(lines[after]) - len(lines[after].lstrip()) > indent
        if (resumes and len(resumes.group(1)) == indent) or deeper:
            here = after
        else:
            break
    return found, here


def names(body):
    """How many things one bullet names: its lead, if the lead IS a list.

    A lead of two or more literal spans joined only by commas and "and"/"or"
    names that many; anything else names one. The lead has to be the WHOLE thing
    before the dash, so a sentence that merely contains two spans stays at one.
    """
    lead = re.split(r"\s+[—–]\s+", body)[0].strip()
    spans = list(SPAN.finditer(lead))
    if len(spans) < 2 or spans[0].start() != 0 or spans[-1].end() != len(lead):
        return 1
    for first, second in zip(spans, spans[1:]):
        if not JOINER.fullmatch(lead[first.end():second.start()]):
            return 1
    return len(spans)


def intro(lines, colon):
    """The sentence that ends at `colon`, and everything before its paragraph.

    Two answers because both are needed: the sentence is where the count word
    may sit, and the text before it is what decides whether a definite noun
    phrase is resuming something.
    """
    start = colon
    while start > 0 and lines[start - 1].strip() and not BULLET.match(lines[start - 1]):
        start -= 1
    paragraph = " ".join(line.strip() for line in lines[start:colon + 1])
    return SENTENCE.split(paragraph)[-1], "\n".join(lines[:start])


def count(sentence, before):
    """The list count this sentence states, or None if it states none.

    The loop runs at most once by construction, and that IS the rule: a sentence
    whose first cardinal is not a count states no count. Reading on for a later
    one that fits promotes a stray word to a verdict -- measured on a docstring
    whose first cardinal is a pronoun and whose second is "three ways at once".
    """
    for found in CARDINAL.finditer(sentence):
        noun = re.match(r"[A-Za-z][A-Za-z'-]*", sentence[found.end():].lstrip())
        noun = noun.group(0) if noun else ""
        if len(noun) < 3 or not noun.lower().endswith("s") or noun.lower().endswith(NOT_PLURAL):
            return None  # a cardinal over a singular is a pronoun, not a count
        before_word = sentence[:found.start()].rstrip().rsplit(" ", 1)[-1].lower().strip("(\"'")
        if before_word in DEFINITE and re.search(rf"\b{re.escape(noun)}\b", before, re.IGNORECASE):
            return None  # "the N Xs" resuming an X above is a back-reference
        return found.group(0), CARDINALS[found.group(0).lower()], noun
    return None


def blocks(text):
    """Every (offset, sentence, bullets, items, count) list block of a docstring."""
    lines, found, here = text.split("\n"), [], 0
    while here < len(lines):
        line = lines[here]
        if not line.strip() or BULLET.match(line):
            here += 1
            continue
        first = here + 1
        while first < len(lines) and not lines[first].strip():
            first += 1
        if first >= len(lines) or first - here > 2 or not BULLET.match(lines[first]):
            here += 1
            continue
        indices, end = bullets(lines, first)
        sentence, before = intro(lines, here)
        items = sum(names(BULLET.match(lines[at]).group(2)) for at in indices)
        found.append((here, sentence, len(indices), items, count(sentence, before)))
        here = end
    return found


def docstrings(path):
    """(line, text) for every docstring in one file, module and def alike."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            text = ast.get_docstring(node, clean=False)
            if text:
                yield node.body[0].lineno, text


def corpus(root):
    """Every `.py` of the checkout this repo writes, git's answer and not a walk."""
    return [
        rel
        for rel in sorted(gate_lines.tree_files(root))
        if rel.suffix == ".py" and not str(rel).startswith(NOT_OURS)
    ]


def survey(root):
    """(rel, line, sentence, bullets, items, count) for every block in the tree."""
    seen = []
    for rel in corpus(root):
        for at, text in docstrings(root / rel):
            for offset, sentence, count_of, items, stated in blocks(text):
                seen.append((rel, at + offset, sentence, count_of, items, stated))
    return seen


def audit(root):
    """A finding per block whose spelled count and whose list disagree."""
    findings = []
    for rel, line, sentence, count_of, items, stated in survey(root):
        if stated is None or stated[1] == items:
            continue
        word, value, noun = stated
        spread = f"{count_of} bullets" if count_of == items else f"{count_of} bullets naming {items} things"
        findings.append(
            f"{rel} line {line}: \"{word} {noun}\" over {spread}"
            f" -- the word says {value}, the list says {items}."
            f"\n    {sentence.strip()[:120]}"
        )
    return findings


def run(root=ROOT):
    findings = audit(root)
    for finding in findings:
        print(f"docstring-count-gate: {finding}", file=sys.stderr)
    if findings:
        print(
            "A spelled list count is the cheapest number in this tree to check and"
            " the easiest to leave behind: fix the word or the list.",
            file=sys.stderr,
        )
        return 1
    seen = survey(root)
    counted = [block for block in seen if block[5] is not None]
    files = len({block[0] for block in seen})
    print(
        f"docstring-count-gate: ok — {len(counted)} spelled list counts hold over"
        f" {len(seen)} docstring lists in {files} files"
    )
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    return run(pathlib.Path(argv[0]).resolve() if argv else ROOT)


if __name__ == "__main__":
    sys.exit(main())
