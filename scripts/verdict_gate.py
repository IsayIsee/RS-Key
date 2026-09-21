#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold `formal/floors.txt` — the TLA verdict registry — without running TLC.

The full matrix runs in the weekly `deep-checks.yml` safety tier and nowhere
else, so between two weeklies the registry can be weakened and nothing notices.
Two narrower layers already sit in the merge gate: `security_trace.py
--check-data` replays the main `TraceSecurity` and reads its exact verdict
entries plus the `@TraceSecurity*` ratchets, and `scripts/test_run_tlc.py`
drives the real `run-tlc.sh` against a fake TLC. Measured together they name
TWO of the registry's 25 wildcard families — `Mut_` and `Solo_`, because the
fixture happens to spell `Mut_BugResetGatesFirst.cfg` — so 23 families covering
102 of the 192 configurations had no cheap merge-gate witness at all. A
`SeamMut_*.cfg RED` turned `GREEN` was the measured miss.

Everything here is DERIVED, because a hand-kept copy of a verdict expectation is
the thing being guarded:

* the **verdict** comes from a configuration's own CONSTANTS. A file that
  switches a `Bug*`/`Mutate*` constant on is a mutant and owes RED — unless a
  `Check*` observer is switched off, which is what makes
  `TraceSecurityBadAlphaNoR4b.cfg` a GREEN control. So `RED`→`GREEN` is refused
  on every family at once, and no family list is written down here;
* the **reason** a RED row claims must be attributable, and solo-style is read
  off the INVARIANTS block rather than off the `Solo_` in a name: a mutant whose
  configuration checks ONE invariant says which defect a RED describes, and a
  multi-target one borrows that from the sibling running the same switches. A
  RED nothing can attribute is the shape that let 2 of 24 co-refutation patches
  in this tree score a kill for the INVERSE defect;
* the **runner's own reader** is held to the names the registry gives it.
  `run-tlc.sh` extracted an invariant name with `[A-Za-z]+` for its whole life
  and every `R4*` has a DIGIT, so nine rows printed a blank verdict column and
  read RED coarsely. That is a static disagreement between two files, and this
  is where it is now caught;
* a **floor** is compared with the newest committed registry that differs from
  the working tree's, so a decrease has to say so in the file.

Limits, so the row is not read as more than it is.

* it never runs TLC, so it cannot say which of the five invariants a
  `TraceSecurity*` configuration checks a given mutation actually breaks — only
  that the registry names one the configuration checks and the runner can read.
  Swapping `R4cGateAnswers` for `R4bAlphaMatchesGamma` on a row whose
  configuration checks both stays green here, and the weekly matrix refuses it;
* a divergence expressed in a constant that is neither a defect switch nor a
  `Fix*` is not read as one. Those are SIZES — `MaxRetries`, `ResetWindow`, the
  reduced constants `TokenRefinement.cfg` runs at — and whether a scope is big
  enough to express a defect is `scope_gate.py`'s question, not this one's;
* the floor comparison is against the last DIFFERING commit, not against a merge
  base, so a decrease split across two commits is judged in two steps and each
  step's marker is dropped by the next. That is deliberate — the marker is a
  disposition for the change under review, not a changelog — and it means the
  ratchet catches a fall, never a slide;
* it needs the git history of `floors.txt`. A shallow clone or a tarball export
  reddens the row rather than skipping the comparison, which is the direction a
  guard should fail in but is still a red for a reason nobody's change caused.

What this closes is the cheap half: the registry is no longer weakenable in the
six days between two weekly runs.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORMAL = ROOT / "formal"
REGISTRY = "formal/floors.txt"
RUNNER = "formal/run-tlc.sh"

#: The defect switches. `Fix*` is deliberately not one: `FixSweepDropsCredsBefore
#: RpEntries = FALSE` is the shipped tree in every baseline configuration, so
#: reading it as a mutation would call `Shipped.cfg` a mutant. This refines
#: `scope_gate.SWITCH`, which only needs to know that a name is not a size.
DEFECT = re.compile(r"^(?:Bug|Mutate)[A-Z]")
#: An observer switch. Turning one off disarms the check a mutation is aimed at,
#: which is a CONTROL and expects GREEN — the one thing that separates
#: `TraceSecurityBadAlphaNoR4b.cfg` from the RED row it is the control for.
OBSERVER = re.compile(r"^Check[A-Z]")
#: A shipped fix, and the exclusion above read the other way round: taken OFF the
#: arm the baseline ships it on, a `Fix*` is a defect present again, which is what
#: `Historical_E77.cfg` is. Left unread it was an unlisted limit — `gen-configs
#: .sh`'s `emit <name> <bug> <fix> <fix2>` makes a Fix-only mutant a
#: one-argument change, and one would have derived GREEN.
FIX = re.compile(r"^Fix[A-Z]")

#: The configuration every `Fix*` arm is compared against: the tree as it stands,
#: and the registry's own first row. Only the arm is read from it — a size that
#: differs is a scope, not a mutation.
BASELINE = "Shipped.cfg"

#: The invariant TLC would report vacuously in every configuration; it is the
#: type predicate, never a mutant's target.
TYPE_INVARIANT = "TypeOK"

#: Below this a GREEN says nothing: the Next relation fired nothing at all.
#: `run-tlc.sh` refuses that as `VACUOUS` on its own — but only on the branch it
#: reaches, and the `distinct < 2` test sits behind an `elif` after
#: `grep -qE '^INIT([[:space:]]|$)'`. So for the two induction probes
#: (`StoreInduction.cfg`, `BootInduction.cfg`) the runner holds depth to 1 and
#: applies NO distinct floor whatever, and this is the only one they have.
MIN_FLOOR = 2

#: One weakening can reach 161 configurations — a wildcard laid over the whole
#: registry names every row it masks — and a reader given 629 lines reads none of
#: them. `audit()` still returns them all; only the report stops.
REPORT_LIMIT = 20

#: The one configuration with no verdict entry, and the reason `assurance_gate.py`
#: and `config_gen_gate.py` both record for it. Checked in both directions: an
#: entry the registry has started matching is a contradiction, not a carve-out.
NO_VERDICT = {
    "TokenExport.cfg": "serialization-only TLC input consumed by "
    "scripts/export_token_relation.py — it has no mutation family and no tier row",
}

#: The one RED whose divergence is not a CONSTANT, so neither the verdict nor the
#: reason can be derived from its switches. Also checked in both directions.
UNSWITCHED_RED = {
    "TraceSeamsBad.cfg": "the divergence lives in TraceSeamsBad.tla rather than in a "
    "switch, and TLC refuses the replay by DEADLOCK — which names no invariant",
    "TokenGateDisagreement.cfg": "the refusal is that RequiredGate and the relation "
    "read as a gate are two predicates, which is a property of the module and not of "
    "a switch — a GREEN here is the degenerate oracle §4.3 refuses",
}

#: A floor may fall, but not quietly. The reason is part of the pattern: a marker
#: carrying only the two numbers restates the diff instead of justifying it. It is
#: read against the change under review, so it goes in with the decrease and comes
#: back out with the next edit to the file — a disposition, not a changelog.
DECREASE = re.compile(
    r"^\\\*\s+floor-decrease:\s+(?P<subject>\S+)\s+(?P<was>\d+)\s*->\s*(?P<now>\d+)\s+(?P<why>\S.*)$"
)

#: The default for `audit`'s `previous_text`. `None` cannot serve as one: it is
#: what a git that could not answer returns, and that case owes a finding rather
#: than the default behaviour.
FROM_GIT = object()

#: What makes a row a wildcard FAMILY rather than an exact name — the two
#: operators a shell `case` expands that this row also resolves.
GLOB = re.compile(r"[*?]")

#: The third one, refused rather than resolved. `case` expands `Boot[MS]*.cfg`
#: and nothing here would, so a row carrying one would be read as a literal and
#: report seven configurations as unentered — a red for the wrong reason, which
#: is how a gate row gets deleted. No row uses one; saying so is cheaper than a
#: bracket parser for a syntax the file has never wanted.
CLASS = re.compile(r"\[")

#: Columns of a row, and the count `read -r want floor heap inv` splits into
#: after the pattern: everything past the fourth stays with the fifth.
COLUMNS = 5

#: Under this the `formal/*.cfg` glob found the wrong directory, or nothing at
#: all — the shape five guards in this tree shipped with, where every loop runs
#: over an empty set and the row reads as a pass.
CONFIG_FLOOR = 100

#: How `run-tlc.sh` spells the name it compares against this registry's last
#: column. Read out of the runner rather than copied, because the two disagreeing
#: is the defect: `[A-Za-z]+` there and `R4cGateAnswers` here read RED coarsely
#: and compared nothing for the whole life of the nine trace rows.
RUNNER_READS = re.compile(r"'Invariant (?P<name>\S+) is violated'")

#: `Name = value` or `Name <- operator`, the two spellings a `.cfg` assigns with.
ASSIGNMENT = re.compile(r"([A-Za-z][A-Za-z0-9_]*)\s*(?:=|<-)\s*(.+)$")

#: What STARTS one, which is not the same question: `Name =` with the value on
#: the next line is an assignment whose first line carries no value. Read as a
#: continuation of the line above it folds two constants into one, and the row
#: then goes red naming the wrong one — measured, `Boot.cfg` reported
#: `BugRekeyKeepsTheMarker` for a `BugMarkerBeforeScrub` that was switched on.
ASSIGNS = re.compile(r"[A-Za-z][A-Za-z0-9_]*\s*(?:=|<-)")

#: A TLA+ line comment, and it may sit AFTER a value. `Bug… = TRUE  \* kept` is
#: TRUE to TLC and was "not armed" here, which is the whole of the finding below.
INLINE_COMMENT = re.compile(r"\\\*")


def git(root, *args):
    """`git` in `root`, or None when it could not answer.

    None is never read as "nothing changed" by a caller here — the floor check
    reports it as a finding instead, because a guard that takes a git failure for
    a clean tree goes green the day the command's spelling breaks.
    """
    done = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    return None if done.returncode else done.stdout


def previous_registry(root=ROOT, rel=REGISTRY, limit=50):
    """The newest committed registry whose bytes differ from the working tree's.

    Not `HEAD`: on a clean checkout — which is every CI run — `HEAD` IS the
    working tree, every floor compares equal to itself, and the whole check
    passes without looking at anything. Walking back to the last DIFFERENT
    version keeps the comparison non-vacuous both on a clean tree (it re-reads
    the last change to the file, forever) and on a dirty one (it reads `HEAD`,
    which is the change under review).
    """
    now = decoded(pathlib.Path(root) / rel)
    history = git(root, "log", "--format=%H", f"-{limit}", "--", rel)
    if history is None:
        return None
    for sha in history.split():
        was = git(root, "show", f"{sha}:{rel}")
        if was is not None and was != now:
            return was
    return None


def decoded(path):
    """`path` as text with its line endings INTACT.

    `read_text` folds `\\r\\n` to `\\n`, and this is the one file where that
    difference is the finding rather than noise.
    """
    return path.read_bytes().decode("utf-8")


def block_names(text, head):
    """The names a `.cfg` lists under one block header, in order.

    `scope_gate.referenced_by` answers a related question and cannot serve here:
    it unions SPECIFICATION, INVARIANTS, PROPERTIES and SYMMETRY into one set, so
    it loses both which block a name came from and how many names the block has —
    and "exactly one invariant" is the whole definition of solo-style.
    """
    names = []
    for found in re.finditer(rf"^(?:{head})\s*$([\s\S]*?)(?=^[A-Z]+\s*$|\Z)", text, re.M):
        names += [ln.strip() for ln in found.group(1).splitlines()
                  if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", ln.strip())]
    for inline in re.finditer(rf"^(?:{head})\s+([A-Za-z][A-Za-z0-9_]*)\s*$", text, re.M):
        names.append(inline.group(1))
    return list(dict.fromkeys(names))


def statements(body):
    """`body`'s lines with comment tails cut and wrapped values folded back on.

    Both are legal TLA+ that TLC reads straight through, and reading either as
    "no value" is the silent direction: a defect switched on in a BASELINE
    configuration then derives GREEN. Measured end to end against real TLC —
    `Boot.cfg` carrying `BugMarkerBeforeScrub = TRUE  \\* E-arm kept`, and the
    same value wrapped onto the next line, each gave `run-tlc.sh` RED at
    `MarkerNeverLies` with this row EXIT=0.
    """
    out = []
    for raw in body.splitlines():
        line = INLINE_COMMENT.split(raw, 1)[0].strip()
        if not line:
            continue
        if out and not ASSIGNS.match(line):
            out[-1] += " " + line
        else:
            out.append(line)
    return out


def assignments(text):
    """CONSTANT assignments of one configuration, as {name: raw value}.

    Both spellings, for the reason `scope_gate.constants_of` gives on the module
    side: a parser that silently sees fewer constants than TLC does is the blind
    kind of green.
    """
    out = {}
    block = re.search(r"^CONSTANTS?\s*$([\s\S]*?)(?=^[A-Z]+\s*$|\Z)", text, re.M)
    for line in statements(block.group(1)) if block else []:
        hit = ASSIGNMENT.match(line)
        if hit:
            out[hit.group(1)] = hit.group(2).strip()
    for inline in re.finditer(rf"^CONSTANTS?\s+{ASSIGNMENT.pattern}", text, re.M):
        out[inline.group(1)] = INLINE_COMMENT.split(inline.group(2), 1)[0].strip()
    return out


class Config:
    """One `.cfg` as this row reads it: its switches and what it checks."""

    def __init__(self, path):
        text = path.read_text(encoding="utf-8")
        self.name = path.name
        constants = assignments(text)
        # A switch whose value is neither is a FINDING, never "not armed": every
        # unreadable spelling would otherwise derive GREEN, which is the
        # direction `v == "TRUE"` failed in by construction.
        self.unreadable = sorted((n, v) for n, v in constants.items()
                                 if (DEFECT.match(n) or OBSERVER.match(n))
                                 and v not in ("TRUE", "FALSE"))
        self.armed = sorted(n for n, v in constants.items() if DEFECT.match(n) and v == "TRUE")
        self.disarmed = sorted(n for n, v in constants.items()
                               if OBSERVER.match(n) and v == "FALSE")
        self.fixes = {n: v for n, v in constants.items() if FIX.match(n)}
        self.invariants = block_names(text, "INVARIANTS?")
        self.targets = [i for i in self.invariants if i != TYPE_INVARIANT]
        self.properties = block_names(text, "PROPERT(?:Y|IES)")

    @property
    def want(self):
        """The verdict this configuration's own CONSTANTS ask for."""
        return "RED" if self.armed and not self.disarmed else "GREEN"

    @property
    def solo(self):
        """Whether the configuration itself says which defect a RED describes."""
        return len(self.targets) == 1 or (not self.targets and len(self.properties) == 1)


def read_registry(text):
    """(rows, ratchets, problems) parsed the way `run-tlc.sh` parses this file.

    Its `read -r pat rest` splits on whitespace and skips a line whose first word
    is exactly `\\*`, so `\\*Shipped.cfg GREEN 1` is a glob to the runner and must
    be one here too — a parser that is more generous about comments than the
    runner is a parser reading a different registry. `split(None, COLUMNS - 1)`
    for the same reason: `read -r want floor heap inv` puts everything from the
    fifth field to the end of the line into `inv`, so a trailing remark there is
    part of the name the runner compares, and reading only `parts[4]` would call
    that row well-formed while every run of it printed `!! expected`.
    """
    rows, ratchets, problems = [], {}, []
    for number, line in enumerate(text.splitlines(), 1):
        parts = line.split(None, COLUMNS - 1)
        if not parts or parts[0] == "\\*" or parts[0].startswith("#"):
            continue
        if parts[0].startswith("@"):
            if len(parts) != 2 or not re.fullmatch(r"-?\d+", parts[1]):
                problems.append(f"{REGISTRY}:{number}: expected `@Name <integer>`")
            elif parts[0] in ratchets:
                problems.append(f"{REGISTRY}:{number}: {parts[0]} recorded twice")
            else:
                ratchets[parts[0]] = int(parts[1])
            continue
        if len(parts) < 2:
            problems.append(
                f"{REGISTRY}:{number}: expected `<config or glob> <GREEN|RED>"
                " <min distinct, or -> [heap] [invariant]`")
            continue
        pattern, want = parts[0], parts[1]
        # `.rstrip()` because `read` strips trailing IFS whitespace off the last
        # field and `split(None, 4)` keeps it: three spaces after an invariant
        # name made TWO findings about a row the runner reads correctly.
        floor = (parts + ["-"] * COLUMNS)[2]
        invariant = (parts + ["-"] * COLUMNS)[4].rstrip()
        if CLASS.search(pattern):
            problems.append(
                f"{REGISTRY}:{number}: `{pattern}` carries a character class, which a shell"
                " `case` expands and this row resolves as a literal — spell the row out")
            continue
        if want not in ("GREEN", "RED"):
            problems.append(f"{REGISTRY}:{number}: {want!r} is neither GREEN nor RED")
            continue
        if floor != "-" and not re.fullmatch(r"\d+", floor):
            problems.append(f"{REGISTRY}:{number}: floor must be a count or `-`, got {floor!r}")
            continue
        rows.append({
            "line": number, "pattern": pattern, "want": want,
            "floor": None if floor == "-" else int(floor),
            "invariant": None if invariant == "-" else invariant,
        })
    return rows, ratchets, problems


def glob_to_regex(pattern):
    """A shell `case` glob as a regex, the operators `run-tlc.sh` can be given.

    `fnmatch` is close but not this: it folds case on a case-insensitive
    filesystem, and `Solo_*.cfg` matching `solo_x.cfg` is a match the runner's
    `case` would not make. Character classes are refused at the parse instead of
    being translated here, so the two never disagree about one.
    """
    out = ""
    for char in pattern:
        out += {"*": ".*", "?": "."}.get(char, re.escape(char))
    return re.compile(out + r"\Z")


def resolve(rows, names):
    """(first match per name, every match per name) — the runner takes the first."""
    matched = {row["pattern"]: glob_to_regex(row["pattern"]) for row in rows}
    every = {name: [row for row in rows if matched[row["pattern"]].match(name)]
             for name in names}
    return {name: hits[0] if hits else None for name, hits in every.items()}, every


def payload(row):
    return (row["want"], row["floor"], row["invariant"])


def check_completeness(rows, first, every, problems):
    """Every configuration answered for, and every row answering for something."""
    for name, row in sorted(first.items()):
        if row is None and name not in NO_VERDICT:
            problems.append(f"{name}: no verdict entry in {REGISTRY} and no registered"
                            " exemption — say which verdict it owes, or why it owes none")
        if row is not None and name in NO_VERDICT:
            problems.append(f"{name}: registered as having no verdict entry, but"
                            f" {REGISTRY}:{row['line']} `{row['pattern']}` matches it")
    for name in sorted(set(NO_VERDICT) - set(first)):
        problems.append(f"{name}: registered as exempt from a verdict entry but no such"
                        " configuration — stale entry in scripts/verdict_gate.py")
    for row in rows:
        reachable = [name for name, hits in every.items() if hits and hits[0] is row]
        if reachable:
            continue
        shadowing = [name for name, hits in every.items() if row in hits]
        if shadowing:
            masker = every[shadowing[0]][0]
            problems.append(
                f"{REGISTRY}:{row['line']} `{row['pattern']}` never decides anything:"
                f" {REGISTRY}:{masker['line']} `{masker['pattern']}` matches"
                f" {len(shadowing)} configuration(s) first, including {shadowing[0]}")
        else:
            problems.append(f"{REGISTRY}:{row['line']} `{row['pattern']}` matches no"
                            " configuration in formal/ — an orphaned entry")


def check_switches(configs, problems):
    """A defect switch this row cannot read is reported, never taken for OFF.

    The two spellings that defeated `v == "TRUE"` are read now, so what is left
    here is everything else: `= 1`, `= TRUE /\\ FALSE`, a value that is no value.
    Reported rather than skipped because the skip is the silent direction — the
    weekly matrix would run the mutant this file called a baseline.
    """
    for name, config in sorted(configs.items()):
        for switch, value in config.unreadable:
            problems.append(
                f"{name}: {switch} = {value!r}, which is neither TRUE nor FALSE — whether"
                " the defect is switched on cannot be derived, and an unreadable switch"
                " reads here exactly like one that is off")


def repair_arms(configs, problems):
    """{configuration: the `Fix*` constants it turns ON that `BASELINE` leaves OFF}.

    The counterpart of a reverted fix, and it had no reader at all until
    `Historical_E76.cfg` became one. A `Fix*` the tree does NOT ship is a
    counterfactual repair: armed beside the defect it was proposed for, the
    question the run answers is "would this repair have worked", and that is the
    one thing a configuration's constants cannot say in advance — which is why
    `check_verdicts` stops deriving for these and the registry decides instead.

    A `Fix*` whose value is neither TRUE nor FALSE is reported here rather than
    read as OFF, for the reason `Config.unreadable` gives one switch family over:
    the silent direction is the one that derives the permissive answer.
    """
    baseline = configs.get(BASELINE)
    if baseline is None:
        problems.append(f"{BASELINE}: no such configuration, so a `Fix*` constant taken"
                        " off the arm the tree ships has nothing to be compared with")
        return {}
    for name, config in sorted(configs.items()):
        for fix, value in sorted(config.fixes.items()):
            if value not in ("TRUE", "FALSE"):
                problems.append(
                    f"{name}: {fix} = {value!r}, which is neither TRUE nor FALSE — whether"
                    " it takes a shipped fix out or applies one the tree never took cannot"
                    " be derived, and an unreadable fix reads here like the shipped arm")
    return {name: sorted(n for n, v in config.fixes.items()
                         if v == "TRUE" and baseline.fixes.get(n) == "FALSE")
            for name, config in configs.items()}


def check_reverted_fixes(configs, first, problems):
    """A shipped fix taken back out is a defect, whatever its constant is called.

    `Fix*` is not a defect switch — reading it as one would call every baseline a
    mutant — so it is read as one exactly where it is taken OFF the arm
    `BASELINE` ships it on, which is what `Historical_E77.cfg` is. One direction
    only: a reverted fix may not be required GREEN, and nothing here asks a
    configuration to be RED.

    ONE DIRECTION OF THE VALUE, TOO, and that is the correction `Historical_E76
    .cfg` forced. The comparison was `v != baseline.fixes[n]`, which is symmetric
    — so a fix the baseline leaves OFF and a configuration turns ON tripped this
    as "a fix taken back out". Applying a repair the tree never took cannot
    reintroduce a defect; the direction that can is a fix REMOVED. What the
    other direction owes instead is `check_repair_experiments`.
    """
    baseline = configs.get(BASELINE)
    if baseline is None:
        return
    for name, config in sorted(configs.items()):
        row = first.get(name)
        if row is None or row["want"] == "RED":
            continue
        reverted = sorted(n for n, v in config.fixes.items()
                          if baseline.fixes.get(n) == "TRUE" and v != "TRUE")
        if reverted:
            problems.append(
                f"{name}: {REGISTRY}:{row['line']} `{row['pattern']}` requires GREEN, but"
                f" it takes {', '.join(reverted)} off the arm {BASELINE} ships it on —"
                " a fix taken back out is the defect it closed, and owes RED")


def check_repair_experiments(configs, first, repaired, problems):
    """A defect armed beside a repair the tree never took owes an EXACT row.

    Its verdict is a measurement and not a derivation, so the registry is the
    only thing that can carry it — and a WILDCARD carrying it would be an
    accident: `Mut_*.cfg RED -` would silently absorb a `Mut_` configuration
    somebody had disarmed with a `Fix*`, and the family's own RED would be the
    reason nobody looked. Naming the row makes the exemption a line of the
    registry that a reader passes on the way to the family it sits beside.

    The verdict itself is still held: `check_row_shape` refuses a GREEN with no
    floor, and `check_reasons` refuses a RED nothing can attribute.
    """
    for name, config in sorted(configs.items()):
        if not repaired.get(name) or not config.armed:
            continue
        row = first.get(name)
        if row is None or not GLOB.search(row["pattern"]):
            continue
        problems.append(
            f"{name}: arms {', '.join(config.armed)} together with"
            f" {', '.join(repaired[name])}, a repair {BASELINE} does not ship — whether"
            " that closes the defect is what the run measures, so it owes an exact"
            f" row of its own and {REGISTRY}:{row['line']} `{row['pattern']}` is a family")


def check_conflicts(every, problems):
    """Two rows over one configuration are refused, not settled by their order."""
    for name, hits in sorted(every.items()):
        for other in hits[1:]:
            if payload(other) != payload(hits[0]):
                problems.append(
                    f"{name}: {REGISTRY}:{hits[0]['line']} `{hits[0]['pattern']}` and"
                    f" {REGISTRY}:{other['line']} `{other['pattern']}` both match it and"
                    f" disagree ({payload(hits[0])} against {payload(other)}) — first"
                    " match decides it silently")


def check_verdicts(configs, first, repaired, problems):
    """The verdict a configuration's CONSTANTS ask for against the one it is given."""
    for name, config in sorted(configs.items()):
        row = first.get(name)
        if row is None:
            continue
        if repaired.get(name) and config.armed:
            # A repair the tree never took, armed beside the defect it was
            # proposed for: the constants say a defect is present AND that
            # something is meant to close it, so neither verdict is derivable
            # from them. `check_repair_experiments` makes the row say which.
            continue
        exempt = name in UNSWITCHED_RED
        if exempt and config.armed:
            problems.append(f"{name}: registered as RED without a switch, but it now"
                            f" switches {', '.join(config.armed)} on — drop the carve-out")
            continue
        if exempt:
            # The carve-out is about where the verdict is DERIVED from, never about
            # whether there is one: skipping the comparison here left the one row
            # singled out for attention as the only one whose RED could go GREEN.
            if row["want"] != "RED":
                problems.append(f"{name}: registered as RED without a switch, and"
                                f" {REGISTRY}:{row['line']} says {row['want']} — the"
                                " carve-out exempts the derivation, not the verdict")
            continue
        if row["want"] != config.want:
            why = (f"switches {', '.join(config.armed)} on" if config.armed
                   else "switches no defect on")
            if config.disarmed:
                why += f" with {', '.join(config.disarmed)} off"
            problems.append(f"{name}: {REGISTRY}:{row['line']} `{row['pattern']}` requires"
                            f" {row['want']}, but the configuration {why} and so owes"
                            f" {config.want}")
    for name in sorted(set(UNSWITCHED_RED) - set(configs)):
        problems.append(f"{name}: registered as RED without a switch but no such"
                        " configuration — stale entry in scripts/verdict_gate.py")


def check_row_shape(rows, reads, problems):
    """The rules that are about a ROW rather than about a configuration.

    Reported once per row on purpose: `SeamMut_*.cfg` decides nineteen
    configurations, and one mistyped column that says the same thing nineteen
    times is a report a reader stops reading.
    """
    for row in rows:
        where = f"{REGISTRY}:{row['line']} `{row['pattern']}`"
        if row["want"] == "GREEN" and row["floor"] is None:
            problems.append(f"{where}: GREEN with no floor — the runner's own VACUOUS rule"
                            " is then the only thing left, and it sees the collapse all the"
                            " way to nothing only")
        elif row["want"] == "GREEN" and row["floor"] < MIN_FLOOR:
            problems.append(f"{where}: GREEN floored at {row['floor']}, under the"
                            f" {MIN_FLOOR} below which a GREEN says only that nothing"
                            " was enabled")
        if row["want"] == "RED" and row["floor"] is not None:
            problems.append(f"{where}: RED with a floor of {row['floor']} — a counterexample"
                            " search halts at the first violation, so its state count is"
                            " worker-scheduling dependent and carries no floor")
        if row["invariant"] is None:
            continue
        if row["want"] != "RED":
            problems.append(f"{where}: GREEN and naming {row['invariant']} — nothing compares"
                            " an invariant on a pass, so the name reads like a claim the"
                            " runner checks and is one it never reads")
        elif reads is not None and not reads.fullmatch(row["invariant"]):
            problems.append(f"{where}: names {row['invariant']}, which {RUNNER}'s own"
                            f" `{reads.pattern}` cannot read — the verdict column prints"
                            " blank and the comparison compares nothing")


def check_reasons(configs, first, problems):
    """Every RED says which defect it describes, in terms its own file carries."""
    for name, config in sorted(configs.items()):
        row = first.get(name)
        if row is None or row["want"] != "RED":
            continue
        if row["invariant"] is not None:
            if row["invariant"] == TYPE_INVARIANT:
                problems.append(
                    f"{name}: {REGISTRY}:{row['line']} expects RED at {TYPE_INVARIANT},"
                    " which every configuration checks and no mutant targets — that"
                    " attributes the RED to nothing")
            elif row["invariant"] in config.properties:
                problems.append(
                    f"{name}: {REGISTRY}:{row['line']} names the property"
                    f" {row['invariant']}; {RUNNER} reads `Invariant … is violated` and"
                    " nothing else, so a temporal refutation cannot be named here")
            elif row["invariant"] not in config.invariants:
                problems.append(
                    f"{name}: {REGISTRY}:{row['line']} expects RED at {row['invariant']},"
                    " which the configuration does not check — no run of it can report"
                    " that name")
            continue
        if name in UNSWITCHED_RED or config.solo:
            continue
        twins = [other for other, sibling in configs.items()
                 if other != name and sibling.armed == config.armed and sibling.solo
                 and first.get(other) is not None and first[other]["want"] == "RED"]
        if not twins:
            # A properties-only configuration cannot be sent to the invariant column:
            # `run-tlc.sh` reads no property name, so the only remedy it HAS is a
            # solo-style sibling, and offering it the other one is a demand nobody
            # can satisfy.
            remedy = ("give it a solo-style sibling on the same switches"
                      if not config.targets else
                      "name the invariant in the registry, or give it a solo-style sibling")
            problems.append(
                f"{name}: RED for no stated reason — it checks {len(config.targets)}"
                f" invariant(s) and {len(config.properties)} propert(ies), no row names"
                " one, and no solo-style configuration running"
                f" {', '.join(config.armed) or 'the same switches'} is required RED, so a"
                f" RED for the INVERSE defect passes here; {remedy}")


def check_floors(configs, first, ratchets, previous, text, problems):
    """A floor may fall; it may not fall quietly."""
    stated = {}
    for line in text.splitlines():
        said = DECREASE.match(line)
        if said:
            stated[said["subject"]] = (int(said["was"]), int(said["now"]))
    if previous is None:
        problems.append(
            f"no committed {REGISTRY} differs from the working tree's, so no floor could be"
            " compared with anything — run this inside the git checkout")
        for subject in sorted(stated):
            problems.append(f"{subject}: a floor-decrease marker with nothing to compare it to")
        return
    was_rows, was_ratchets, _ = read_registry(previous)
    if not was_rows and not was_ratchets:
        # `previous is None` is not the whole of "git could not answer": an empty
        # string parses to no rows, every `before` is None, and NO FLOOR IS
        # COMPARED WITH ANYTHING while this reports nothing at all.
        problems.append(
            f"the committed {REGISTRY} parses to no rows and no ratchets, so no floor could"
            " be compared with anything — an answer of nothing reads here exactly like a"
            " registry no floor fell in")
        for subject in sorted(stated):
            problems.append(f"{subject}: a floor-decrease marker with nothing to compare it to")
        return
    was_first, _ = resolve(was_rows, sorted(configs))
    weakened = {}
    for name in sorted(configs):
        before = was_first.get(name)
        after = first.get(name)
        if before is None or before["floor"] is None or after is None:
            continue
        now = after["floor"] or 0
        if now < before["floor"]:
            weakened[name] = (before["floor"], now)
    for ratchet, before in sorted(was_ratchets.items()):
        if ratchet not in ratchets:
            # Deleting the line was the cheapest decrease of all: `security_trace.py`
            # dies on the six it names by constant, and a seventh would have had no
            # reader anywhere.
            problems.append(f"{ratchet}: recorded at {before} in the committed registry"
                            " and gone from this one — a deleted ratchet is the largest"
                            " decrease there is")
            continue
        now = ratchets[ratchet]
        # A `Max` is the same ratchet upside down: it is weakened by RISING.
        if (now < before) if not ratchet.endswith("Max") else (now > before):
            weakened[ratchet] = (before, now)
    for subject, (before, now) in sorted(weakened.items()):
        if stated.get(subject) != (before, now):
            problems.append(
                f"{subject}: floor {before} -> {now} with no justification — add"
                f" `\\* floor-decrease: {subject} {before} -> {now} <why>` beside the row,"
                " and say what was re-measured")
    for subject, (before, now) in sorted(stated.items()):
        if weakened.get(subject) != (before, now):
            problems.append(
                f"{subject}: a floor-decrease marker for {before} -> {now}, which is not the"
                " movement the committed registry shows — either the decrease is committed"
                " already and the marker has done its work, or it never happened")


def audit(formal=FORMAL, registry_text=None, previous_text=FROM_GIT, runner_text=None):
    """(problems, one-line summary) for how `floors.txt` matches `formal/*.cfg`."""
    formal = pathlib.Path(formal)
    text = registry_text if registry_text is not None else decoded(formal.parent / REGISTRY)
    runner = runner_text if runner_text is not None else (
        formal.parent / RUNNER).read_text(encoding="utf-8")
    if previous_text is FROM_GIT:
        previous_text = previous_registry(formal.parent)

    rows, ratchets, problems = read_registry(text)
    configs = {}
    for path in sorted(formal.glob("*.cfg")):
        # A directory named `*.cfg` is an `IsADirectoryError` a line later, and a
        # traceback is a report nobody can act on. `config_gen_gate.audit` has
        # the same rule over the same glob, and for the same reason.
        if path.is_file():
            configs[path.name] = Config(path)
        else:
            problems.append(f"{path.name}: a formal/*.cfg entry that is not a regular file")
    first, every = resolve(rows, sorted(configs))
    if "\r" in text:
        # `read` leaves the CR on the last field, so `[ "$distinct" -lt "$floor" ]`
        # errors, bash reads the non-zero as false, and every floored row falls
        # through to GREEN. Folded away by `read_text`, which is why this asks the
        # bytes -- the sibling guard compares bytes for the same reason.
        problems.append(f"{REGISTRY}: carries a CR, and {RUNNER} reads a floor of `200\\r`"
                        " as an integer error — which it takes for `not below the floor`")
    if len(configs) < CONFIG_FLOOR:
        problems.append(f"formal/ holds {len(configs)} configuration(s), under the floor of"
                        f" {CONFIG_FLOOR} — every check below then loops over nothing")

    reads = RUNNER_READS.search(runner)
    if reads is None:
        problems.append(f"{RUNNER} no longer extracts an invariant name the way this row"
                        " reads it — the last column is compared against nothing")
    reads = re.compile(reads["name"]) if reads else None

    repaired = repair_arms(configs, problems)
    check_completeness(rows, first, every, problems)
    check_conflicts(every, problems)
    check_switches(configs, problems)
    check_verdicts(configs, first, repaired, problems)
    check_reverted_fixes(configs, first, problems)
    check_repair_experiments(configs, first, repaired, problems)
    check_row_shape(rows, reads, problems)
    check_reasons(configs, first, problems)
    check_floors(configs, first, ratchets, previous_text, text, problems)

    families = {row["pattern"] for row in rows if GLOB.search(row["pattern"])}
    covered = sum(1 for hit in first.values() if hit and hit["pattern"] in families)
    experiments = sum(1 for name, config in configs.items()
                      if repaired.get(name) and config.armed)
    return problems, (
        f"verdict-gate: ok — {sum(1 for hit in first.values() if hit)} configuration(s)"
        f" held to {len(rows)} entries ({len(families)} wildcard families covering"
        f" {covered}), {len(ratchets)} ratchets, {len(NO_VERDICT)} exempt,"
        f" {experiments} counterfactual repair(s)"
    )


def run(formal=FORMAL):
    problems, summary = audit(formal)
    if problems:
        print(f"verdict-gate: {len(problems)} finding(s)", file=sys.stderr)
        for problem in problems[:REPORT_LIMIT]:
            print(f"  {problem}", file=sys.stderr)
        if len(problems) > REPORT_LIMIT:
            print(f"  … and {len(problems) - REPORT_LIMIT} more", file=sys.stderr)
        print(f"  {REGISTRY} is what the weekly TLC matrix is judged against", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main():
    if sys.argv[1:]:
        print("usage: verdict_gate.py", file=sys.stderr)
        return 2
    return run()


if __name__ == "__main__":
    sys.exit(main())
