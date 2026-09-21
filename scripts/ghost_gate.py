#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold `NoAuthorizationBypass`'s ghost clause against the actions that populate it.

A `"Name" \\notin viol` clause is only as strong as the completeness of the
assignments that write the name, and an action that should record and does not
makes its invariant silently pass. `RSKeySecurityState.tla` knows this — it says
so above the three ghosts — and then names the actions in a COMMENT. That comment
claimed eleven for its whole life. The tree has **twenty-one**, over
**twenty-four routes**, and nothing compared the sentence to the set.

`R1oOutcomeCoverage` is the only completeness equality inside the models, and it
guards a different set (`TokenOutcomeActions`, 23 outcome producers). This is the
second one, over the authorization-recording set, and it lives here rather than
in TLA+ for one reason: a route is a syntactic thing. TLA+ can compare two sets
of names, which is what the comment already failed at; it cannot say that
`RegisterStart` records by TWO independent routes, so deleting one leaves the
other standing and a name-set equality green over a half-deleted guard.

What is derived, and nothing about it is stored:

* the ACTIONS — every operator `Next` reaches. A roster of actions written down
  beside the module is the same copy the comment was;
* the ALIASES — every operator whose body carries the invariant's name and is not
  the invariant itself. `TokenBypass` is one today; a second arrives as a set of
  new routes rather than as silence;
* the ROUTES — one per occurrence of the name (literal or alias) inside a `viol'`
  assignment, labelled by the operator that carries it. A helper's routes are
  inherited by every action that calls it, which is how `PinAttempt`'s one route
  reaches `GetPinToken`, `WrongPin`, `MintPpuat` and `ChangePinStart`.

What is compared:

* every derived action has exactly one entry and every entry names a derived
  action, so an action that starts recording arrives unowned;
* the ROUTE LIST of each entry equals the derived one. Deleting one of
  `RegisterStart`'s two routes reddens this row naming the route — a per-action
  equality would not, and that is the hole the exit criterion this file answers
  was written against;
* the POLICY LIST too — every `*Policy` operator the assignment consults. A route
  kept and its guard swapped is the same defect one layer in, and the two-way
  equality is what makes swapping `TouchPolicy` for `ButtonFreePolicy` a finding
  rather than an edit;
* the roster is not empty, and neither is the route set. A derivation that finds
  nothing satisfies every rule above.

Deliberately not here: whether the action records the RIGHT thing. That is what
`Solo_*.cfg` and the co-refutation twins are for. This row keeps the ghost's
denominator honest.
"""

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = pathlib.Path("formal/RSKeySecurityState.tla")
LEDGER = pathlib.Path("assurance/ghost_actions.toml")

#: The invariant whose ghost this is. One name, because a second ghost would want
#: its own ledger rather than a column here.
INVARIANT = "NoAuthorizationBypass"

#: How a guard is spelled in this module, so the POLICY each route consults is
#: derived beside the route rather than labelled beside it. A taxonomy written
#: here would be the comment again: the invariant's own sentence names five gates
#: and the ghost records a sixth family -- the touch -- which is exactly the kind
#: of thing a hand-kept column gets to be wrong about.
POLICY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*Policy$")

#: The operator whose body IS the ghost's disjunction over the whole model.
#: Everything an action can reach starts here; a roster written beside it would
#: be the copy this file exists to delete.
ENTRY = "Next"

#: Definitions that mention the name and are not a route: the invariant itself
#: and the roster of every invariant name.
NOT_A_ROUTE = (INVARIANT, "InvNames")

#: Below these the derivation stopped reading the module rather than the module
#: stopped recording, and every rule above passes over the empty set either way.
#: Set under the measured 21/24 so ordinary movement does not trip them.
FLOOR_ACTIONS = 15
FLOOR_ROUTES = 18

DEF = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(\([^)]*\))?\s*==", re.M)
VIOL = re.compile(r"^(\s*)(?:/\\\s*)?viol'\s*=", re.M)
CONJUNCT = re.compile(r"^(\s*)/\\", re.M)


def strip_comments(text: str) -> str:
    """The module with `(* … *)` blocks and `\\*` line comments blanked.

    Not cosmetic: the comment under `TokenBypass` names `BugConsumeKeepsMcGa` and
    the one under `PinAttempt` names four call sites, so a scan over raw text
    reports `OpAdvancesIsOneActivity` as a caller of both — measured, and it is
    the first thing a route derivation gets wrong.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("(*", i):
            stop = text.find("*)", i + 2)
            i = n if stop < 0 else stop + 2
            continue
        if text.startswith("\\*", i):
            stop = text.find("\n", i)
            i = n if stop < 0 else stop
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def definitions(text: str) -> dict[str, str]:
    """`name -> body`, each body running to the next top-level definition."""
    marks = [(m.group(1), m.start()) for m in DEF.finditer(text)]
    bodies = {}
    for index, (name, start) in enumerate(marks):
        end = marks[index + 1][1] if index + 1 < len(marks) else len(text)
        bodies[name] = text[start:end]
    return bodies


def references(body: str, names) -> set[str]:
    """Which of `names` this body names as a word."""
    words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body))
    return {name for name in names if name in words}


def assignments(body: str) -> list[str]:
    """The right-hand side of every `viol'` assignment in `body`.

    Closed at the next conjunct indented no deeper than the assignment's own, the
    way TLA+ reads it. Closing at the next `/\\` at any depth would cut
    `RegisterStart`'s second route off its first.
    """
    out = []
    for found in VIOL.finditer(body):
        indent = len(found.group(1))
        rest = body[found.end():]
        stop = len(rest)
        for conjunct in CONJUNCT.finditer(rest):
            if len(conjunct.group(1)) <= indent:
                stop = conjunct.start()
                break
        out.append(rest[:stop])
    return out


def aliases(bodies: dict[str, str], actions=frozenset()) -> set[str]:
    """Operators that stand for a set carrying the name — `TokenBypass` today.

    An ACTION is never one, whatever its shape. Without that an action whose
    `viol'` the line-anchored scanner missed was classified as an alias, skipped
    by the backstop, and reported one operator over — red, but naming the caller
    instead of the recorder.
    """
    quoted = f'"{INVARIANT}"'
    return {
        name
        for name, body in bodies.items()
        if quoted in body
        and name not in NOT_A_ROUTE
        and name not in actions
        and not assignments(body)
    }


def policies_of(bodies: dict[str, str], name: str, policy_names) -> list[str]:
    """The guards this operator's `viol'` assignments consult."""
    text = " ".join(assignments(bodies[name]))
    return sorted(references(text, policy_names))


def routes_of(bodies: dict[str, str], name: str, alias_names) -> list[str]:
    """`owner/token` per occurrence of the name inside this operator's `viol'`.

    A repeat takes a `#n` suffix so two occurrences in one operator are two
    routes rather than one, which is the whole point of counting routes.
    """
    quoted = f'"{INVARIANT}"'
    found: list[str] = []
    for rhs in assignments(bodies[name]):
        for _ in re.finditer(re.escape(quoted), rhs):
            found.append("literal")
        for alias in sorted(alias_names):
            for _ in re.finditer(rf"\b{re.escape(alias)}\b", rhs):
                found.append(alias)
    out, seen = [], {}
    for token in found:
        seen[token] = seen.get(token, 0) + 1
        suffix = "" if seen[token] == 1 else f"#{seen[token]}"
        out.append(f"{name}/{token}{suffix}")
    return out


def derive(root: pathlib.Path) -> dict[str, dict[str, list[str]]]:
    """`action -> {routes, policies}`, everything read out of the module."""
    return _derive(strip_comments((root / MODULE).read_text(encoding="utf-8")))[0]


def _derive(text: str):
    """(the roster, the direct routes per operator, the bodies) over one module."""
    bodies = definitions(text)
    if ENTRY not in bodies:
        return {}, {}, bodies, set()
    actions = references(bodies[ENTRY], set(bodies) - {ENTRY})
    alias_names = aliases(bodies, actions)
    policy_names = {name for name in bodies if POLICY.fullmatch(name)}
    direct = {
        name: (
            routes_of(bodies, name, alias_names),
            policies_of(bodies, name, policy_names),
        )
        for name in bodies
        if name not in NOT_A_ROUTE and routes_of(bodies, name, alias_names)
    }
    helpers = {name: found for name, found in direct.items() if name not in actions}
    # To a FIXED POINT, not one level: a helper that calls a helper reached
    # nothing, so a route two calls out from an action was derived by no one.
    # `store_writers` one file over closes the same shape the same way.
    while True:
        grown = {
            name: (
                list(helpers.get(name, ([], []))[0]),
                list(helpers.get(name, ([], []))[1]),
            )
            for name, body in bodies.items()
            if name not in actions and name not in NOT_A_ROUTE
        }
        added = False
        for name, (routes, policies) in grown.items():
            for callee in sorted(references(bodies[name], set(helpers)) - {name}):
                for route in helpers[callee][0]:
                    if route not in routes:
                        routes.append(route)
                        added = True
                for policy in helpers[callee][1]:
                    if policy not in policies:
                        policies.append(policy)
                        added = True
            if routes:
                helpers[name] = (routes, policies)
        if not added:
            break
    out: dict[str, dict[str, list[str]]] = {}
    for action in sorted(actions):
        routes, policies = (list(x) for x in direct.get(action, ([], [])))
        for helper in sorted(references(bodies[action], set(helpers))):
            routes.extend(helpers[helper][0])
            policies.extend(helpers[helper][1])
        if routes:
            out[action] = {
                "routes": sorted(set(routes)),
                "policies": sorted(set(policies)),
            }
    return out, direct, bodies, alias_names


def unaccounted(bodies: dict[str, str], direct: dict, alias_names) -> list[str]:
    """Every mention of the name the route derivation did not account for.

    THE BACKSTOP, and the derivation needs one: `VIOL` is line-anchored, so a
    `viol'` sharing a line with the conjunct before it, a whole definition on one
    line, an assignment inside an `IF … THEN … ELSE`, or a `LET`-bound set
    carrying the name are all invisible to it — measured, four spellings, each
    green with the action recording. The floors cannot see that: 21 of 22 actions
    still derive. This compares the module's own occurrence count with what the
    routes claim, per operator, so reading LESS than the module has is a finding
    rather than a shorter roster.
    """
    quoted = f'"{INVARIANT}"'
    out = []
    for name, body in sorted(bodies.items()):
        if name in NOT_A_ROUTE or name in alias_names:
            continue
        seen = body.count(quoted) + sum(
            len(re.findall(rf"\b{re.escape(alias)}\b", body)) for alias in alias_names
        )
        want = len(direct.get(name, ([], []))[0])
        if seen != want:
            out.append(
                f"{name}: names {INVARIANT} {seen} time(s) and the route derivation"
                f" accounts for {want} — it read less than the module has"
            )
    return out


#: What an `[[action]]` may say, and the only table this file may have. Neither
#: was held: an invented key in the first record left this row at EXIT=0, measured.
ACTION_FIELDS = ("name", "policies", "routes", "why")
TABLES = ("action",)


def audit(root: pathlib.Path) -> tuple[list[str], str]:
    findings: list[str] = []
    text = strip_comments((root / MODULE).read_text(encoding="utf-8"))
    derived, direct, bodies, alias_names = _derive(text)
    if ENTRY not in bodies:
        findings.append(
            f"{MODULE} defines no `{ENTRY}` — the roster starts there, so every"
            " action below is unreached rather than absent"
        )
    findings.extend(unaccounted(bodies, direct, alias_names))
    ledger = tomllib.loads((root / LEDGER).read_text(encoding="utf-8"))
    if stray := sorted(set(ledger) - set(TABLES)):
        findings.append(
            f"{LEDGER} carries {stray}, which nothing reads — a table added here is"
            " held by no rule and shown to no reader"
        )
    entries = ledger.get("action", [])
    owned: dict[str, dict] = {}
    for index, entry in enumerate(entries):
        if stray := sorted(set(entry) - set(ACTION_FIELDS)):
            findings.append(
                f"{LEDGER}: entry #{index + 1} carries {stray}, which nothing reads"
            )
        name = entry.get("name")
        if not name:
            findings.append(f"{LEDGER}: entry #{index + 1} has no 'name'")
            continue
        if name in owned:
            findings.append(f"{name}: owned twice in {LEDGER}")
            continue
        owned[name] = entry

    for name in sorted(set(derived) - set(owned)):
        findings.append(
            f"{name}: records {INVARIANT} by {len(derived[name]['routes'])} route(s) and"
            f" has no entry in {LEDGER} — the ghost's denominator grew unowned"
        )
    for name in sorted(set(owned) - set(derived)):
        findings.append(
            f"{name}: owned in {LEDGER} and records {INVARIANT} nowhere — either the"
            " action stopped recording or it is a stale entry"
        )
    for name in sorted(set(derived) & set(owned)):
        for axis in ("routes", "policies"):
            want = sorted(owned[name].get(axis, []))
            got = sorted(derived[name][axis])
            if want == got:
                continue
            gone = sorted(set(want) - set(got))
            new = sorted(set(got) - set(want))
            detail = ", ".join(
                [f"gone: {', '.join(gone)}"] * bool(gone)
                + [f"new: {', '.join(new)}"] * bool(new)
            )
            findings.append(
                f"{name}: {LEDGER} records {len(want)} {axis[:-1]}(s) and the module has"
                f" {len(got)} — {detail}"
            )
        if not owned[name].get("why", "").strip():
            findings.append(f"{name}: an owner with no reason is not one — 'why' is empty")

    total = sum(len(found["routes"]) for found in derived.values())
    if len(derived) < FLOOR_ACTIONS:
        findings.append(
            f"{len(derived)} recording action(s) derived, under the floor of"
            f" {FLOOR_ACTIONS} — the derivation stopped reading {MODULE}"
        )
    if total < FLOOR_ROUTES:
        findings.append(
            f"{total} route(s) derived, under the floor of {FLOOR_ROUTES} — the"
            " derivation stopped reading the `viol'` assignments"
        )
    guards = {p for found in derived.values() for p in found["policies"]}
    summary = (
        f"ghost-gate: ok — {len(derived)} action(s) record {INVARIANT} over {total}"
        f" route(s), consulting {len(guards)} guard(s)"
    )
    return findings, summary


def main() -> int:
    findings, summary = audit(ROOT)
    if findings:
        print("ghost-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
