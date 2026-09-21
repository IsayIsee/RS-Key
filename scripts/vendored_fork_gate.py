#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold every workspace to the vendored fork, so upstream cannot come back.

`third_party/sequential-storage/` is a local fork of the KV library every sealed
secret is stored in, and `third_party/sequential-storage.patch` is the record of
what it repairs. Item 2: the upstream page-advance loop swallowed a page-state
`Err` via `_ => continue`, so one unreadable page mid-ring was skipped and the
walk still reached the terminator and reported itself COMPLETE. Item 3: upstream
`remove_item_inner` erased from `find_first_page(PartialOpen).unwrap_or_default()`
— page 0 in the normal steady state — so a power cut mid-remove erased the newest
copy first and left an older one live for `fetch_item` to return. Both defects
are one manifest edit away, because the fork reaches a build through
`[patch.crates-io]` and through nothing else.

That stanza is wired in the root, `fuzz/` and `tools/emu/` manifests, and until
this row nothing held the three together. A workspace that lost its copy links
upstream 8.0.0 and every host test stays green: driven by putting the
page-advance defect back into the vendored copy, `rsk-store`'s walk yielded 16 of
19 items and answered `complete = true`, and `Fs::scan` fills its `decided` bitmap
from exactly that answer — so each un-yielded FID reads authoritatively absent for
the rest of the boot. The emulator HAD drifted that way once; the comment over
`tools/emu`'s stanza is the record of its suites running against a different store
library from the device's.

The subject is the LOCKFILE, not the stanza. A manifest can carry a
`[patch.crates-io]` entry that applies to nothing, while what cargo actually
resolved is in `Cargo.lock`, where a patched dependency is recorded with no
`source` and no `checksum` and a registry one carries both. So both directions
are held, and the lock is the half that cannot be talked round:

* the lock — a workspace whose lock names the crate must resolve it to the
  vendored copy, with the registry's `source` and `checksum` absent;
* the manifest — that same workspace must carry the `[patch.crates-io]` entry
  whose `path`, resolved against the workspace's own directory, IS the vendored
  directory. It is spelled differently in every manifest that carries it, so the
  string cannot be compared; it has to be resolved.

A workspace that does not depend on the crate owes neither, which is `tools/tui`
and has to stay green. A vendored crate no workspace's lock names at all is a
fork nothing builds, and that is its own direction rather than a silence.

Which forks exist is DERIVED: every directory under `third_party/` whose
`Cargo.toml` declares a `[package] name`, taken from that manifest rather than
from the directory it sits in. A `sequential-storage` written into this file
would be one more hand-written copy of the fact the row exists to stop copying —
`third_party/README.md` and the patch header are already two of them.

## What this cannot say

That the vendored copy still carries the repairs. The patch file is the record of
what the fork is FOR, and diffing it against upstream is a different rule; this
one says that whatever `third_party/` holds is what every workspace builds. Nor
does it read a workspace with no `Cargo.lock`: an unlocked workspace resolves
afresh on every build and there is none in this tree.
"""

import os
import pathlib
import sys
import tomllib

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Where a fork lives, and the registry table cargo applies it through. A crate
#: vendored anywhere else is not this row's subject; `third_party/README.md` tells
#: apart the three kinds that live here.
VENDOR = "third_party"
REGISTRY = "crates-io"
MANIFEST = "Cargo.toml"
LOCK = "Cargo.lock"

#: What a `[[package]]` carries when cargo resolved it from the registry after
#: all. Either key is enough to say so: a patched dependency has neither, and a
#: lock regenerated over a lost `[patch]` grows both at once.
REGISTRY_KEYS = ("source", "checksum")

#: Floors under the two derivations, both of the "a finder that has stopped
#: finding loops over nothing and exits 0" shape. The workspace floor is 2 rather
#: than 1 because the defect is a DETACHED workspace — a reading that sees only
#: the root's lock is blind to every case this row is about.
FLOOR_FORKS = 1
FLOOR_WORKSPACES = 2


def load(root, rel, problems):
    """One parsed TOML file, or None and a problem.

    Reported rather than skipped: a manifest this cannot read is a workspace
    nothing below is held to, and skipping is how that stops being noticed.
    """
    try:
        return tomllib.loads((root / rel).read_text())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        problems.append(f"{rel.as_posix()} cannot be read as TOML: {error}")
        return None


def forks(root, problems):
    """{crate: its directory} for every vendored crate under `third_party/`.

    The NAME comes from the manifest's `[package]`, not from the directory it
    sits in: what a `[patch]` entry has to spell is the crate's name, and the two
    are equal only by convention. A directory with no `[package]` is nothing to
    patch — the two vendored pytest suites and the generated font tables are that
    case, and so is a bare `[workspace]`.
    """
    found = {}
    for rel in sorted(gate_lines.tree_files(root)):
        if rel.name != MANIFEST or rel.parent.parent.as_posix() != VENDOR:
            continue
        data = load(root, rel, problems)
        if data is None:
            continue
        name = data.get("package", {}).get("name")
        if not name:
            continue
        if name in found:
            problems.append(
                f"`{name}` is vendored twice, at {found[name].as_posix()} and"
                f" {rel.parent.as_posix()} — a `[patch]` path can only name one of"
                " them, so the other is a fork nothing builds"
            )
        found[name] = rel.parent
    return found


def workspaces(root):
    """Every workspace of the checkout, as the directory holding its `Cargo.lock`.

    A lock INSIDE `third_party/` is upstream's own file and not one of this tree's
    workspaces: a path dependency's lock is ignored by the build that consumes it,
    so holding it to a `[patch]` would be a red about nothing.
    """
    return [
        rel.parent
        for rel in sorted(gate_lines.tree_files(root))
        if rel.name == LOCK and not rel.as_posix().startswith(f"{VENDOR}/")
    ]


def resolved(lock, crate):
    """Every `[[package]]` the lock records for `crate`, in file order.

    A list and not one entry: two versions of a crate resolve to two tables, and
    a dict keyed by name would hold whichever came last while the other linked
    the registry unread.
    """
    return [package for package in lock.get("package", []) if package.get("name") == crate]


def points_at(workspace, spelled):
    """`spelled` resolved against the workspace's own directory, from the root.

    Lexically, because the answer is a path in the checkout and not on this disk,
    and against the DIRECTORY rather than the string for the reason the module
    docstring gives: the three manifests spell one directory three ways.
    """
    return os.path.normpath((workspace / spelled).as_posix())


def held(workspace, manifest, entries, crate, home):
    """Both directions for one workspace the lock says depends on `crate`."""
    problems = []
    for entry in entries:
        upstream = [key for key in REGISTRY_KEYS if key in entry]
        if upstream:
            problems.append(
                f"{(workspace / LOCK).as_posix()} resolves `{crate}`"
                f" {entry.get('version', '?')} from the registry — it carries"
                f" {', '.join(upstream)}, and a patched dependency has neither."
                f" That workspace builds upstream, not {home.as_posix()}"
            )
    spelled = manifest.get("patch", {}).get(REGISTRY, {}).get(crate)
    where = (workspace / MANIFEST).as_posix()
    if spelled is None:
        problems.append(
            f"{where} depends on `{crate}` and carries no [patch.{REGISTRY}] entry"
            f" for it — that workspace resolves the crates.io copy, and"
            f" {home.as_posix()} is the fork the firmware builds"
        )
    elif not isinstance(spelled, dict) or "path" not in spelled:
        # A bare `= "8.0.1"` is legal TOML and cargo refuses it, so it is a
        # spelling this has to name rather than iterate the characters of.
        said = sorted(spelled) if isinstance(spelled, dict) else [spelled]
        problems.append(
            f"{where} patches `{crate}` with {said} rather than a `path` —"
            f" only a path reaches {home.as_posix()}"
        )
    elif (aimed := points_at(workspace, spelled["path"])) != home.as_posix():
        problems.append(
            f"{where} patches `{crate}` to {aimed}, and the vendored copy is"
            f" {home.as_posix()} — the path is relative to the workspace, so a"
            " stanza copied between manifests aims one directory level out"
        )
    return problems


def audit(root):
    """(problems, one-line summary) over every vendored fork and every workspace."""
    root = pathlib.Path(root)
    problems: list[str] = []
    vendored = forks(root, problems)
    roots = workspaces(root)
    if len(vendored) < FLOOR_FORKS:
        problems.append(
            f"no directory under {VENDOR}/ declares a `[package] name` — with no"
            " fork derived, every rule below compares an empty set to an empty one"
        )
    if len(roots) < FLOOR_WORKSPACES:
        problems.append(
            f"the checkout has {len(roots)} {LOCK}(s), under the floor of"
            f" {FLOOR_WORKSPACES} — the case this row is about is a DETACHED"
            " workspace, so a reading that finds one is blind to all of them"
        )
    if problems:
        return problems, ""

    read = {}
    for workspace in roots:
        lock = load(root, workspace / LOCK, problems)
        manifest = load(root, workspace / MANIFEST, problems)
        if lock is not None and manifest is not None:
            read[workspace] = (lock, manifest)
    if problems:
        return problems, ""

    said = []
    for crate, home in sorted(vendored.items()):
        reached, idle = [], []
        for workspace, (lock, manifest) in read.items():
            entries = resolved(lock, crate)
            # A workspace that does not depend on the crate owes neither
            # direction: `tools/tui` is that case and a rule demanding a stanza
            # from it would be a red on a manifest that is right.
            (reached if entries else idle).append(workspace)
            if entries:
                problems += held(workspace, manifest, entries, crate, home)
        if not reached:
            problems.append(
                f"{home.as_posix()} vendors `{crate}` and no workspace's {LOCK}"
                " names it — a fork nothing builds is a repair nothing has"
            )
        said.append(
            f"{crate} at {home.as_posix()}, linked by"
            f" {', '.join((w / MANIFEST).as_posix() for w in reached) or 'nothing'}"
            f"; not depended on by {', '.join((w / MANIFEST).as_posix() for w in idle) or 'nothing'}"
        )
    return problems, f"vendored-fork-gate: ok — {'; '.join(said)}"


def run(root):
    problems, summary = audit(root)
    if problems:
        print("vendored-fork-gate:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nThe vendored fork reaches a build through [patch.crates-io] and\n"
            "nothing else, so a workspace that lost its stanza links upstream\n"
            "8.0.0 — whose walk reports a page it could not read as a COMPLETE\n"
            "enumeration, and whose torn remove leaves an older copy live. Every\n"
            "host test stays green either way, which is why this is a row.",
            file=sys.stderr,
        )
        return 1
    print(summary)
    return 0


def main():
    if sys.argv[1:]:
        print("usage: vendored_fork_gate.py", file=sys.stderr)
        return 2
    return run(ROOT)


if __name__ == "__main__":
    sys.exit(main())
