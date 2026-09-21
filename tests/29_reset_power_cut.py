#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""HIL: cut real board power during authenticatorReset, then inspect the next boot.

    nix develop -c python tests/29_reset_power_cut.py

⚠ DESTRUCTIVE: wipes FIDO credentials/PIN and deliberately removes power during
a flash mutation. Use a throwaway key running the no-touch test image.

This is the runtime witness for `ResetNeverWeakensSurvivingState` and its three
clauses: `ResetKeepsThePinGate`, `ResetKeepsTheAlwaysUvGate`, and
`ResetKeepsTheBackupSeal`. It provisions one owner seed, seals its export window,
sets a PIN, enables alwaysUv, and creates a resident credential. While RESET is
in flight the operator unplugs the key. On the next boot:

* the old credential must not authorize without either gate;
* if the PIN or alwaysUv record disappeared, that refusal is mandatory;
* if the backup seal disappeared, the now-exportable seed must be a fresh seed,
  never the owner's pre-reset seed.

For a relay rig, set `RSK_POWER_CUT_CMD` to an argv-style command that removes USB
power long enough for the device to disappear and then restores it. Optional
`RSK_POWER_CUT_DELAY_MS` selects the delay after the RESET sender starts
(default [`DEFAULT_DELAY_MS`]). Without it, the script asks the operator to yank
and restore the cable.

## What says the wipe had started

A cut that lands before the RESET request reaches the board satisfies every
assertion above — a device on which the reset never began is trivially
fail-closed — so the run needs a device-sourced fact that the wipe was running.
The only one on this wire is `CTAPHID_KEEPALIVE`: `rsk_usb::ctaphid`'s
`run_with_keepalive` is entered only after the whole CBOR message is
reassembled, and it writes its first frame one `KEEPALIVE_MS` timer later, so a
keepalive says the request arrived AND the handler had been running that long.
The status byte separates the two ways it can be busy — `STATUS_UPNEEDED` is the
touch ceremony, which stands ahead of every flash write, and only
`STATUS_PROCESSING` is past it. So `STATUS_PROCESSING` is the only frame that
confirms a run, and everything else is INCONCLUSIVE with a reason attached: the
board ANSWERED and refused to start (CTAP 2.1 §6.6 says `0x30` well under the
floor, which no later cut changes), `STATUS_UPNEEDED` says it is still waiting
for a finger, and only a silent wire is the cut that beat the request there.

A keepalive counts only when it carries OUR channel id. hidraw and IOHIDManager
hand every input report to every open handle, so a second host process with a
slow CBOR command in flight streams its own `PROCESSING` keepalives into this
read queue while our request is still unread in the OUT buffer — the shape that
proves a reset began on somebody else's channel, and ours never left the host.

That is a lower bound on `inside the handler`, not on `the first erase landed`:
nothing on the wire tells the ceremony's return from `wipe`'s first tombstone.
And it exists at all only because the operation is slower than `KEEPALIVE_MS` —
487.2 ms measured on the board `assurance/board/PLAT-FLASH-001.toml` cites.

## The record

Each cut appends one JSON object to [`CUT_RECORD`], because one run is one cut
and a sweep is a series of runs. Zero is `worker.start()`, the instant the RESET
sender is released — the same zero `RSK_POWER_CUT_DELAY_MS` counts from. Four
instants are written down, and not one of them is when the supply went:

* `wipe_lower_ms.first_keepalive` — the earliest instant the device is known to
  have been inside the RESET handler.
* `cut_lower_ms.last_frame` — the newest frame that came back. A LOWER bound on
  the cut, and an empty read is not a frame: hidapi returns an empty list when a
  read times out rather than raising, which `ctaphid.send_cbor` asserts on.
* `cut_upper_ms.transfer_death` — when the sender's transfer died, taken inside
  the thread rather than after the join. An upper bound only when the handle
  itself failed (`death.kind = "hid_error"`), whose error is then the USB
  stack's detection latency; a transfer that died of ctaphid's own read budget
  bounds nothing, and is written as null under the kind that says so.
* `cut_upper_ms.host_saw_gone` — when `replug.wait_gone()` first missed the
  device. Looser, with an error floor of `replug.POLL_S`.

`verdict` is the CUT's and not the run's — the run answers with its exit code —
and it is `torn`, `unconfirmed` (no PROCESSING frame), `missed` (the RESET
finished first), `stuck`, `relay_failed`, `never_gone`, `never_back` or
`aborted`. The line is written when the cut happens, so a record that cannot be
written can never stand in for an assertion that failed after it.

Which is why the line cannot carry the run's exit code: `main`'s post-reboot
assertions — the ones this row exists to catch failing — run AFTER it. A run
that failed them leaves a `torn` line a passing run would also have left. So the
line carries [`RUN_ID`] and a `records` sentence saying so in as many words, and
the same id is on the console beside `PASS`: the pair is what tells a pasted
record which transcript it came out of. Read the exit code off that transcript.
"""
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import replug  # noqa: E402
from ctaphid import (  # noqa: E402
    CTAPHID_KEEPALIVE,
    Protocol2,
    client_pin,
    decode,
    enc,
    send_cbor,
)
from rsk import backup  # noqa: E402

PIN = b"6482"
RP = "reset-power-cut.example"
PERM_MC, PERM_ACFG = 0x01, 0x20
MAKE_CREDENTIAL, GET_ASSERTION, GET_INFO, AUTH_CONFIG = 0x01, 0x02, 0x04, 0x0D
CTAP_RESET = 0x07
PUAT_PREFIX = b"\xff" * 32
# `rsk_usb::ctaphid`: the status byte a KEEPALIVE carries. PROCESSING is the
# worker running the command; UPNEEDED is the touch ceremony, which on this
# command stands ahead of the first flash write, so it proves the opposite.
STATUS_PROCESSING, STATUS_UPNEEDED = 0x01, 0x02
# `rsk_usb::ctaphid::KEEPALIVE_MS`: the transport races the handler against this
# timer, so the FIRST keepalive is this far into the command and there is no
# earlier device-sourced proof that the reset began.
KEEPALIVE_MS = 100
# The relay's default cut, above the keepalive so a default run can be confirmed
# at all, and well inside the 487.2 ms the wipe measured on the cited board.
DEFAULT_DELAY_MS = 2 * KEEPALIVE_MS
# One JSON object per cut, appended: PLAT-FLASH-001 asks for the delays LISTED
# and a record a rerun overwrites lists nothing. Outside the checkout so a run
# leaves nothing untracked in the tree; `RSK_POWER_CUT_LOG` aims it at a file
# meant to be committed. NOT `tests/54_sram_residue.py`'s fresh `mkdtemp`: that
# default is per-run because its dump is a key image, and a per-run directory is
# exactly what a sweep must not have — these lines accumulate or they enumerate
# nothing. So the directory is stable and per-uid, made 0700, and the append
# refuses a symlink. `os.getuid` stays behind the `or`: an operator who aimed the
# record somewhere must not need it to import the script at all.
CUT_RECORD = os.environ.get("RSK_POWER_CUT_LOG") or os.path.join(
    tempfile.gettempdir(), f"rs-key-cuts-{os.getuid()}", "PLAT-FLASH-001-cuts.jsonl"
)
# One run is one cut, so this names both. It is in the record and on the console
# line, because `verdict` below is the CUT's: `main`'s post-reboot assertions run
# after the line is written, and a run they FAIL leaves a line a passing run
# would have left. The id is what joins that line to the transcript that failed.
RUN_ID = os.urandom(4).hex()


def mac(token, data):
    from cryptography.hazmat.primitives import hashes, hmac as chmac

    h = chmac.HMAC(token, hashes.SHA256())
    h.update(data)
    return h.finalize()


def set_pin(dev, cid):
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    assert ka[0] == 0, f"getKeyAgreement: {ka[0]:#x}"
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    padded = PIN + b"\x00" * (64 - len(PIN))
    encrypted = proto.encrypt(padded)
    r = client_pin(
        dev,
        cid,
        {1: 2, 2: 3, 3: proto.cose(), 4: proto.authenticate(encrypted), 5: encrypted},
    )
    assert r[0] == 0, f"setPIN: {r[0]:#x}"


def token_for(dev, cid, permission, rp=None):
    ka = client_pin(dev, cid, {1: 2, 2: 2})
    assert ka[0] == 0, f"getKeyAgreement: {ka[0]:#x}"
    cose = decode(ka[1:])[1]
    proto = Protocol2(cose[-2], cose[-3])
    req = {
        1: 2,
        2: 9,
        3: proto.cose(),
        6: proto.encrypt(hashlib.sha256(PIN).digest()[:16]),
        9: permission,
    }
    if rp is not None:
        req[10] = rp
    r = client_pin(dev, cid, {k: req[k] for k in sorted(req)})
    assert r[0] == 0, f"getPinUvAuthToken: {r[0]:#x}"
    return proto.decrypt(decode(r[1:])[2])


def make_resident_credential(dev, cid):
    client_data_hash = hashlib.sha256(b"phase-6 reset power cut").digest()
    token = token_for(dev, cid, PERM_MC, RP)
    request = {
        1: client_data_hash,
        2: {"id": RP},
        3: {"id": b"\x29\x29\x29\x29", "name": "phase6"},
        4: [{"alg": -7, "type": "public-key"}],
        7: {"rk": True},
        8: mac(token, client_data_hash),
        9: 2,
    }
    r = send_cbor(dev, cid, bytes([MAKE_CREDENTIAL]) + enc(request))
    assert r[0] == 0, f"makeCredential: {r[0]:#x}"
    auth_data = decode(r[1:])[2]
    cred_len = int.from_bytes(auth_data[53:55], "big")
    credential_id = auth_data[55:55 + cred_len]
    assert credential_id, "makeCredential returned an empty credential id"
    return credential_id


def enable_always_uv(dev, cid):
    token = token_for(dev, cid, PERM_ACFG)
    verify = PUAT_PREFIX + bytes([AUTH_CONFIG, 0x02])
    request = {1: 0x02, 3: 2, 4: mac(token, verify)}
    r = send_cbor(dev, cid, bytes([AUTH_CONFIG]) + enc(request))
    assert r[0] == 0, f"toggleAlwaysUv: {r[0]:#x}"
    info = decode(send_cbor(dev, cid, bytes([GET_INFO]))[1:])
    assert info[4].get("alwaysUv") is True, "alwaysUv did not engage"


def old_credential_without_gates(dev, cid, credential_id):
    request = {
        1: RP,
        2: hashlib.sha256(b"post-cut assertion").digest(),
        3: [{"id": credential_id, "type": "public-key"}],
    }
    return send_cbor(dev, cid, bytes([GET_ASSERTION]) + enc(request))[0]


class TappedHid:
    """`dev` with a clock on it: what came back from the DEVICE, and when.

    `send_cbor` writes the request and then blocks in `read`, so the newest
    frame before the handle dies is the newest instant the board is known to
    have been powered. An EMPTY frame is not one: hidapi returns an empty list
    when a read times out and raises nothing, which is the read `send_cbor`'s
    own `len(r) >= 5` assert exists for.

    A keepalive counts only on `cid`. Every open handle on this device sees
    every input report, so another host process's ceremony writes `PROCESSING`
    frames into this queue while our own request is still sitting unread in the
    OUT buffer — and unscoped, those frames say the wipe began when what began
    was somebody else's command. Same reason `ctaphid_init` matches its nonce.
    `last_frame` is deliberately NOT scoped: any frame at all, on any channel,
    is the board answering, which is the whole of what that bound claims.
    """

    def __init__(self, dev, cid):
        self.dev = dev
        self.cid = cid
        self.last_frame = None  # when a frame last came back from the device
        self.keepalives = []  # (status byte, perf_counter) per KEEPALIVE frame
        self.foreign_keepalives = 0  # …on another channel: not this request's
        self.empty_reads = 0
        self.death = None  # (perf_counter, call) of the call the handle failed

    def write(self, data):
        try:
            return self.dev.write(data)
        except Exception:
            if self.death is None:
                self.death = (time.perf_counter(), "write")
            raise

    def read(self, length, timeout_ms):
        try:
            frame = self.dev.read(length, timeout_ms)
        except Exception:
            if self.death is None:
                self.death = (time.perf_counter(), "read")
            raise
        if not frame:
            self.empty_reads += 1
            return frame
        self.last_frame = time.perf_counter()
        if len(frame) > 7 and frame[4] == CTAPHID_KEEPALIVE:
            if bytes(frame[:4]) == self.cid:
                self.keepalives.append((frame[7], self.last_frame))
            else:
                self.foreign_keepalives += 1
        return frame

    def close(self):
        self.dev.close()

    def processing_at(self):
        """When the device first said PROCESSING, or None if it never did."""
        return self.first_said(STATUS_PROCESSING)

    def touch_wait_at(self):
        """The same for UPNEEDED: a ceremony that stands ahead of every flash
        write, so a cut in it landed before the wipe rather than inside it."""
        return self.first_said(STATUS_UPNEEDED)

    def first_said(self, status):
        at = (when for carried, when in self.keepalives if carried == status)
        return next(at, None)


def bounds(opened, gone, tap, outcome):
    """The measured half of a cut record: what each instant bounds, and its error.

    Pure, and split out for that: the classification below is one decision per
    fact, and a dict literal with the branches inline is where the last version
    of it certified a bound it had not earned.
    """

    def since(mark):
        return None if mark is None or opened is None else round((mark - opened) * 1000, 1)

    if outcome.get("error") is None:
        death = None  # the transfer survived, so there is nothing to bound with
    elif tap.death is not None:
        # The handle itself failed: power went at or before it, and the error is
        # the USB stack's own detection latency, which nothing here measures.
        death = {"kind": "hid_error", "call": tap.death[1], "bounds_the_cut": True}
    elif tap.empty_reads:
        # `ctaphid.read`'s 20 s budget expired and hidapi returned empty. That is
        # the HOST giving up, at an instant the supply had no part in.
        death = {"kind": "read_timeout", "call": "read", "bounds_the_cut": False}
    else:
        death = {"kind": "host_assert", "call": None, "bounds_the_cut": False}
    return {
        "wipe_observed": tap.processing_at() is not None,
        "keepalives": [status for status, _ in tap.keepalives],
        "wipe_lower_ms": {"first_keepalive": since(tap.processing_at())},
        "cut_lower_ms": {"last_frame": since(tap.last_frame)},
        "cut_upper_ms": {
            "transfer_death": since(tap.death[0]) if death and death["bounds_the_cut"] else None,
            "host_saw_gone": since(gone),
        },
        "error_ms": {
            "last_frame": None,
            "transfer_death": None,
            "host_saw_gone": round(replug.POLL_S * 1000, 1),
        },
        "death": death,
        "empty_reads": tap.empty_reads,
        "foreign_keepalives": tap.foreign_keepalives,
        "sender": outcome.get("error") or repr(outcome.get("response")),
    }


def append_cut(cut):
    """Append one cut to CUT_RECORD. Writes; says nothing — [`say_cut`] does that.

    Appended and never rewritten: one run is one cut, so the sweep is a series
    of runs and this file is the only place they can be enumerated.

    `O_NOFOLLOW` and 0700 because the default directory has a predictable name
    in a shared temp. It refuses a SYMLINK at the final component and nothing
    else: a directory or a file already planted there is appended to, and so is
    a hard link. That is deliberate — the normal case for this file IS one that
    already exists, because a sweep accumulates — and what separates our lines
    from anyone else's is [`RUN_ID`] on each of them, not the path.
    """
    directory = os.path.dirname(CUT_RECORD)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
    with os.fdopen(os.open(CUT_RECORD, flags, 0o600), "a") as record:
        record.write(json.dumps(cut, sort_keys=True) + "\n")


def say_cut(cut):
    """Say on the console what each number in `cut` bounds, and what it does not."""
    # `is not None`, because RSK_POWER_CUT_DELAY_MS=0 is a delay somebody chose.
    ordered = cut["commanded_delay_ms"]
    said = f"commanded delay {ordered} ms" if ordered is not None else "no commanded delay"
    print(f"cut appended to {CUT_RECORD}: {cut['verdict']}, {cut['arm']} arm, {said} "
          f"[run {cut['run_id']}]")
    print(f"   zero = {cut['zero']}")
    began = cut["wipe_lower_ms"]["first_keepalive"]
    if began is None:
        print("   the device was NOT seen inside the reset: no PROCESSING keepalive came back")
        print(f"   what the RESET sender came back with: {cut['sender']}")
        if cut["foreign_keepalives"]:
            print(f"   {cut['foreign_keepalives']} keepalive(s) came back on ANOTHER "
                  "channel: the device was busy with somebody else's command")
    else:
        print(f"   the device was inside the reset by {began} ms after zero (its first "
              f"PROCESSING keepalive, which the transport writes only after "
              f"{KEEPALIVE_MS} ms of the handler running)")
    for edge, edges in (("lower", cut["cut_lower_ms"]), ("upper", cut["cut_upper_ms"])):
        for name, ms in sorted(edges.items()):
            when = f"{ms} ms after zero" if ms is not None else "not observed"
            floor = cut["error_ms"][name]
            error = f"error ≥ {floor} ms" if floor is not None else "error unmeasured"
            print(f"   {edge} bound on the cut: {when} ({name}, {error})")
    if cut["death"] is not None and not cut["death"]["bounds_the_cut"]:
        print(f"   the sender's transfer died of {cut['death']['kind']}, which bounds nothing")


def cut_during_reset(dev, cid):
    outcome = {}
    tap = TappedHid(dev, cid)

    def send_reset():
        try:
            outcome["response"] = send_cbor(tap, cid, bytes([CTAP_RESET]))
        except Exception as error:  # the expected path is a dead USB handle
            outcome["error"] = repr(error)
        finally:
            tap.close()

    worker = threading.Thread(target=send_reset, daemon=True)
    command = os.environ.get("RSK_POWER_CUT_CMD")
    commanded = (
        int(os.environ.get("RSK_POWER_CUT_DELAY_MS", str(DEFAULT_DELAY_MS)))
        if command
        else None
    )
    # Built before the run and written from the `finally`, so the exits that
    # wrote nothing are recorded too — a relay that failed, a key that never
    # disappeared, and a key that never came back, i.e. a cut that bricked it.
    cut = {
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_id": RUN_ID,
        "arm": "relay" if command else "manual",
        "commanded_delay_ms": commanded,
        "zero": "worker.start(), the instant the RESET sender was released",
        "records": ("this CUT, not the run: main's post-reboot assertions run "
                    "after this line is written, so a run that FAILED them "
                    "leaves the same verdict a passing one does. The run's "
                    "answer is its exit code, on the transcript carrying run_id"),
        "verdict": "aborted",
    }
    opened = gone = relay = None
    try:
        if command:
            opened = time.perf_counter()
            worker.start()
            time.sleep(commanded / 1000)
            relay = subprocess.Popen(shlex.split(command))
        else:
            input("Press Enter when your hand is on the cable; yank it at the CUT line… ")
            opened = time.perf_counter()
            worker.start()
            print("\n>>> CUT POWER NOW — then plug the key back in once it disappears <<<")
        cut["verdict"] = "never_gone"
        replug.wait_gone()
        gone = time.perf_counter()
        if relay is not None and relay.wait() != 0:
            cut["verdict"] = "relay_failed"
            sys.exit(f"FAIL: RSK_POWER_CUT_CMD exited {relay.returncode}")
        cut["verdict"] = "never_back"
        fresh, fresh_cid, _ = replug.wait_back()
        worker.join(timeout=5)
        if worker.is_alive():
            cut["verdict"] = "stuck"
            fresh.close()
            sys.exit("INCONCLUSIVE: the RESET sender did not observe the power loss")
        response = outcome.get("response")
        if response and response[0] == 0:
            cut["verdict"] = "missed"
            fresh.close()
            sys.exit("INCONCLUSIVE: RESET completed before power disappeared; cut earlier")
        # The one thing a fail-closed device cannot tell you: a board that
        # never began the reset passes every assertion in `main`. Only the
        # device settles it, and this is the frame that carries the answer.
        if tap.processing_at() is None:
            cut["verdict"] = "unconfirmed"
            fresh.close()
            # Three worlds share this verdict and only one of them is cured by
            # cutting later. `response` is non-zero here — a zero took the
            # `missed` branch above — so a response AT ALL is the board
            # refusing the command, which no delay changes (CTAP 2.1 §6.6
            # answers 0x30 well inside the keepalive floor).
            if response:
                why = (f"the board ANSWERED {response[0]:#04x} instead: it refused the "
                       "RESET rather than starting one, and no cut delay changes that")
            elif tap.touch_wait_at() is not None:
                why = ("every keepalive said UPNEEDED: the board was waiting for a "
                       "finger, a ceremony that stands ahead of every flash write")
            elif tap.foreign_keepalives:
                why = (f"{tap.foreign_keepalives} keepalive(s) came back on another "
                       "channel: the device was busy with a command that is not ours")
            else:
                why = ("this is what a cut BEFORE the request arrived looks like; cut "
                       f"later than {KEEPALIVE_MS} ms")
            sys.exit("INCONCLUSIVE: no PROCESSING keepalive came back, so nothing here "
                     f"says the board began the reset at all — {why}")
        cut["verdict"] = "torn"
        print(f"reset interrupted as intended ({outcome.get('error', response)!s}), "
              f"{len(tap.keepalives)} keepalive(s) back")
        return fresh, fresh_cid
    finally:
        # Two scopes, because one catch spanning both LIED: `say_cut` runs after
        # the line is on disk, so a raise in the console loop printed "no cut
        # record written" over a record that had been. Broad, and the only two
        # broad catches here: an instrument that cannot write, or cannot
        # narrate, must not leave with its own exception in place of the
        # assertion that was on its way out. A missing directory used to.
        try:
            cut.update(bounds(opened, gone, tap, outcome))
            append_cut(cut)
        except Exception as error:
            print(f"WARNING: no cut record written to {CUT_RECORD}: {error!r}")
        else:
            try:
                say_cut(cut)
            except Exception as error:
                print(f"WARNING: the cut IS recorded in {CUT_RECORD}; only this "
                      f"summary of it failed: {error!r}")


def main():
    print("Phase-6 HIL — use a throwaway key; this intentionally tears a flash wipe.")
    dev, cid = replug.reset(None, "the phase-6 clean-slate setup")
    try:
        owner_seed = backup.read_seed(dev, cid, None)
        status, _ = backup._vendor(dev, cid, {1: backup.FINALIZE})
        assert status == 0, f"backup finalize: {status:#x}"
        set_pin(dev, cid)
        credential_id = make_resident_credential(dev, cid)
        enable_always_uv(dev, cid)
        print("provisioned: sealed owner seed + PIN + alwaysUv + resident credential")

        dev, cid = cut_during_reset(dev, cid)
        info_response = send_cbor(dev, cid, bytes([GET_INFO]))
        assert info_response[0] == 0, f"getInfo after cut: {info_response[0]:#x}"
        options = decode(info_response[1:])[4]
        assertion_status = old_credential_without_gates(dev, cid, credential_id)
        assert assertion_status != 0, (
            "old credential authorized after the reset lost its protection "
            f"(clientPin={options.get('clientPin')}, alwaysUv={options.get('alwaysUv')})"
        )

        status, state = backup._vendor(dev, cid, {1: backup.STATE})
        assert status == 0, f"backup state after cut: {status:#x}"
        sealed = bool(state[1])
        if not sealed:
            current = backup.read_seed(dev, cid, PIN.decode() if options.get("clientPin") else None)
            assert current != owner_seed, "owner seed survived after its backup seal disappeared"

        print(
            "post-cut: "
            f"clientPin={options.get('clientPin')} alwaysUv={options.get('alwaysUv')} "
            f"sealed={sealed} old-assertion={assertion_status:#x}"
        )
        print(f"PASS [run {RUN_ID}] — torn reset remained fail-closed across the real reboot")
    finally:
        dev.close()


if __name__ == "__main__":
    main()
