# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host tests for the `rsk status` JSON shape (no device).

Run from tools/:  python -m pytest rsk/test_status.py

`gather()` is a documented machine-readable surface, so the two shapes a script
can rely on are pinned here: the serial is promoted to the top level from the
rescue SELECT, and it is `null` — never a KeyError — on the hosts where the CCID
interface is unavailable, which on Linux is the common case (docs/linux.md).
"""
import sys
import types

sys.modules.setdefault("hid", types.ModuleType("hid"))

from rsk import ccid, status

SERIAL = "a29974d3f40ac7cd"
SELECT_OK = bytes.fromhex("6f0a8408") + bytes.fromhex(SERIAL)


def test_gather_promotes_the_serial(monkeypatch):
    monkeypatch.setattr(status, "_fido", lambda: {"present": False})
    monkeypatch.setattr(status, "_secure_boot", lambda: {"available": True, "serial": SERIAL})
    assert status.gather()["serial"] == SERIAL


def test_gather_reports_no_serial_without_ccid(monkeypatch):
    monkeypatch.setattr(status, "_fido", lambda: {"present": False})
    monkeypatch.setattr(status, "_secure_boot", lambda: None)
    assert status.gather()["serial"] is None


def _run(monkeypatch, capsys, fido):
    monkeypatch.setattr(status, "gather", lambda: {"fido": fido, "secure_boot": None, "serial": None})
    status.run(types.SimpleNamespace(json=False))
    return capsys.readouterr().out


FIDO = {"present": True, "fw": "5.7.4", "aaguid": "", "versions": [], "clientPin": False}


def test_a_refused_at_rest_re_arm_is_printed(monkeypatch, capsys):
    """The refusal's only channel. `authenticatorReset` re-arms the at-rest scrub
    best-effort and answers success whatever the flash said, so a stuck medium is
    invisible everywhere else — including in the reset's own status."""
    assert "REFUSED" in _run(monkeypatch, capsys, FIDO | {"rescrub_refused": True})


def test_a_healthy_device_prints_no_at_rest_line(monkeypatch, capsys):
    """The control, and the reason this is an exception report: the marker the flag
    is about is latched on every provisioned key, so a line on every run says
    nothing. Both the healthy device and firmware too old to send key 5 stay quiet."""
    assert "at-rest" not in _run(monkeypatch, capsys, FIDO | {"rescrub_refused": False})
    assert "at-rest" not in _run(monkeypatch, capsys, FIDO)


STATE = {1: False, 2: True, 3: False, 4: False, 5: True}


def test_backup_fields_reads_the_key_numbers_the_device_sends():
    """The wire is the key NUMBER, and nothing else pins it on this side: `_fido`
    opens a HID device, so the decode is unreachable from a test unless it is split
    out, and a map read one key over still fills every field the printer asks for."""
    assert status.backup_fields(STATE) == {
        "backup": {"sealed": False, "has_seed": True},
        "lock": {"locked": False, "unlocked": False},
        "rescrub_refused": True,
    }


def test_backup_fields_drops_what_an_older_firmware_omits():
    """Both keys are versioned additions (3/4 at 0x0742, 5 at 0x09C5), so absence is
    the older device and must not read as `False` — the printer keys off presence."""
    assert status.backup_fields({1: True, 2: True}) == {"backup": {"sealed": True, "has_seed": True}}
    assert "rescrub_refused" not in status.backup_fields({k: STATE[k] for k in (1, 2, 3, 4)})


def test_rescue_serial_reads_the_select_response():
    assert status.rescue_serial(SELECT_OK, *ccid.SW_OK) == SERIAL


def test_rescue_serial_refuses_a_short_or_failed_select():
    assert status.rescue_serial(SELECT_OK[:11], *ccid.SW_OK) is None
    assert status.rescue_serial(SELECT_OK, 0x6A, 0x82) is None
