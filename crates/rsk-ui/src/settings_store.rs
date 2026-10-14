// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `EF_DISPLAY` wire-format codec — the persisted on-device display settings the
//! trusted-display firmware reads at boot and writes when the user edits them in
//! Settings → Display.
//!
//! The block is `[brightness, sleep_secs_be(2), flags, nohost_idx]` (5 bytes): the
//! backlight level (`1..=BRIGHTNESS_LEVELS`), the display-sleep timeout in seconds
//! (`0` = Off), a flags byte ([`FLAG_PIN_DECLINED`] — the user chose "continue
//! without a device PIN" at first-run, so the panel must not re-prompt — and
//! [`FLAG_SCRAMBLE_PIN`]), and the no-host-info delay index ([`NOHOST_CHOICES`]).
//! The **touch timeout** is *not* here — it persists in the phy record's
//! `PresenceTimeout` tag (shared with `rsk hw --touch-timeout`), so it keeps one
//! source of truth.
//!
//! [`DisplayConfig::apply_block`] overlays a stored block onto a default `self`,
//! field by field, so a record written by an *older* firmware (the original
//! `CORE_LEN`-byte block, no flags; or the 4-byte one with no no-host index) or read
//! by an *older* firmware (a future, longer block — only its known prefix is read)
//! survives a firmware upgrade without losing or misreading a field; anything a
//! shorter block omits keeps its current value. [`DisplayConfig::default`] mirrors
//! the firmware's live defaults, so a device with no record behaves exactly as
//! before.
//!
//! Like `rsk-led`'s codec this crate is pure (no `embassy` / HAL), so the format is
//! unit-testable on the host; `firmware/src/display.rs` owns the live brightness
//! field and the `SLEEP_TIMEOUT_MS` atomic and marshals them through here.

/// `EF_DISPLAY` length: `[brightness, sleep_secs_be(2), flags, nohost_idx]`.
pub const CONF_LEN: usize = 5;

/// The original layout (`[brightness, sleep_secs_be(2)]`, no flags byte). A record
/// written before the flags byte existed is exactly this long; [`DisplayConfig::apply_block`]
/// still reads its two fields and leaves the later ones at their defaults, so an
/// already-provisioned device keeps its brightness / sleep across the upgrades that
/// added them.
const CORE_LEN: usize = 3;

/// The layout with the flags byte but before the no-host index: a 4-byte record
/// loads its flags and keeps the default delay, so an upgrade does not change how
/// long a host-less device shows its spinner.
const FLAGS_LEN: usize = 4;

/// Flags-byte bit 1: scramble the PIN pad's digits on every entry. Off by default —
/// it trades muscle memory for smudge/over-the-shoulder resistance, and the retry
/// budget makes a typo expensive (`PIN_MISMATCH_LIMIT` is three per power cycle), so
/// it is the owner's call rather than the firmware's.
pub const FLAG_SCRAMBLE_PIN: u8 = 0x02;

/// Flags-byte bit 0: the user chose "continue without a device PIN" at the
/// first-run prompt. Set, the panel never re-shows that onboarding screen (until a
/// factory reset wipes `EF_DISPLAY`); clear (the default), a PIN-less device is
/// offered the prompt once.
pub const FLAG_PIN_DECLINED: u8 = 0x01;

/// Default display-sleep timeout in seconds — the single source of truth: the
/// firmware derives its `DEFAULT_SLEEP_MS` from it, so a device with no record
/// blanks on the same schedule it did before this record existed.
pub const DEFAULT_SLEEP_SECS: u16 = 60;

/// No-host-info choices in seconds: how long the panel waits, with no host having
/// configured the device, before Home shows its status card instead of the booting
/// spinner. The last entry is the default. No "Off" on purpose — a key that lives on
/// a charger is the case this exists for, and the old behaviour it replaces ("Starting…"
/// for ever, repainting at 10 Hz) is not one to keep as an option.
pub const NOHOST_CHOICES: [u16; 4] = [3, 5, 10, 30];

/// Default index into [`NOHOST_CHOICES`] — 30 s, the same "settle down" delay the
/// GEEK's idle menu uses.
pub const DEFAULT_NOHOST_IDX: u8 = NOHOST_CHOICES.len() as u8 - 1;

/// The seconds a stored no-host index means. A byte from flash is clamped to a
/// listed choice rather than indexing past the table — a corrupt record must not
/// panic the display task.
pub fn nohost_secs(idx: u8) -> u16 {
    NOHOST_CHOICES[(idx as usize).min(NOHOST_CHOICES.len() - 1)]
}

/// The persisted display settings: backlight level, the display-sleep timeout, and
/// the first-run PIN-prompt flag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DisplayConfig {
    /// Backlight level `1..=BRIGHTNESS_LEVELS`. Stored raw; the firmware clamps it
    /// to the valid range when it applies it to the PWM, so a corrupt or
    /// out-of-range byte can never blank or over-drive the panel.
    pub brightness: u8,
    /// Display-sleep timeout in seconds; `0` = Off (never blanks).
    pub sleep_secs: u16,
    /// The user has dismissed the first-run "set a device PIN?" prompt by choosing
    /// to continue without one — so the panel must not re-offer it. Cleared on a
    /// factory reset (which wipes the record), so a wiped device re-onboards.
    pub pin_declined: bool,
    /// Draw the PIN pad's digits in a fresh random order for every entry (Settings →
    /// Security → "Scramble PIN pad"). Off by default.
    pub scramble_pin: bool,
    /// How long the panel shows the booting spinner before Home's card, on a device
    /// no host has configured — an index into [`NOHOST_CHOICES`], clamped on use.
    pub nohost_idx: u8,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            brightness: crate::BRIGHTNESS_LEVELS,
            sleep_secs: DEFAULT_SLEEP_SECS,
            pin_declined: false,
            scramble_pin: false,
            nohost_idx: DEFAULT_NOHOST_IDX,
        }
    }
}

impl DisplayConfig {
    /// Pack into the wire block: `[brightness, sleep_secs_be, flags, nohost_idx]`
    /// (big-endian sleep, matching the phy record's byte order).
    pub fn encode(&self) -> [u8; CONF_LEN] {
        let s = self.sleep_secs.to_be_bytes();
        let mut flags = 0;
        if self.pin_declined {
            flags |= FLAG_PIN_DECLINED;
        }
        if self.scramble_pin {
            flags |= FLAG_SCRAMBLE_PIN;
        }
        [self.brightness, s[0], s[1], flags, self.nohost_idx]
    }

    /// Overlay a stored block onto `self`, field by field: each field is read from
    /// the first layout that carried it, so every older record loads whole (the
    /// flags-less original keeps its later fields at their defaults) and a future,
    /// longer block is read up to its known prefix. Anything shorter than `CORE_LEN`
    /// can only be flash corruption, so those fields stay at their defaults rather
    /// than half-applied.
    pub fn apply_block(&mut self, b: &[u8]) {
        if b.len() >= CORE_LEN {
            self.brightness = b[0];
            self.sleep_secs = u16::from_be_bytes([b[1], b[2]]);
        }
        if b.len() >= FLAGS_LEN {
            self.pin_declined = b[3] & FLAG_PIN_DECLINED != 0;
            self.scramble_pin = b[3] & FLAG_SCRAMBLE_PIN != 0;
        }
        if b.len() >= CONF_LEN {
            self.nohost_idx = b[4];
        }
    }
}

#[cfg(kani)]
#[path = "settings_store_kani.rs"]
mod proofs;

#[cfg(test)]
#[path = "settings_store_tests.rs"]
mod tests;
