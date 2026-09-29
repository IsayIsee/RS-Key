// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The guided touch-calibration screen: four targets at known panel coordinates,
//! the raw reading of each tap beside it, the solved range, and — once solved — a
//! cross that follows the finger through that range, so "is the mapping right?" is
//! answered by looking at the panel rather than by a second flash.
//!
//! Tool-only paint (the firmware's `display-calib` build, never shipped), but it
//! lives here with the rest of the panel layout: the target coordinates it draws
//! are the ones [`crate::calib`] solves against, so the two cannot drift.

use super::*;
use crate::calib::{CalibState, TARGETS};

/// Diameter of a target's ring, and the diameter of the dot at its centre.
const TARGET_DIA: u32 = 34;
const TARGET_DOT_DIA: u32 = 6;
/// Half-arm of the follow cross, in pixels.
const CROSS_ARM: i32 = 12;
/// How far a target's two raw-reading lines sit from its centre — toward the panel
/// middle, so the top row reads below its targets and the bottom row above, and
/// neither runs into the ring or the edge.
const READOUT_DY: i32 = 30;
/// Line spacing of the two reading lines (mono small is 11 px).
const READOUT_GAP: i32 = 14;
/// The heading, prompt and solved-range rows, all in the band between the target
/// rows — the corners own the edges, so the text lives where nothing else is.
const TITLE_Y: i32 = 14;
const HINT_Y: i32 = 140;
const RANGE_Y: i32 = 180;
const RANGE_GAP: i32 = 22;

/// The prompt per tap count, plus the two resting states: solved (check by touch)
/// and unsolved (the taps could not describe a mapping, so start over).
const HINTS: [&str; 4] = [
    "Tap target 1 of 4",
    "Tap target 2 of 4",
    "Tap target 3 of 4",
    "Tap target 4 of 4",
];
const HINT_CHECK: &str = "Solved - tap anywhere to check";
const HINT_FAILED: &str = "No mapping - reset to retry";

/// Paint the calibration screen for `state`, with the finger's raw reading (when
/// one is down) drawn through the solved range as a cross.
pub fn render_calib<D>(t: &mut D, state: &CalibState, finger: Option<Point>) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    t.clear(BG)?;
    text(
        t,
        "Touch calibration",
        EgPoint::new(MIDX, TITLE_Y),
        Role::BodyStrong,
        FG,
    )?;
    text(
        t,
        hint(state),
        EgPoint::new(MIDX, HINT_Y),
        Role::Body,
        MUTED,
    )?;

    for (i, target) in TARGETS.iter().enumerate() {
        let done = state.tap(i).is_some();
        let current = state.next_target() == Some(*target);
        let ring = if done {
            theme::SUCCESS
        } else if current {
            theme::ACCENT_TEXT
        } else {
            theme::FAINT
        };
        ring_mark(t, *target, ring)?;
        if let Some(tap) = state.tap(i) {
            // Readings face the panel middle: the top row's sit below its targets,
            // the bottom row's above, so neither lands under the edge.
            let inward = if target.y < crate::PANEL_H / 2 {
                READOUT_DY
            } else {
                -READOUT_DY - READOUT_GAP
            };
            let at = EgPoint::new(target.x as i32, target.y as i32 + inward);
            let mut xbuf = [0u8; 8];
            let mut ybuf = [0u8; 8];
            font::centered(
                t,
                num_line(b'x', tap.raw.x, &mut xbuf),
                at,
                Role::MonoSmall,
                theme::TEXT_2,
                BG,
            )?;
            font::centered(
                t,
                num_line(b'y', tap.raw.y, &mut ybuf),
                at + EgPoint::new(0, READOUT_GAP),
                Role::MonoSmall,
                theme::TEXT_2,
                BG,
            )?;
        }
    }

    if let Some(range) = state.range() {
        let mut xbuf = [0u8; 16];
        let mut ybuf = [0u8; 16];
        let at = EgPoint::new(MIDX, RANGE_Y);
        font::centered(
            t,
            range_line(b'x', range.x_min, range.x_max, &mut xbuf),
            at,
            Role::Mono,
            theme::ACCENT_TEXT,
            BG,
        )?;
        font::centered(
            t,
            range_line(b'y', range.y_min, range.y_max, &mut ybuf),
            at + EgPoint::new(0, RANGE_GAP),
            Role::Mono,
            theme::ACCENT_TEXT,
            BG,
        )?;
        if let Some(panel) = finger.and_then(|raw| range.map(raw)) {
            cross(t, panel)?;
        }
    }
    Ok(())
}

/// The prompt line for the state: the tap counter while targets remain, then the
/// solved/unsolved verdict.
fn hint(state: &CalibState) -> &'static str {
    match HINTS.get(state.next_index()) {
        Some(hint) => hint,
        None if state.range().is_some() => HINT_CHECK,
        None => HINT_FAILED,
    }
}

/// A target: a two-pixel ring with a dot at its centre, so the exact coordinate to
/// hit is unambiguous at fingertip size.
fn ring_mark<D: DrawTarget<Color = Rgb565>>(
    t: &mut D,
    at: Point,
    color: Rgb565,
) -> Result<(), D::Error> {
    let top_left =
        |dia: u32| EgPoint::new(at.x as i32 - dia as i32 / 2, at.y as i32 - dia as i32 / 2);
    crate::aa::circle(t, top_left(TARGET_DIA), TARGET_DIA, 2, color, BG)?;
    crate::aa::filled_circle(t, top_left(TARGET_DOT_DIA), TARGET_DOT_DIA, color, BG)
}

/// The follow cross — where the panel thinks the finger is.
fn cross<D: DrawTarget<Color = Rgb565>>(t: &mut D, at: Point) -> Result<(), D::Error> {
    let c = EgPoint::new(at.x as i32, at.y as i32);
    for (from, to) in [
        (
            EgPoint::new(c.x - CROSS_ARM, c.y),
            EgPoint::new(c.x + CROSS_ARM, c.y),
        ),
        (
            EgPoint::new(c.x, c.y - CROSS_ARM),
            EgPoint::new(c.x, c.y + CROSS_ARM),
        ),
    ] {
        Line::new(from, to)
            .into_styled(PrimitiveStyle::with_stroke(theme::WARN, 2))
            .draw(t)?;
    }
    Ok(())
}

/// `"x 123"` into `out`, using the decimal formatter the rest of the renderer
/// speaks. The caller owns the buffer; `fmt_u16`'s five-byte bound is what keeps
/// the copy in range.
fn num_line(prefix: u8, v: u16, out: &mut [u8; 8]) -> &str {
    out[0] = prefix;
    out[1] = b' ';
    let mut digits = [0u8; 5];
    let text = fmt_u16(v, &mut digits);
    let n = text.len();
    out[2..2 + n].copy_from_slice(text.as_bytes());
    core::str::from_utf8(&out[..2 + n]).unwrap_or("?")
}

/// `"x 33..225"` into `out` — the solved range in the form the board file wants it.
fn range_line(prefix: u8, lo: u16, hi: u16, out: &mut [u8; 16]) -> &str {
    let mut at = 0;
    out[at] = prefix;
    at += 1;
    out[at] = b' ';
    at += 1;
    let mut lo_digits = [0u8; 5];
    let lo_text = fmt_u16(lo, &mut lo_digits);
    out[at..at + lo_text.len()].copy_from_slice(lo_text.as_bytes());
    at += lo_text.len();
    out[at] = b'.';
    out[at + 1] = b'.';
    at += 2;
    let mut hi_digits = [0u8; 5];
    let hi_text = fmt_u16(hi, &mut hi_digits);
    out[at..at + hi_text.len()].copy_from_slice(hi_text.as_bytes());
    at += hi_text.len();
    core::str::from_utf8(&out[..at]).unwrap_or("?")
}
