// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Solving a board's raw→panel touch mapping from four guided taps.
//!
//! A CST816D reports in its own frame, and where that frame sits on the glass is a
//! per-unit property of the mount — so a board states the mapping as a
//! [`TouchRange`] and this is where that range comes from. The display draws
//! [`TARGETS`] at known panel coordinates, the user taps them, and [`CalibState`]
//! extrapolates the edge-to-edge range from the readings. All of it is pure, so
//! the host tests carry the arithmetic and the state machine and the firmware only
//! supplies the taps.

use crate::Point;
use crate::touch::TouchRange;

/// Distance of each target's centre from the panel edge, in pixels. Far enough in
/// that a fingertip reaches it even on a touch area narrower than the glass, and
/// close enough that extrapolating to the edge stays near the measured segment.
pub const TARGET_MARGIN: u16 = 40;

/// The four targets in tap order — top-left, top-right, bottom-right, bottom-left.
/// Clockwise, so the guided screen reads naturally; the pairs the solver averages
/// are the columns `[0,3]`/`[1,2]` and the rows `[0,1]`/`[2,3]`.
pub const TARGETS: [Point; 4] = [
    Point::new(TARGET_MARGIN, TARGET_MARGIN),
    Point::new(crate::PANEL_W - 1 - TARGET_MARGIN, TARGET_MARGIN),
    Point::new(
        crate::PANEL_W - 1 - TARGET_MARGIN,
        crate::PANEL_H - 1 - TARGET_MARGIN,
    ),
    Point::new(TARGET_MARGIN, crate::PANEL_H - 1 - TARGET_MARGIN),
];

/// One guided tap: where the target was drawn, and what the controller reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CalibTap {
    pub panel: Point,
    pub raw: Point,
}

/// How far the taps have got: which target is next, what has been read, and the
/// range once every target has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CalibState {
    taps: [Option<CalibTap>; 4],
    next: usize,
    range: Option<TouchRange>,
}

impl Default for CalibState {
    fn default() -> Self {
        Self::new()
    }
}

impl CalibState {
    pub const fn new() -> Self {
        Self {
            taps: [None; 4],
            next: 0,
            range: None,
        }
    }

    /// The target waiting for a tap, or `None` once all four are recorded.
    pub fn next_target(&self) -> Option<Point> {
        TARGETS.get(self.next).copied()
    }

    /// How many targets have been recorded, `0..=4` — the guided screen's index
    /// into its prompts.
    pub fn next_index(&self) -> usize {
        self.next
    }

    /// Record a reading against the waiting target and advance; after the fourth
    /// the range is solved. Returns whether the state is now complete.
    pub fn record(&mut self, raw: Point) -> bool {
        let Some(panel) = self.next_target() else {
            return true;
        };
        self.taps[self.next] = Some(CalibTap { panel, raw });
        self.next += 1;
        if self.next == TARGETS.len() {
            let [Some(a), Some(b), Some(c), Some(d)] = self.taps else {
                // Unreachable: `next` only reaches `len()` through the writes above.
                return true;
            };
            self.range = solve_range(&[a, b, c, d]);
        }
        self.is_done()
    }

    pub fn is_done(&self) -> bool {
        self.next == TARGETS.len()
    }

    /// A recorded tap by target index, for the guided screen's readout.
    pub fn tap(&self, index: usize) -> Option<CalibTap> {
        self.taps.get(index).copied().flatten()
    }

    pub fn range(&self) -> Option<TouchRange> {
        self.range
    }
}

/// Fixed-point scale for the slope, so a raw unit per panel pixel keeps its
/// fraction. The extrapolated edge values stay good to well under a pixel.
const FIXED: i64 = 1024;

/// The largest raw value a 12-bit CST816-family report can carry.
const RAW_MAX: i64 = 4095;

/// Solve the edge-to-edge range from four taps, or `None` when the readings cannot
/// describe one — an axis that hardly moved, a slope no touch panel plausibly has,
/// or an extrapolated edge off the controller's own scale. `None` is what the
/// guided screen shows as "try again", so the checks below have to be willing to
/// reject a bad set rather than hand back a mapping that would land taps wildly.
pub fn solve_range(taps: &[CalibTap; 4]) -> Option<TouchRange> {
    let (x_min, x_max) = axis(
        (taps[0].raw.x as i64 + taps[3].raw.x as i64) / 2,
        (taps[1].raw.x as i64 + taps[2].raw.x as i64) / 2,
        TARGET_MARGIN as i64,
        (crate::PANEL_W - 1 - TARGET_MARGIN) as i64,
        crate::PANEL_W as i64,
    )?;
    let (y_min, y_max) = axis(
        (taps[0].raw.y as i64 + taps[1].raw.y as i64) / 2,
        (taps[2].raw.y as i64 + taps[3].raw.y as i64) / 2,
        TARGET_MARGIN as i64,
        (crate::PANEL_H - 1 - TARGET_MARGIN) as i64,
        crate::PANEL_H as i64,
    )?;
    Some(TouchRange {
        x_min,
        x_max,
        y_min,
        y_max,
    })
}

/// One axis: the mean of two readings at a known panel position each, extrapolated
/// out to both edges. `lo_panel < hi_panel` by construction (the target margin).
fn axis(lo_raw: i64, hi_raw: i64, lo_panel: i64, hi_panel: i64, len: i64) -> Option<(u16, u16)> {
    let span = hi_panel - lo_panel;
    if span <= 0 {
        return None;
    }
    let slope = round_div((hi_raw - lo_raw) * FIXED, span);
    // A panel's raw-per-pixel is within a fraction of one; a touch area spanning
    // the same controller scale over a different glass stays within a small factor
    // of that. Outside this window the taps do not describe a touch area at all
    // (two taps landed on one target, or a crossed pair), and the extrapolation
    // would amplify the noise into the whole panel.
    if slope.abs() < FIXED / 8 || slope.abs() > FIXED * 16 {
        return None;
    }
    let min = round_div(lo_raw * FIXED - slope * lo_panel, FIXED);
    let max = round_div(hi_raw * FIXED + slope * (len - 1 - hi_panel), FIXED);
    if !(0..=RAW_MAX).contains(&min) || !(0..=RAW_MAX).contains(&max) || min == max {
        return None;
    }
    Some((min as u16, max as u16))
}

/// `a / b` rounded to nearest, for `b > 0`.
fn round_div(a: i64, b: i64) -> i64 {
    if a >= 0 {
        (a + b / 2) / b
    } else {
        -((-a + b / 2) / b)
    }
}

#[cfg(test)]
#[path = "calib_tests.rs"]
mod tests;
