// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Parsing a CST328 capacitive-touch report into a panel coordinate. Pure and
//! host-tested: the firmware's `display.rs` does the I2C transfer (read the report
//! block at register 0xD000) and hands the raw bytes here, so the bit-twiddling
//! that turns a report into the point [`crate::hit_confirm`] will judge sits under
//! test rather than buried in the driver — a wrong reconstruction maps a tap to
//! the wrong button.

use crate::Point;

/// Finger-1 status nibble (CST328 register 0xD000, low 4 bits) meaning a finger
/// is down.
const FINGER_DOWN: u8 = 0x06;

/// Parse a CST328 report block read starting at register 0xD000, returning the
/// first active finger's coordinate or `None` (no finger down, or a short block).
///
/// Byte layout returned by the controller from 0xD000: `[0]` finger-1 status,
/// `[1]` X high 8 bits, `[2]` Y high 8 bits, `[3]` X low 4 bits (upper nibble) |
/// Y low 4 bits (lower nibble). Both axes are 12-bit. The controller is configured
/// at the panel resolution and reports the panel's own axes, so `display.rs` hands
/// this straight on — there is no rotation or flip step anywhere.
pub fn parse_cst328(report: &[u8]) -> Option<Point> {
    if report.len() < 4 || report[0] & 0x0F != FINGER_DOWN {
        return None;
    }
    let x = ((report[1] as u16) << 4) | ((report[3] as u16) >> 4);
    let y = ((report[2] as u16) << 4) | ((report[3] as u16) & 0x0F);
    Some(Point::new(x, y))
}

/// The register a CST816D report block starts at; the driver reads six bytes
/// from here and hands them to [`parse_cst816d`].
pub const CST816_BLOCK: u8 = 0x01;

/// Parse a CST816D report block read starting at register 0x01, returning the
/// first finger's raw coordinate or `None` (no finger down, or a short block).
///
/// Byte layout: `[0]` gesture, `[1]` finger count, `[2]` X high 4 bits, `[3]` X
/// low 8, `[4]` Y high 4, `[5]` Y low 8 — the CST816 family's single-byte
/// register layout (0x01..0x06), unlike the CST328's 16-bit addresses. No
/// rotation is applied here: the vendor example swaps the axes and subtracts X
/// from the width for its *landscape* demo, and this panel is portrait, so the
/// orientation belongs to [`TouchRange`], where a board states it once.
pub fn parse_cst816d(report: &[u8]) -> Option<Point> {
    if report.len() < 6 || report[1] == 0 {
        return None;
    }
    let x = (((report[2] as u16) & 0x0F) << 8) | report[3] as u16;
    let y = (((report[4] as u16) & 0x0F) << 8) | report[5] as u16;
    Some(Point::new(x, y))
}

/// Where a controller's raw coordinates sit on the panel: the range it reports
/// with a finger at each edge of the glass. A contact area smaller than the
/// glass, a mount offset and a mirrored scan all show up as a range narrower
/// than the panel or one that runs the other way — so one pair of numbers per
/// axis states all three, and `min > max` *is* the mirror, with no flag beside
/// it to keep in sync. Both axes are in the controller's own frame, so a board
/// that mirrors one axis (a MADCTL scan bit) states it here rather than in the
/// driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TouchRange {
    pub x_min: u16,
    pub x_max: u16,
    pub y_min: u16,
    pub y_max: u16,
}

impl TouchRange {
    /// The identity: the controller already reports panel pixels edge to edge
    /// (the 2.8"'s CST328 is configured at the panel resolution).
    pub const IDENTITY: Self = Self {
        x_min: 0,
        x_max: crate::PANEL_W - 1,
        y_min: 0,
        y_max: crate::PANEL_H - 1,
    };

    /// Map a raw report onto panel pixels, clamping a raw value that lands
    /// outside the calibrated range (a fingertip at the very edge does). `None`
    /// for a degenerate axis: a hand-written board file that collapses one would
    /// otherwise divide by zero in a poll driven by the touch interrupt.
    pub fn map(&self, raw: Point) -> Option<Point> {
        Some(Point::new(
            scale(raw.x, self.x_min, self.x_max, crate::PANEL_W)?,
            scale(raw.y, self.y_min, self.y_max, crate::PANEL_H)?,
        ))
    }
}

/// `raw` in `lo..=hi` onto `0..=len-1`, clamped into that span. `None` when the
/// range is degenerate (`lo == hi`).
fn scale(raw: u16, lo: u16, hi: u16, len: u16) -> Option<u16> {
    let span = hi as i32 - lo as i32;
    if span == 0 {
        return None;
    }
    let last = (len - 1) as i32;
    let mapped = (raw as i32 - lo as i32) * last / span;
    Some(mapped.clamp(0, last) as u16)
}

#[cfg(test)]
#[path = "touch_tests.rs"]
mod tests;
