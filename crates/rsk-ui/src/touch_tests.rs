// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn reconstructs_finger_coordinate() {
    // x=100 (0x064): X high 8 = 0x06, X low 4 = 0x4. y=200 (0x0C8): Y high 8 =
    // 0x0C, Y low 4 = 0x8 — so the packed low-nibble byte is 0x48.
    let r = [FINGER_DOWN, 0x06, 0x0C, 0x48, 0, 0, 0];
    assert_eq!(parse_cst328(&r), Some(Point::new(100, 200)));
}

#[test]
fn no_finger_down_is_none() {
    assert_eq!(parse_cst328(&[0x00, 0x06, 0x0C, 0x48]), None);
}

#[test]
fn short_report_is_none() {
    assert_eq!(parse_cst328(&[FINGER_DOWN, 0x06]), None);
    assert_eq!(parse_cst328(&[]), None);
}

#[test]
fn full_scale_is_twelve_bits_each() {
    let r = [FINGER_DOWN, 0xFF, 0xFF, 0xFF];
    assert_eq!(parse_cst328(&r), Some(Point::new(0xFFF, 0xFFF)));
}

// --- CST816D: the same family's single-byte register layout (the 2" board) ---

#[test]
fn cst816d_reconstructs_the_raw_coordinate() {
    // x = 200 (0x0C8): X high 4 bits = 0x0, X low 8 = 0xC8. y = 100 (0x064):
    // Y high 4 = 0x0, Y low 8 = 0x64.
    let r = [0x00, 0x01, 0x00, 0xC8, 0x00, 0x64];
    assert_eq!(parse_cst816d(&r), Some(Point::new(200, 100)));
}

#[test]
fn cst816d_masks_the_high_nibble() {
    // The upper nibble of XposH is not part of X — 0xF5 reads as 0x5AB with a
    // 0xAB low byte — and the same holds for Y. The vendor example masks it.
    let r = [0x00, 0x01, 0xF5, 0xAB, 0xF0, 0xCD];
    assert_eq!(parse_cst816d(&r), Some(Point::new(0x5AB, 0x0CD)));
}

#[test]
fn cst816d_no_finger_is_none() {
    assert_eq!(parse_cst816d(&[0x00, 0x00, 0x00, 0xC8, 0x00, 0x64]), None);
}

#[test]
fn cst816d_short_block_is_none() {
    assert_eq!(parse_cst816d(&[0x00, 0x01, 0x00]), None);
    assert_eq!(parse_cst816d(&[]), None);
}

// --- TouchRange: the controller's frame onto the panel's ---

#[test]
fn the_identity_range_maps_the_panel_edges_exactly() {
    let r = TouchRange::IDENTITY;
    assert_eq!(r.map(Point::new(0, 0)), Some(Point::new(0, 0)));
    assert_eq!(
        r.map(Point::new(crate::PANEL_W - 1, crate::PANEL_H - 1)),
        Some(Point::new(crate::PANEL_W - 1, crate::PANEL_H - 1))
    );
}

#[test]
fn a_narrower_range_is_stretched_onto_the_panel() {
    // A contact area smaller than the glass: the raw range is 33..225 across a
    // 240-pixel axis, and the midpoint lands where the arithmetic puts it (the
    // scale truncates, so 129 is 119 and not 120).
    let r = TouchRange {
        x_min: 33,
        x_max: 225,
        y_min: 7,
        y_max: 327,
    };
    assert_eq!(r.map(Point::new(33, 7)), Some(Point::new(0, 0)));
    assert_eq!(
        r.map(Point::new(225, 327)),
        Some(Point::new(crate::PANEL_W - 1, crate::PANEL_H - 1))
    );
    assert_eq!(r.map(Point::new(129, 167)), Some(Point::new(119, 159)));
}

#[test]
fn a_reversed_range_is_the_mirror() {
    // A board whose panel scan mirrors an axis states it by giving that axis the
    // other way round — which is what the 2" does with MADCTL's MX bit.
    let r = TouchRange {
        x_min: 225,
        x_max: 33,
        ..TouchRange::IDENTITY
    };
    assert_eq!(r.map(Point::new(225, 0)), Some(Point::new(0, 0)));
    assert_eq!(
        r.map(Point::new(33, 0)),
        Some(Point::new(crate::PANEL_W - 1, 0))
    );
}

#[test]
fn a_raw_value_just_outside_the_range_pins_to_the_edge_it_left() {
    let r = TouchRange {
        x_min: 33,
        x_max: 225,
        ..TouchRange::IDENTITY
    };
    // A fingertip that ran off the glass: the contact's centre can leave the panel, so a
    // reading a little outside the span belongs to the edge it left, not to nowhere.
    assert_eq!(r.map(Point::new(20, 0)), Some(Point::new(0, 0)));
    assert_eq!(r.map(Point::new(240, 0)), Some(Point::new(239, 0)));
}

#[test]
fn a_degenerate_axis_is_none() {
    let r = TouchRange {
        x_min: 100,
        x_max: 100,
        ..TouchRange::IDENTITY
    };
    assert_eq!(r.map(Point::new(100, 0)), None);
}

/// The 2" bench's frames, and the two ends of the panel they land on. A raw `y` past the
/// calibrated maximum (323) is refused however small the excess: the panel's bottom edge is
/// the nav bar's Home cell, and the frame the controller still holds after a contact ends
/// reads there (measured raw y = 3584 against that maximum, 2026-09-29). A corner press —
/// which reports *below* the calibration's minimum on **both** axes, because a fingertip's
/// centre can leave the glass — is pinned to the corner instead: refusing it is what made
/// the top-left take several taps to register.
#[test]
fn past_the_calibrated_maximum_is_never_a_touch_and_a_corner_is() {
    let range = TouchRange {
        x_min: 18,
        x_max: 223,
        y_min: 2,
        y_max: 323,
    };
    // No tolerance at this end at all — one unit past is already not a touch.
    assert_eq!(range.map(Point::new(100, 324)), None);
    assert_eq!(range.map(Point::new(18, 330)), None);
    assert_eq!(range.map(Point::new(18, 4095)), None);
    // The corner: both axes below the calibrated minimum, pinned rather than refused.
    assert_eq!(range.map(Point::new(12, 0)), Some(Point::new(0, 0)));
    // Past the edge slop it is not a fingertip either.
    assert_eq!(range.map(Point::new(4095, 160)), None);
    assert_eq!(range.map(Point::new(18, 2)), Some(Point::new(0, 0)));
    assert_eq!(range.map(Point::new(223, 323)), Some(Point::new(239, 319)));
}
