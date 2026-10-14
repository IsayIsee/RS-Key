// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// Four taps read by `f`, one per target — the shape the guided screen produces
/// when the controller maps its frame by `f`.
fn taps(f: impl Fn(Point) -> Point) -> [CalibTap; 4] {
    TARGETS.map(|panel| CalibTap {
        panel,
        raw: f(panel),
    })
}

#[test]
fn a_panel_aligned_controller_solves_to_the_identity() {
    let range = solve_range(&taps(|p| p)).expect("aligned taps solve");
    assert_eq!(
        range,
        TouchRange {
            x_min: 0,
            x_max: crate::PANEL_W - 1,
            y_min: 0,
            y_max: crate::PANEL_H - 1,
        }
    );
}

#[test]
fn a_scaled_and_offset_frame_is_inverted_back_out() {
    // raw = 0.8·panel + 30, the shape a touch area narrower than the glass and
    // mounted off-centre produces. Inverting it recovers the raw values that would
    // sit at the panel's own edges.
    let range = solve_range(&taps(|p| Point::new(p.x * 4 / 5 + 30, p.y * 4 / 5 + 30)))
        .expect("a linear frame solves");
    assert_eq!(range.x_min, 30);
    assert_eq!(range.x_max, 30 + (crate::PANEL_W - 1) * 4 / 5);
    assert_eq!(range.y_min, 30);
    assert_eq!(range.y_max, 30 + (crate::PANEL_H - 1) * 4 / 5);
}

#[test]
fn a_mirrored_axis_solves_min_above_max() {
    // The mirror is the range run backwards; a solver that sorted the two would
    // silently un-mirror the controller.
    let range = solve_range(&taps(|p| {
        Point::new(crate::PANEL_W - 1 - p.x, crate::PANEL_H - 1 - p.y)
    }))
    .expect("a mirrored frame solves");
    assert_eq!(range.x_min, crate::PANEL_W - 1);
    assert_eq!(range.x_max, 0);
    assert_eq!(range.y_min, crate::PANEL_H - 1);
    assert_eq!(range.y_max, 0);
}

#[test]
fn taps_that_never_moved_are_refused() {
    // Two taps on one target, or a controller stuck at one reading: extrapolating
    // from a slope near zero would put the whole panel in a couple of raw units.
    let range = solve_range(&taps(|_| Point::new(123, 456)));
    assert_eq!(range, None);
}

#[test]
fn a_slope_no_panel_has_is_refused() {
    let range = solve_range(&taps(|p| Point::new(p.x * 100, p.y * 100)));
    assert_eq!(range, None);
}

#[test]
fn an_edge_off_the_controller_scale_is_refused() {
    // A plausible slope whose extrapolated edges fall past what a 12-bit report
    // can carry: the taps are not describing this panel's touch area.
    let range = solve_range(&taps(|p| Point::new(p.x * 4 + 4000, p.y * 4 + 4000)));
    assert_eq!(range, None);
}

#[test]
fn state_records_the_samples_against_the_targets_in_order() {
    let mut state = CalibState::new();
    assert_eq!(state.next_target(), Some(TARGETS[0]));
    assert_eq!(state.range(), None);

    for (i, panel) in TARGETS.iter().enumerate() {
        for k in 0..SAMPLES_PER_TARGET {
            assert_eq!(state.next_target(), Some(*panel), "target {i}");
            assert_eq!(state.samples_so_far(), k);
            let done = state.record(Point::new(panel.x * 2, panel.y * 2));
            assert_eq!(
                done,
                i == TARGETS.len() - 1 && k == SAMPLES_PER_TARGET - 1,
                "only the last sample of the last target completes"
            );
        }
        assert_eq!(state.tap(i).map(|t| t.panel), Some(*panel));
        assert_eq!(state.next_target(), TARGETS.get(i + 1).copied());
    }

    assert!(state.is_done());
    let range = state.range().expect("four targets solve");
    // raw = 2·panel: the panel edges sit at raw 0 and 2·(edge).
    assert_eq!(range.x_min, 0);
    assert_eq!(range.x_max, 2 * (crate::PANEL_W - 1));
}

#[test]
fn a_reading_after_the_last_target_is_ignored() {
    let mut state = CalibState::new();
    for panel in TARGETS {
        for _ in 0..SAMPLES_PER_TARGET {
            state.record(Point::new(panel.x * 2, panel.y * 2));
        }
    }
    let solved = state.range().expect("the taps solve");
    assert!(state.record(Point::new(1, 1)));
    assert_eq!(state.range(), Some(solved));
}

#[test]
fn unrecoverable_taps_leave_the_range_unsolved() {
    let mut state = CalibState::new();
    for _ in 0..TARGETS.len() * SAMPLES_PER_TARGET {
        state.record(Point::new(7, 7));
    }
    assert!(state.is_done());
    assert_eq!(state.range(), None);
}

/// One reading per target that landed off-centre — or was mis-read — must not move the
/// solution: the median of three is what the tool keeps, and the corner that used to need
/// several taps to register is exactly the reading this discards (2026-09-29).
#[test]
fn one_off_centre_reading_does_not_move_the_solution() {
    let clean = |p: Point| Point::new(p.x * 2, p.y * 2);
    let mut with_outlier = CalibState::new();
    let mut reference = CalibState::new();
    for panel in TARGETS {
        // A wild first reading, then two that agree — the median is the clean pair.
        with_outlier.record(Point::new(panel.x * 2 + 300, panel.y * 2 + 300));
        for _ in 0..SAMPLES_PER_TARGET {
            reference.record(clean(panel));
        }
        for _ in 0..SAMPLES_PER_TARGET - 1 {
            with_outlier.record(clean(panel));
        }
    }
    assert!(with_outlier.is_done() && reference.is_done());
    assert_eq!(
        with_outlier.range(),
        reference.range(),
        "one outlier reading moved the solved range"
    );
}
