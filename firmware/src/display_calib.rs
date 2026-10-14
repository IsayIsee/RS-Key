// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The touch-calibration tool (`--features display-calib`): a build whose whole
//! job is to solve this board's touch range — the raw coordinates the controller
//! reports for a finger at each edge of the glass — and show it on the panel.
//!
//! This is a bench tool, never a shipped image. It exists because that range is a
//! property of the panel's mount, not of the firmware: a controller reports in its
//! own frame, and the glass sits over the sensor with an offset and a touch area
//! that is usually smaller than the display. `rsk-ui`'s calibration screen walks
//! four targets and `rsk-ui::calib` solves the range from the readings; what is
//! here is only the loop that drives them — read the controller raw, hand the tap
//! state machine, repaint when something changed. The solved four numbers are read
//! off the panel and written into the board file by hand.

use core::cell::RefCell;
use core::sync::atomic::{AtomicU16, Ordering};

use embassy_rp::gpio::Input;
use embassy_time::Timer;

use rsk_display::Hooks as _;
use rsk_ui::Point;
use rsk_ui::calib::CalibState;

use crate::display::Ui;

/// Panel repaint period while calibrating. Fast enough that the follow cross
/// tracks a finger, slow enough that a full-frame repaint (~15 ms of SPI) does
/// not saturate the task.
const FRAME_MS: u64 = 30;

/// Backlight duty the tool holds: mid-range, where the LED current is actually
/// chopped. The panel's own false frames are read at every brightness, but the
/// chopper multiplies their rate — at full duty the pin is a steady level with no
/// current edges and they thin out (bench, 2026-09-29), the opposite of what a
/// probe wants. Light enough to read, chopped enough to provoke.
const PROBE_DUTY: u16 = 91;

/// Rising edges seen on the panel's Touch_INT since boot. The controller announces
/// each report it has for the host with a pulse there (~100 µs, `IrqPluseWidth`), so
/// the tool can ask the one question polling cannot: did the frame it just read come
/// with one? A frame the chip never announced is not a touch — that is what the
/// out-of-range refusal in `rsk_ui::touch` turns away (bench, 2026-09-29).
static IRQ_EDGES: AtomicU16 = AtomicU16::new(0);

/// Latch Touch_INT's rising edges. The RP2350 latches an edge in the bank's
/// write-1-to-clear `INTR` until the GPIO handler reads it, so the count survives a
/// pulse far shorter than any poll — a level poll would miss every one of them.
#[embassy_executor::task]
pub async fn irq_task(mut irq: Input<'static>) {
    loop {
        irq.wait_for_rising_edge().await;
        IRQ_EDGES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Whether the finger is down from the previous tick. The controller reports
/// level, not edges: without this, one contact would be recorded against every
/// target the panel walks through while it is held.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    AwaitTap,
    AwaitRelease,
}

/// Drive the calibration screen until the device is reset. Spawned in place of
/// `status_task` by the `display-calib` build — the flow that normally owns this
/// panel is not started, so nothing else paints over the tool's screen.
#[embassy_executor::task]
pub async fn calib_task(ui: &'static RefCell<Ui>) {
    let mut state = CalibState::new();
    let mut flow = Flow::AwaitTap;
    // What the panel is showing, so a still finger does not repaint it 33 times a
    // second. The IRQ count is part of it — it is on screen, and a rising edge with
    // nothing else changed still has to reach the panel. `None` until the first frame.
    let mut painted: Option<(CalibState, Option<Point>, u16)> = None;
    let mut lit = false;

    loop {
        if let Ok(mut ui) = ui.try_borrow_mut() {
            let (panel, touch, hooks) = ui.calibration_parts();
            if !lit {
                // The panel-owning flow restores the *persisted* brightness, which
                // can be a dim level; a calibration screen has to be readable.
                hooks.set_backlight(PROBE_DUTY);
                lit = true;
            }

            let raw = touch.read_raw();
            match (flow, raw) {
                (Flow::AwaitTap, Some(point)) => {
                    state.record(point);
                    flow = Flow::AwaitRelease;
                }
                (Flow::AwaitRelease, None) => flow = Flow::AwaitTap,
                _ => {}
            }

            let irq = IRQ_EDGES.load(Ordering::Relaxed);
            if painted != Some((state, raw, irq)) {
                let _ = rsk_ui::render_calib(panel, &state, raw, irq);
                painted = Some((state, raw, irq));
            }
        }
        Timer::after_millis(FRAME_MS).await;
    }
}
