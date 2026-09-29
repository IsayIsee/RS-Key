// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! This board's trusted display: the Waveshare RP2350 touch panels (ST7789 over
//! PIO serial output, the CST328/CST816D touch controller on the board's own I2C
//! bus), plus the board verbs the flow asks for.
//!
//! The flow itself — which screen is shown when, the PIN pad, the Approve/Deny
//! wait — is [`rsk_display`], where a host can run it against a window. What is
//! here is the part that is genuinely this board's: bringing the panel and the
//! touch controller up, and the [`rsk_display::Hooks`] impl wiring the backlight
//! PWM, the wake button and the firmware's own globals back in.

use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_rp::gpio::{Input, Output};
use embassy_rp::i2c::{Blocking as I2cBlocking, I2c};
use embassy_rp::peripherals::{I2C0, I2C1};
use embassy_rp::pwm::{Config as PwmConfig, Pwm};
use embassy_time::{Duration, Instant, block_for};
use mipidsi::options::{ColorInversion, ColorOrder};

extern crate alloc;
use alloc::boxed::Box;

use rsk_display::{BL_TOP, TouchPad};
use rsk_rsa::RsaKey;

use crate::flash_storage::FlashStorage;
use crate::handler::{FidoRng, Store};

use crate::display_panel::Panel;
pub(crate) use crate::display_panel::PioDisplayTx;

pub use rsk_display::{DeviceInfo, DeviceKeys, UI_YIELD_FLOOR_MS, piv_ref_title};

/// CST328 7-bit I2C address.
const CST328_ADDR: u16 = 0x1A;
/// CST816D 7-bit I2C address (the CST816 family shares it).
const CST816_ADDR: u16 = 0x15;

/// This board's instance of the flow.
pub type Ui = rsk_display::Ui<'static, Panel, Touch, DisplayHooks, FlashStorage, FidoRng>;
/// The on-screen presence backend over this board's panel.
pub type TouchPresence =
    rsk_display::TouchPresence<'static, Panel, Touch, DisplayHooks, FlashStorage, FidoRng>;

/// The panel's SPI bus + control pins, bundled so `main` stays
/// within embassy's argument cap when it hands the peripherals over.
pub struct PanelHw {
    pub spi: PioDisplayTx,
    pub cs: Output<'static>,
    pub dc: Output<'static>,
    pub rst: Output<'static>,
    /// GPIO16 backlight, driven as PWM for brightness (constructed at zero duty so
    /// the panel stays dark through init — no white flash).
    pub bl: Pwm<'static>,
}

/// The touch controller's I2C bus: whichever of the two the board wires its
/// pads to (the 2.8" and the 1.54" use I2C1 on GP6/GP7, the 2" i2c0 on
/// GP12/GP13). `I2c` is generic over its instance and the board config carries
/// values, so the variant is chosen once in `main` and every transfer dispatches
/// on it — a generic `Touch` instead would ripple into the `Ui` type alias and
/// the `UI` cell that holds it.
pub enum TouchI2c {
    Block0(I2c<'static, I2C0, I2cBlocking>),
    Block1(I2c<'static, I2C1, I2cBlocking>),
}

impl TouchI2c {
    pub fn block0(i2c: I2c<'static, I2C0, I2cBlocking>) -> Self {
        Self::Block0(i2c)
    }

    pub fn block1(i2c: I2c<'static, I2C1, I2cBlocking>) -> Self {
        Self::Block1(i2c)
    }

    /// A bus error is erased to `()`: a failed transfer already means "no touch"
    /// or "the controller did not take the write" to every caller here.
    fn write(&mut self, addr: u16, bytes: &[u8]) -> Result<(), ()> {
        match self {
            Self::Block0(i2c) => i2c.blocking_write(addr, bytes),
            Self::Block1(i2c) => i2c.blocking_write(addr, bytes),
        }
        .map_err(|_| ())
    }

    fn write_read(&mut self, addr: u16, wr: &[u8], rd: &mut [u8]) -> Result<(), ()> {
        match self {
            Self::Block0(i2c) => i2c.blocking_write_read(addr, wr, rd),
            Self::Block1(i2c) => i2c.blocking_write_read(addr, wr, rd),
        }
        .map_err(|_| ())
    }
}

/// The touch controller's I2C bus + reset pin. `rst` is `None` on a board that
/// wires Touch_RST to the panel's own reset pad (`tp_rst_shared`): there the
/// panel's reset pulse is the controller's, and the pad has a single owner.
///
/// `i2c` is a *shared* cell because two things read the controller: the flow, on its poll
/// (our screens need a level, so they cannot be driven by announcements alone), and
/// [`touch_irq_task`], which reads it on the controller's own announcement the way the
/// vendor's driver does. Both run on the thread executor, so a `RefCell` is the whole of
/// the synchronization — the modal loops hold the *Ui*'s cell for a whole screen, which is
/// why the bus needed a cell of its own.
pub struct TouchHw {
    pub i2c: &'static RefCell<TouchI2c>,
    pub rst: Option<Output<'static>>,
}

/// PWM config for the backlight: 8-bit `top`, non-inverted (high = lit), with
/// `duty` as the on-fraction. Shared by `main`'s initial (zero-duty) construction
/// and every live brightness change so the polarity always matches.
pub fn backlight_cfg(duty: u16) -> PwmConfig {
    // `PwmConfig` is `#[non_exhaustive]`, so build from Default and set fields.
    let mut cfg = PwmConfig::default();
    cfg.top = BL_TOP;
    // Scale the divider: the default is 1, putting the period at
    // clk_sys/(top+1) = 160 MHz/256 = 1.6 µs (625 kHz). Every backlit board here
    // switches its backlight through an SS8050 low-side transistor, whose ~0.3–0.5 µs
    // storage delay is a third of that period — so the duty range compresses at the
    // top (measured on the 2": duty 135 and duty 255 are indistinguishable). ×16 puts
    // the period at 25.6 µs, where the delay is ~2% of it: 39 kHz, far above flicker.
    // The chopper also couples into the touch controller: on the 2" bench the false
    // frames a poll occasionally reads are noticeably rarer at full duty — a steady
    // level, so no current edges at all — than at any dimmed one (2026-09-29).
    cfg.divider = cfg.divider * 16;
    // The compare register is per channel, and a channel whose compare stays 0 is
    // held low for the whole period — so a board whose backlight hangs off
    // channel B (this fork's GEEK wiring shares slice 6 B, the 2" uses slice 7 B)
    // stayed dark while this wrote `compare_a` only.
    if crate::BUILD_DISPLAY_BL_PWM_CHANNEL == 1 {
        cfg.compare_b = duty.min(BL_TOP);
    } else {
        cfg.compare_a = duty.min(BL_TOP);
    }
    cfg
}

/// The report the controller last announced on its Touch_INT, packed as `x << 12 | y`, or
/// [`NO_REPORT`]. Written by [`touch_irq_task`] at the pulse and taken by the next
/// [`TouchPad::read`].
static ANNOUNCED_REPORT: AtomicU32 = AtomicU32::new(NO_REPORT);

/// The packed-report value that means "nothing announced": a 12-bit coordinate pair can
/// never produce it.
const NO_REPORT: u32 = u32::MAX;

/// Latch the touch controller's Touch_INT and read the report there, which is where the
/// vendor's driver reads it. The pulse is ~100 µs — far shorter than any poll — but the
/// RP2350 holds the edge in the bank's write-1-to-clear `INTR` until the GPIO handler
/// reads it, so none is missed; and reading *at* the pulse is what keeps a tap shorter than
/// our poll interval from vanishing. Spawned only where the board wires the line, and only
/// by the flow build: the calibration tool keeps counts of the same edges instead, so this
/// task is not compiled there.
#[cfg(not(feature = "display-calib"))]
#[embassy_executor::task]
pub async fn touch_irq_task(mut irq: Input<'static>, bus: &'static RefCell<TouchI2c>) {
    loop {
        irq.wait_for_rising_edge().await;
        // `try_borrow_mut`: the flow may be mid-transfer, and a dropped pulse costs nothing
        // — the next one is along in a scan period.
        if let Some(p) = bus
            .try_borrow_mut()
            .ok()
            .and_then(|mut b| read_report(&mut b))
        {
            ANNOUNCED_REPORT.store(pack(p), Ordering::Relaxed);
        }
    }
}

/// Pack a raw point for [`ANNOUNCED_REPORT`]: both axes are 12-bit.
#[cfg(not(feature = "display-calib"))]
fn pack(p: rsk_ui::Point) -> u32 {
    ((p.x as u32 & 0x0FFF) << 12) | (p.y as u32 & 0x0FFF)
}

/// The CST328 touch controller on this board's I2C bus. The reset pin is pulsed once
/// during [`build`] (or left to the panel on a `tp_rst_shared` board); the bus is the
/// shared cell [`TouchHw`] carries.
pub struct Touch {
    bus: &'static RefCell<TouchI2c>,
}

impl Touch {
    pub fn new(bus: &'static RefCell<TouchI2c>) -> Self {
        Self { bus }
    }
}

impl Touch {
    /// Leave the controller reporting after the reset pulse.
    fn normal_mode(&mut self) {
        let i2c = &mut *self.bus.borrow_mut();
        match crate::BUILD_DISPLAY_TOUCH_IC {
            crate::TOUCH_CST816D => {
                // The vendor's init, in the vendor's order: DisAutoSleep (left off, it
                // blanks between polls and swallows the first touch after each one), then
                // the report and scan registers. A/B'd on the 2" 2026-09-29: they do *not*
                // stop its occasional false frame — the refusal in `touch::scale` does.
                let _ = i2c.write(CST816_ADDR, &[0xFE, 0x01]); // DisAutoSleep
                let _ = i2c.write(CST816_ADDR, &[0xFA, 0x41]); // IrqCtl, point mode
                let _ = i2c.write(CST816_ADDR, &[0xED, 0x01]); // IrqPluseWidth
                let _ = i2c.write(CST816_ADDR, &[0xEE, 0x01]); // NorScanPer
            }
            _ => {
                // Register 0xD109 (REG_MODE_NORMAL) as a 2-byte big-endian
                // address with no payload.
                let _ = i2c.write(CST328_ADDR, &[0xD1, 0x09]);
            }
        }
    }

    /// One report in the *controller's* own frame, with no board range applied:
    /// the numbers the calibration flow solves a board's range from. Every other
    /// caller wants the panel pixels [`TouchPad::read`] returns instead.
    pub fn read_raw(&mut self) -> Option<rsk_ui::Point> {
        read_report(&mut self.bus.borrow_mut())
    }
}

/// The board's read of the controller — the one place either reader goes through, so the
/// flow's polls and the announcement in [`touch_irq_task`] cannot drift apart. In the
/// *controller's* own frame, with no board range applied.
fn read_report(i2c: &mut TouchI2c) -> Option<rsk_ui::Point> {
    match crate::BUILD_DISPLAY_TOUCH_IC {
        crate::TOUCH_CST816D => {
            // One register per transfer. All three of the vendor's own drivers for this
            // board read this controller that way — single-byte `I2C_Read(reg)` calls,
            // never a block read — and the registers are the family's single-byte layout
            // from `CST816_BLOCK`: gesture, finger count, X high/low, Y high/low. The
            // controller is the one part of this panel whose physical behaviour we cannot
            // change, so its read lives in this board's branch rather than in a shape
            // shared with the CST328 (2026-09-29).
            let mut buf = [0u8; 6];
            for i in 0..buf.len() {
                let mut byte = [0u8; 1];
                let reg = rsk_ui::touch::CST816_BLOCK + i as u8;
                match i2c.write_read(CST816_ADDR, &[reg], &mut byte) {
                    Ok(()) => buf[i] = byte[0],
                    Err(()) => return None,
                }
            }
            rsk_ui::touch::parse_cst816d(&buf)
        }
        _ => {
            let mut buf = [0u8; 7];
            let pt = match i2c.write_read(CST328_ADDR, &[0xD0, 0x00], &mut buf) {
                Ok(()) => rsk_ui::touch::parse_cst328(&buf),
                Err(()) => None,
            };
            // Clear register 0xD005 (write address + a 0 byte) to ack the report.
            let _ = i2c.write(CST328_ADDR, &[0xD0, 0x05, 0x00]);
            pt
        }
    }
}

impl TouchPad for Touch {
    /// Read the first finger's coordinate, if any. What comes back is in the *controller's*
    /// frame; the board's range maps it onto the panel's, refusing a reading outside that
    /// range rather than pinning it to the edge (`scale`).
    ///
    /// A report the controller announced comes first — that is where the vendor's own driver
    /// reads, and the only trace a tap shorter than our poll interval leaves. Past it this is
    /// the poll our screens need for a *level*: they hold a press for as long as the finger
    /// is down, and the announcement rate is not a contract to build that on.
    fn read(&mut self) -> Option<rsk_ui::Point> {
        let range = crate::BUILD_DISPLAY_TOUCH_RANGE.unwrap_or(rsk_ui::touch::TouchRange::IDENTITY);
        let announced = ANNOUNCED_REPORT.swap(NO_REPORT, Ordering::Relaxed);
        if announced != NO_REPORT {
            let p = rsk_ui::Point::new((announced >> 12) as u16, (announced & 0x0FFF) as u16);
            return range.map(p);
        }
        self.read_raw().and_then(|p| range.map(p))
    }
}

/// The board verbs and firmware globals the flow reaches through.
pub struct DisplayHooks {
    /// Backlight on GPIO16, driven as PWM for brightness control and held for the
    /// device's lifetime (dropping it disconnects the pad → black panel).
    bl: Pwm<'static>,
    // The CST328 reset (GPIO17 on the 2.8"), held so its pad isn't disconnected on
    // drop (an embassy `Output` sets funcsel = Null when dropped); never toggled
    // after build. `None` when the board shares the panel's reset pad.
    #[allow(dead_code)]
    tp_rst: Option<Output<'static>>,
    /// The display-sleep wake button (the board's BAT_PWR / a `WAKE_PIN` GPIO) paired
    /// with its `active_high` polarity, or `None` when `WAKE_PIN=none` (touch-only
    /// wake). Polled while asleep.
    wake_btn: Option<(Input<'static>, bool)>,
}

impl rsk_display::Hooks for DisplayHooks {
    fn set_backlight(&mut self, duty: u16) {
        self.bl.set_config(&backlight_cfg(duty));
    }

    fn wake_pressed(&self) -> bool {
        match &self.wake_btn {
            Some((btn, active_high)) => {
                if *active_high {
                    btn.is_high()
                } else {
                    btn.is_low()
                }
            }
            None => false,
        }
    }

    fn led_status(&self) -> u8 {
        crate::led::status()
    }

    fn set_led_status(&mut self, status: u8) {
        crate::led::set_status(status);
    }

    fn attach_elapsed_ms(&self) -> u64 {
        crate::usb_attach::elapsed_ms()
    }

    fn host_request_pending_after(&self, since: Instant) -> bool {
        crate::worker::host_request_pending_after(since)
    }

    fn host_request_pending(&self) -> bool {
        crate::worker::host_request_pending()
    }

    fn request_reboot(&mut self, bootsel: bool) {
        crate::vendor::request_reboot(bootsel);
    }

    fn reboot_pending(&self) -> bool {
        crate::vendor::reboot_pending()
    }

    fn note_local_pin_changed(&mut self) {
        crate::handler::note_local_pin_changed();
    }

    /// The same worker signal, because its whole effect is what both events need:
    /// end the RAM `pinUvAuthToken` before the next CBOR command. They stay mapped
    /// together only while that holds — a re-key-*specific* side effect added
    /// there would then fire on a failed check too.
    fn note_local_pin_failed(&mut self) {
        crate::handler::note_local_pin_changed();
    }

    fn secure_boot_enabled(&self) -> bool {
        use rsk_rescue::Platform as _;
        // A pure OTP read (no flash / no shared borrow) — true only on a fused,
        // secure-boot device, where the boot ROM actually verifies the image
        // signature on next boot.
        crate::rescue_platform::RescuePlatform
            .secure_boot_status()
            .enabled
    }

    fn set_up_pending(&mut self, pending: bool) {
        crate::presence::set_up_pending(pending);
    }

    fn set_cancel_requested(&mut self, requested: bool) {
        crate::presence::set_cancel_requested(requested);
    }

    fn cancel_requested(&self) -> bool {
        crate::presence::cancel_requested()
    }

    fn presence_timeout_ms(&self) -> u32 {
        crate::presence::presence_timeout_ms()
    }

    fn set_presence_timeout_ms(&mut self, ms: u32) {
        crate::presence::set_presence_timeout_ms(ms);
    }

    fn rsa_search_progress(
        &mut self,
        nbits: usize,
        rng: &mut dyn rsk_sdk::Rng,
        on_tick: &mut dyn FnMut(),
    ) -> Option<Box<RsaKey>> {
        crate::core1::run_rsa_search_progress(nbits, rng, on_tick)
    }
}

/// Build and initialize the panel + touch from the raw peripherals, then hand them
/// to the flow. Blocking (~370 ms of panel/touch reset) — `main` calls this *after*
/// the USB task is spawned, so the interrupt executor keeps enumerating while these
/// busy-waits run on the thread executor; enumeration is never delayed.
pub fn build(
    panel: PanelHw,
    touch: TouchHw,
    info: DeviceInfo,
    fs: &'static RefCell<Store>,
    keys: DeviceKeys,
    rng: &'static RefCell<FidoRng>,
    wake_btn: Option<(Input<'static>, bool)>,
) -> Ui {
    let PanelHw {
        spi,
        cs,
        dc,
        rst,
        bl,
    } = panel;
    let TouchHw {
        i2c,
        rst: mut tp_rst,
    } = touch;

    // ST7789 240x320 portrait. Inversion and color order from board config.
    let invert = if crate::BUILD_DISPLAY_INVERT_COLORS {
        ColorInversion::Inverted
    } else {
        ColorInversion::Normal
    };
    let color_order = match crate::BUILD_DISPLAY_COLOR_ORDER {
        1 => ColorOrder::Bgr,
        _ => ColorOrder::Rgb,
    };
    let mut damage_key_bytes = [0u8; 16];
    rsk_sdk::Rng::fill(&mut *rng.borrow_mut(), &mut damage_key_bytes);
    let damage_key = [
        u64::from_le_bytes(damage_key_bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(damage_key_bytes[8..].try_into().unwrap()),
    ];
    let panel = Panel::new(
        spi,
        cs,
        dc,
        rst,
        damage_key,
        invert,
        color_order,
        crate::BUILD_DISPLAY_MADCTL_SCAN,
        crate::BUILD_DISPLAY_WIN_OFF,
    );

    // CST328 reset pulse (high → low → high), then normal reporting mode. On a
    // `tp_rst_shared` board there is no second pad: the panel's reset in
    // `Panel::new` drove the shared line, with the longer low time the touch
    // controller asks for (`display_panel::reset_and_init`).
    if let Some(rst) = tp_rst.as_mut() {
        rst.set_high();
        block_for(Duration::from_millis(10));
        rst.set_low();
        block_for(Duration::from_millis(10));
        rst.set_high();
        block_for(Duration::from_millis(50));
    }
    let mut touch = Touch::new(i2c);
    touch.normal_mode();

    let hooks = DisplayHooks {
        bl,
        tp_rst,
        wake_btn,
    };
    Ui::new(panel, touch, hooks, info, fs, keys, rng)
}

/// The ambient status screen. `#[embassy_executor::task]` cannot be generic, so
/// this monomorphic wrapper is what the spawner takes; the loop itself is
/// [`rsk_display::status_loop`].
#[embassy_executor::task]
pub async fn status_task(ui: &'static RefCell<Ui>) {
    rsk_display::status_loop(ui).await;
}
