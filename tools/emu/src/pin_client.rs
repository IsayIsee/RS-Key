// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The platform half of the PIN protocol, for tests that have to get a PIN onto the
//! device the way a host does: agree a key, then `setPIN` over real CBOR. Shared
//! by the device and display tests, which both drive `AppletHandler` over a job.

use rsk_crypto::pinproto::{self, PinProto};
use rsk_fido::consts::CTAP_CLIENT_PIN;

/// pinUvAuthProtocol 2 — the one a current platform picks, and the one whose
/// 16-byte IV and 32-byte MAC make every length below explicit. The wire byte is
/// the same fact twice, so the display test checks the two agree before using either.
pub(crate) const PROTO: PinProto = PinProto::Two;
pub(crate) const PROTO_WIRE: u8 = 2;

pub(crate) const CTAP2_OK: u8 = 0x00;

pub(crate) struct Platform {
    x: [u8; 32],
    y: [u8; 32],
    shared: [u8; 64],
    slen: usize,
}

impl Platform {
    /// Agree a shared secret with the authenticator's `getKeyAgreement` key. The
    /// platform scalar is fixed: nothing here needs a fresh key, and a
    /// deterministic one makes a failing run reproducible.
    pub(crate) fn agree(peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Self {
        let mut scalar = [0u8; 32];
        scalar[0] = 0x13;
        scalar[31] = 0x42;
        let (x, y) = pinproto::public_xy(&scalar).expect("a valid P-256 scalar");
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(PROTO, &scalar, peer_x, peer_y, &mut shared)
            .expect("the authenticator's key agreement point is on the curve");
        Self { x, y, shared, slen }
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.shared[..self.slen]
    }

    pub(crate) fn enc(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 128];
        let n = pinproto::encrypt(PROTO, self.secret(), &[0x55; 16], plaintext, &mut out)
            .expect("the buffer holds an IV and 64 padded bytes");
        out[..n].to_vec()
    }

    pub(crate) fn mac(&self, data: &[u8]) -> Vec<u8> {
        mac_under(self.secret(), data)
    }

    pub(crate) fn key_agreement(&self) -> Vec<u8> {
        cose_ecdh(&self.x, &self.y)
    }
}

pub(crate) fn mac_under(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 32];
    let n = pinproto::authenticate(PROTO, key, data, &mut out).expect("a 32-byte MAC fits");
    out[..n].to_vec()
}

/// `{1:2, 3:-25, -1:1, -2:x, -3:y}` — the COSE ECDH key both sides put on the
/// wire. Written out because the emulator does not depend on a CBOR encoder.
fn cose_ecdh(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![
        0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20,
    ];
    v.extend_from_slice(x);
    v.extend_from_slice(&[0x22, 0x58, 0x20]);
    v.extend_from_slice(y);
    v
}

/// A CBOR byte string. Every one here is 32 bytes or more, so the one-byte-length
/// form is also the canonical one.
pub(crate) fn bstr(b: &[u8]) -> Vec<u8> {
    assert!((24..=255).contains(&b.len()), "not the 0x58 length form");
    let mut v = vec![0x58, b.len() as u8];
    v.extend_from_slice(b);
    v
}

/// A CBOR map with small unsigned keys and pre-encoded values.
pub(crate) fn map(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    assert!(entries.len() < 24, "not the single-byte map header");
    let mut v = vec![0xA0 | entries.len() as u8];
    for (k, val) in entries {
        assert!(*k < 24, "not a single-byte key");
        v.push(*k);
        v.extend_from_slice(val);
    }
    v
}

/// A CBOR unsigned small enough to be its own header.
pub(crate) fn u(n: u8) -> Vec<u8> {
    assert!(n < 24, "not a single-byte unsigned");
    vec![n]
}

pub(crate) fn get_key_agreement_req() -> Vec<u8> {
    let mut v = vec![CTAP_CLIENT_PIN];
    v.extend(map(&[(1, u(PROTO_WIRE)), (2, u(2))]));
    v
}

pub(crate) fn set_pin_req(plat: &Platform, pin: &[u8]) -> Vec<u8> {
    let mut padded = [0u8; 64];
    padded[..pin.len()].copy_from_slice(pin);
    let new_pin_enc = plat.enc(&padded);
    let puap = plat.mac(&new_pin_enc);
    let mut v = vec![CTAP_CLIENT_PIN];
    v.extend(map(&[
        (1, u(PROTO_WIRE)),
        (2, u(3)),
        (3, plat.key_agreement()),
        (4, bstr(&puap)),
        (5, bstr(&new_pin_enc)),
    ]));
    v
}

/// `{1: COSE key}` — the authenticator's ephemeral public point.
pub(crate) fn parse_key_agreement(body: &[u8]) -> ([u8; 32], [u8; 32]) {
    assert_eq!(body[0], CTAP2_OK, "getKeyAgreement");
    let head: &[u8] = &[
        0xA1, 0x01, 0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20,
    ];
    assert_eq!(&body[1..1 + head.len()], head, "COSE ECDH key layout moved");
    let xs = 1 + head.len();
    let mut x = [0u8; 32];
    x.copy_from_slice(&body[xs..xs + 32]);
    assert_eq!(&body[xs + 32..xs + 35], &[0x22, 0x58, 0x20]);
    let mut y = [0u8; 32];
    y.copy_from_slice(&body[xs + 35..xs + 67]);
    (x, y)
}
