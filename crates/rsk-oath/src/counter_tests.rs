// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! HOTP's moving factor on a medium that refuses to advance it. The response buffer
//! reaches the wire whatever the status word says, so a code built ahead of a refused
//! counter write is issued a second time by the next CALCULATE.

use super::*;

/// What a healthy CALCULATE of the RFC 4226 credential answers at `counter`, in
/// either response form: the truncated code (`P2=01`) or the full HMAC (`P2=00`).
fn hotp_response(p2: u8, counter: u64) -> Vec<u8> {
    if p2 == 0x01 {
        let code: u32 = [755224, 287082][counter as usize];
        let mut v = vec![TAG_RESPONSE + 1, 5, 6];
        v.extend(code.to_be_bytes());
        return v;
    }
    let mut v = vec![TAG_RESPONSE, 21, 6];
    v.extend(hmac_sha1(SECRET_SHA1, &counter.to_be_bytes()));
    v
}

#[test]
fn a_refused_counter_advance_puts_no_hotp_code_on_the_wire() {
    for p2 in [0x00, 0x01] {
        let (mut fs, medium) = new_cut_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let cred = put_data(b"h", 0x11, 6, SECRET_SHA1, false, None);
        assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
        let mut body = tlv(TAG_NAME, b"h");
        body.extend(tlv(TAG_CHALLENGE, &0u64.to_be_bytes()));
        let calc = apdu(INS_CALCULATE, 0, p2, &body);

        medium.arm(0);
        let refused = run(&mut app, &mut fs, &calc);
        medium.arm(u32::MAX);
        let second = run(&mut app, &mut fs, &calc);
        let third = run(&mut app, &mut fs, &calc);

        assert_eq!(
            [refused, second, third],
            [
                (Sw::MEMORY_FAILURE, vec![]),
                (Sw::OK, hotp_response(p2, 0)),
                (Sw::OK, hotp_response(p2, 1)),
            ],
            "P2={p2:02X}: a refused advance must send no code and burn no counter"
        );
    }
}
