// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.1 §12.5 hmac-secret *evaluate* conformance, driven through the wire
//! envelope (`process_cbor`): a credential is created with hmac-secret, then a
//! getAssertion carries `{keyAgreement, saltEnc, saltAuth}` and the encrypted
//! output decrypts (under the ECDH shared secret) to a 32-byte value that is
//! deterministic per (credential, salt). The platform runs the real
//! pinUvAuthProtocol-2 primitives.

use super::{Authr, assert_ok, field_at, pin_auth};
use crate::consts::{ALG_ES256, CTAP_CLIENT_PIN, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL};
use crate::cose::cose_key_ecdh;
use crate::state::{PERM_GA, PERM_MC};
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use rsk_crypto::pinproto::{self, PinProto, public_xy};

const RP_ID: &str = "hmac.example";
const CDH: [u8; 32] = [0xCD; 32];
const SALT: [u8; 32] = [0xA1; 32];

/// The platform half of the ECDH exchange (a fixed key + the shared secret).
struct Ecdh {
    x: [u8; 32],
    y: [u8; 32],
    shared: Vec<u8>,
}

impl Ecdh {
    fn establish(a: &mut Authr) -> Self {
        // getKeyAgreement: {1: proto=2, 2: subCommand=2}.
        let mut kbuf = [0u8; 16];
        let kn = {
            let mut e = Encoder::new(Cursor::new(&mut kbuf[..]));
            e.map(2).unwrap();
            e.u8(1).unwrap().u64(2).unwrap();
            e.u8(2).unwrap().u64(2).unwrap();
            e.writer().position()
        };
        let r = a.send(CTAP_CLIENT_PIN, &kbuf[..kn]);
        let (ax, ay) = authenticator_public(&r.body);
        let mut s = [0u8; 32];
        s[0] = 0x13;
        s[31] = 0x42;
        let (x, y) = public_xy(&s).unwrap();
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(PinProto::Two, &s, &ax, &ay, &mut shared).unwrap();
        Ecdh {
            x,
            y,
            shared: shared[..slen].to_vec(),
        }
    }

    fn enc(&self, pt: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 96];
        let n = pinproto::encrypt(PinProto::Two, &self.shared, &[0x55; 16], pt, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 32];
        let n = pinproto::authenticate(PinProto::Two, &self.shared, data, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn decrypt(&self, ct: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 96];
        let n = pinproto::decrypt(PinProto::Two, &self.shared, ct, &mut out).unwrap();
        out[..n].to_vec()
    }
}

/// The authenticator's key-agreement public key from getKeyAgreement.
fn authenticator_public(body: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut d = field_at(body, 1).expect("keyAgreement (0x01) present");
    assert_eq!(d.map().unwrap().unwrap(), 5);
    d.u8().unwrap();
    d.u8().unwrap(); // 1: kty
    d.u8().unwrap();
    d.i64().unwrap(); // 3: alg
    d.i8().unwrap();
    d.u8().unwrap(); // -1: crv
    d.i8().unwrap(); // -2: x label
    let mut x = [0u8; 32];
    x.copy_from_slice(d.bytes().unwrap());
    d.i8().unwrap(); // -3: y label
    let mut y = [0u8; 32];
    y.copy_from_slice(d.bytes().unwrap());
    (x, y)
}

/// A discoverable makeCredential over `RP_ID` requesting hmac-secret.
fn mc_hmac() -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP_ID)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[9, 9]).unwrap();
        e.str("name").unwrap().str("grace").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("hmac-secret")
            .unwrap()
            .bool(true)
            .unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A getAssertion over `RP_ID` evaluating hmac-secret for `salt`.
fn ga_hmac(ecdh: &Ecdh, salt: &[u8]) -> Vec<u8> {
    let salt_enc = ecdh.enc(salt);
    let salt_auth = ecdh.mac(&salt_enc);
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        // extensions: { hmac-secret: { 1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: proto } }
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_key_ecdh(&mut e, &ecdh.x, &ecdh.y).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth).unwrap();
        e.u8(4).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// [`ga_hmac`] plus `{5: {"up": false}}` — the silent pre-flight shape.
fn ga_hmac_up_false(ecdh: &Ecdh, salt: &[u8]) -> Vec<u8> {
    let salt_enc = ecdh.enc(salt);
    let salt_auth = ecdh.mac(&salt_enc);
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_key_ecdh(&mut e, &ecdh.x, &ecdh.y).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth).unwrap();
        e.u8(4).unwrap().u64(2).unwrap();
        e.u8(5).unwrap().map(1).unwrap();
        e.str("up").unwrap().bool(false).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// [`ga_hmac_up_false`] with the extension value replaced by one carrying no
/// sub-fields — an empty map, or a value that is not a map at all.
fn ga_degenerate_up_false(empty_map: bool) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap();
        if empty_map {
            e.map(0).unwrap();
        } else {
            e.bool(true).unwrap();
        }
        e.u8(5).unwrap().map(1).unwrap();
        e.str("up").unwrap().bool(false).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The (still-encrypted) hmac-secret output from a getAssertion authData.
fn hmac_output(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    // Assertion authData is rpIdHash(32) | flags(1) | counter(4) | extension map.
    let mut ext = Decoder::new(&ad[37..]);
    let n = ext.map().unwrap().unwrap();
    for _ in 0..n {
        if ext.str().unwrap() == "hmac-secret" {
            return ext.bytes().unwrap().to_vec();
        }
        ext.skip().unwrap();
    }
    panic!("hmac-secret output missing from the assertion");
}

#[test]
fn hmac_secret_evaluate_returns_output() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac()));
    let ecdh = Ecdh::establish(&mut a);
    let g = a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT));
    assert_ok(&g);
    let out = ecdh.decrypt(&hmac_output(&g.body));
    assert_eq!(
        out.len(),
        32,
        "one salt yields a 32-byte hmac-secret output"
    );
}

#[test]
fn hmac_secret_is_deterministic_per_salt() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac()));
    let ecdh = Ecdh::establish(&mut a);

    let out1 = ecdh.decrypt(&hmac_output(
        &a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT)).body,
    ));
    let out2 = ecdh.decrypt(&hmac_output(
        &a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT)).body,
    ));
    assert_eq!(out1, out2, "same salt → same hmac-secret output");

    let salt2 = [0xB2u8; 32];
    let other = ecdh.decrypt(&hmac_output(
        &a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &salt2)).body,
    ));
    assert_ne!(out1, other, "a different salt yields a different output");
}

/// The `up:false` probe skips the presence gate, so serving the extension there
/// hands out per-credential PRF material with no touch and no PIN — and does so on
/// the always-uv build too (audit run-32). The refusal is the invariant; its code
/// follows the reference device: §12.5 writes CTAP2_ERR_UNSUPPORTED_OPTION, a
/// YubiKey 5.8.0 answers CTAP2_ERR_UP_REQUIRED — measured in all three shapes
/// (allowList with a token, without one, and a discoverable walk), issue #109.
#[test]
fn hmac_secret_is_refused_on_an_up_false_probe() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac()));
    let ecdh = Ecdh::establish(&mut a);
    // The same request minus the option still works, so this is the option's doing.
    assert_ok(&a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT)));
    let g = a.send(CTAP_GET_ASSERTION, &ga_hmac_up_false(&ecdh, &SALT));
    assert_eq!(
        g.status,
        crate::error::CtapError::UpRequired as u8,
        "hmac-secret must be refused with 0x3b on an up:false request"
    );
    assert!(g.body.is_empty(), "a refused probe returns no assertion");
}

/// The other half of that rule, and the line between them: an hmac-secret value
/// with no sub-fields in it is not a present extension, so it is not what the
/// refusal above is about. A YubiKey 5.8.0 answers `0x00` to the silent
/// pre-flight for both shapes — an empty map and a boolean — where a real
/// request in the same position is `UP_REQUIRED`. Ours used to answer
/// MISSING_PARAMETER to the first and INVALID_CBOR to the second, and a platform
/// that sends either got no assertion at all.
#[test]
fn a_degenerate_hmac_secret_is_not_a_present_extension() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac()));
    for empty_map in [true, false] {
        let g = a.send(CTAP_GET_ASSERTION, &ga_degenerate_up_false(empty_map));
        assert_eq!(
            g.status, 0,
            "a value with no sub-fields must not refuse the ceremony (empty_map={empty_map})"
        );
        assert!(
            !g.body.is_empty(),
            "the assertion is served (empty_map={empty_map})"
        );
    }
}

/// A UV makeCredential evaluating hmac-secret at registration time
/// (`hmac-secret-mc`, CTAP 2.2 §12.5), the way a platform asking for PRF at
/// creation does.
fn mc_hmac_mc(ecdh: &Ecdh, token: &[u8; 32], salt: &[u8]) -> Vec<u8> {
    let salt_enc = ecdh.enc(salt);
    let salt_auth = ecdh.mac(&salt_enc);
    let auth = pin_auth(token, &CDH);
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(8).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP_ID)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[9, 9]).unwrap();
        e.str("name").unwrap().str("grace").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        // extensions: { hmac-secret: true, hmac-secret-mc: {1: kA, 2: saltEnc, 3: saltAuth, 4: proto} }
        e.u8(6).unwrap().map(2).unwrap();
        e.str("hmac-secret").unwrap().bool(true).unwrap();
        e.str("hmac-secret-mc").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_key_ecdh(&mut e, &ecdh.x, &ecdh.y).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth).unwrap();
        e.u8(4).unwrap().u64(2).unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.u8(8).unwrap().bytes(&auth).unwrap();
        e.u8(9).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// [`ga_hmac`] under a pinUvAuthToken, so the assertion asserts UV.
fn ga_hmac_uv(ecdh: &Ecdh, token: &[u8; 32], salt: &[u8]) -> Vec<u8> {
    let salt_enc = ecdh.enc(salt);
    let salt_auth = ecdh.mac(&salt_enc);
    let auth = pin_auth(token, &CDH);
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_key_ecdh(&mut e, &ecdh.x, &ecdh.y).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth).unwrap();
        e.u8(4).unwrap().u64(2).unwrap();
        e.u8(6).unwrap().bytes(&auth).unwrap();
        e.u8(7).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The `hmac-secret-mc` output from a makeCredential authData.
fn hmac_mc_output(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    // rpIdHash(32) | flags(1) | counter(4) | aaguid(16) | credLen(2) | credId | COSE | ext
    let cred_len = ((ad[53] as usize) << 8) | ad[54] as usize;
    let mut after = Decoder::new(&ad[55 + cred_len..]);
    after.skip().unwrap(); // the COSE public key
    let mut ext = Decoder::new(&ad[55 + cred_len + after.position()..]);
    let n = ext.map().unwrap().unwrap();
    for _ in 0..n {
        if ext.str().unwrap() == "hmac-secret-mc" {
            return ext.bytes().unwrap().to_vec();
        }
        ext.skip().unwrap();
    }
    panic!("hmac-secret-mc output missing from the registration");
}

/// The whole point of PRF for a password manager, and the one thing no test
/// covered: the value a platform reads at REGISTRATION and the value it reads on
/// the follow-up assertion are the same secret. They travel two different code
/// paths — makeCredential's `key_input` is the box or the fresh resident id,
/// getAssertion's is whatever the lookup found — and §12.5 selects a different
/// half of `cred_random` by the response's UV bit, so both ceremonies must agree
/// on both. A Bitwarden-shaped vault key is exactly this pair (#109).
#[test]
fn hmac_secret_mc_and_the_follow_up_assertion_agree() {
    let mut a = Authr::fresh();
    let ecdh = Ecdh::establish(&mut a);
    let token = a.arm_token(PERM_MC | PERM_GA);

    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac_mc(&ecdh, &token, &SALT));
    assert_ok(&mc);
    let at_creation = ecdh.decrypt(&hmac_mc_output(&mc.body));
    assert_eq!(at_creation.len(), 32);

    // A fresh token for the second ceremony: registration collected user presence
    // and that retires the one it rode in on (GHSA-wqjm-653g-hgw3), which is also
    // what a platform does — the follow-up read is its own PIN prompt.
    let token = a.arm_token(PERM_MC | PERM_GA);
    let ga = a.send(CTAP_GET_ASSERTION, &ga_hmac_uv(&ecdh, &token, &SALT));
    assert_ok(&ga);
    let on_read = ecdh.decrypt(&hmac_output(&ga.body));
    assert_eq!(
        at_creation, on_read,
        "the PRF value read back on the assertion must be the one registration returned"
    );
}

/// The UV half is not the non-UV half — §12.5's `CredRandomWithUV` — so a
/// registration under a pinUvAuthToken and an assertion without one must NOT
/// hand the same secret out. The equality above would hold vacuously if both
/// ceremonies quietly picked the same half whatever the UV bit said.
#[test]
fn the_uv_half_is_not_the_one_an_unverified_assertion_gets() {
    let mut a = Authr::fresh();
    let ecdh = Ecdh::establish(&mut a);
    let token = a.arm_token(PERM_MC | PERM_GA);

    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_hmac_mc(&ecdh, &token, &SALT));
    assert_ok(&mc);
    let with_uv = ecdh.decrypt(&hmac_mc_output(&mc.body));

    let ga = a.send(CTAP_GET_ASSERTION, &ga_hmac(&ecdh, &SALT));
    assert_ok(&ga);
    let without_uv = ecdh.decrypt(&hmac_output(&ga.body));
    assert_ne!(
        with_uv, without_uv,
        "a UV registration and an unverified assertion must not share a CredRandom"
    );
}
