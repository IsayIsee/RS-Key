// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The source obligation behind `PLAT-MODEL-001`: WHICH `paut.permissions`
//! values a host can actually obtain.
//!
//! `RSKeySecurityState!PermSets` carries five of the sixteen subsets of the
//! model's four permission elements and its comment calls that "the sets a host
//! actually asks for". Nothing measured it. This sweep does, over every one of
//! the 256 requestable bytes on both permission-bearing subcommands, against an
//! oracle written from CTAP 2.1 §6.5.5.7.2/.3 and this build's own advertised
//! option IDs — not from `clientpin.rs`.
//!
//! The oracle is not a transcription, and the proof of that is the divergence
//! set: it disagrees with the shipped path on 48 of the 512 cases on the default
//! build, all of them the same shape (a permission bit this build implements no
//! option for, which the spec says to refuse and the code admits into a token no
//! gate reads). The divergences are held exactly, so a new one and a repaired
//! one both redden.
//!
//! And the set is BUILD-DEPENDENT, which the first version of this file missed:
//! it wrote the advertised set down as a constant including `lbw`, while §6.4
//! forbids the `largeBlobs` option beside the CTAP 2.3 extension and
//! `getinfo.rs` drops the key under `largeblob-ext` — a flavour
//! `scripts/check.sh` runs. Under it the count is 72, and the extra 24 are a
//! divergence class the constant version agreed away.

use super::*;
use crate::consts::{EF_PAUTHTOKEN, LARGE_BLOB_EXT};
use crate::state::{PERM_CM, PERM_LBW, PERM_PCMR};

/// `getPinUvAuthTokenUsingPinWithPermissions`.
const SUB_PIN: u64 = 9;
/// `getPinUvAuthTokenUsingUvWithPermissions`.
const SUB_UV: u64 = 6;

/// What a request for a permission set may end in. `Persistent` is its own
/// answer and not a `Session`: the `pcmr` branch mints a flash record and
/// leaves the session token alone (`clientpin.rs` `issue_token`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Admit {
    Refused(CtapError),
    Session(u8),
    Persistent,
}

/// The permissions CTAP 2.1 §6.5.5.7.2 lets a host ask for: exactly those whose
/// governing option ID this build advertises in getInfo 0x04. `uvBioEnroll` and
/// `uvAcfg` are absent, so `be` is never admissible and `acfg` is admissible on
/// the host-PIN subcommand only — §6.5.5.7.3 maps it to `uvAcfg` there.
///
/// `largeBlobs` is read from the BUILD and not written down: §6.4 forbids the
/// option beside the CTAP 2.3 extension, so `getinfo.rs` drops the key entirely
/// under `largeblob-ext` and `lbw` stops being a permission this authenticator
/// implements. A constant here would have been a description of one flavour —
/// and `scripts/check.sh` runs the other one.
fn advertised(sub: u64) -> u8 {
    let mut common = PERM_MC | PERM_GA | PERM_CM; // credMgmt
    if !LARGE_BLOB_EXT {
        common |= PERM_LBW; // largeBlobs, absent under the 2.3 extension
    }
    match sub {
        SUB_PIN => common | PERM_ACFG, // authnrCfg
        _ => common,
    }
}

/// The requirement, derived from §6.5.5.7.2/.3 and the advertised option set —
/// never from the implementation. Read as: a request names a non-empty set of
/// permissions this authenticator implements; `pcmr` (perCredMgmtRO) is a
/// different object and travels alone.
fn oracle(sub: u64, requested: u64) -> Admit {
    if requested == 0 {
        return Admit::Refused(CtapError::InvalidParameter);
    }
    if requested & u64::from(PERM_PCMR) != 0 {
        return if requested == u64::from(PERM_PCMR) {
            Admit::Persistent
        } else {
            Admit::Refused(CtapError::UnauthorizedPermission)
        };
    }
    if requested & !u64::from(advertised(sub)) != 0 {
        return Admit::Refused(CtapError::UnauthorizedPermission);
    }
    Admit::Session(requested as u8)
}

/// A sentinel no request can produce (bit 7 is undefined and `PERM_BE` is
/// refused, so no admitted byte carries both), written into the token before
/// each probe so "nothing was minted" is observable rather than inferred.
const UNTOUCHED: u8 = PERM_BE | 0x80;

/// Drive the shipped `client_pin` path once and read back what it did.
fn probe(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    state: &mut FidoState,
    pad: &mut UvPad,
    plat: &Platform,
    sub: u64,
    requested: u64,
) -> Admit {
    state.paut.permissions = UNTOUCHED;
    state.paut.in_use = false;
    let had_ppuat = fs.has_data(EF_PAUTHTOKEN.get());
    let req = if sub == SUB_PIN {
        plat.get_token_perms_req(PIN, requested)
    } else {
        plat.get_uv_token_req(requested)
    };
    let mut out = [0u8; 256];
    match run_with(pad, fs, rng, state, &req, &mut out) {
        Err(e) => Admit::Refused(e),
        Ok(_) if state.paut.permissions == UNTOUCHED && !state.paut.in_use => {
            assert!(
                !had_ppuat || fs.has_data(EF_PAUTHTOKEN.get()),
                "a persistent grant that existed was dropped by an accepted request"
            );
            Admit::Persistent
        }
        Ok(_) => Admit::Session(state.paut.permissions),
    }
}

fn fixture() -> (Fs<RamStorage>, SeqRng, FidoState, Platform, UvPad) {
    let (fs, rng, state, plat) = setup_with_pin(PIN);
    (fs, rng, state, plat, UvPad::typing(PIN))
}

/// The measured disagreement between the requirement and the shipped path.
/// Every member has the same cause: bit 7 is not a permission this build
/// implements, §6.5.5.7.2 step 2 says to answer `UNAUTHORIZED_PERMISSION`, and
/// `clientpin.rs` names only `be` and (on 0x06) `acfg` as forbidden, so the
/// undefined bit rides into a token. It is not an authorization defect — no
/// gate reads bit 7, and every gate is a single-bit test, so the resulting
/// token opens exactly the doors its named bits open — but it IS a conformance
/// divergence, and it is recorded rather than repaired here because the tree's
/// standing rule for undefined input is parity with a real YubiKey, which is a
/// measurement on hardware this change did not have.
fn is_recorded_divergence(sub: u64, requested: u64) -> bool {
    let r = requested as u8;
    // What the build has no option for at all, on this subcommand.
    let unimplemented = !(advertised(sub) | PERM_PCMR);
    // What `clientpin.rs` actually names: `be`, `acfg` on the built-in-UV path,
    // and `pcmr` in company. Everything else it admits.
    let refused = r & PERM_BE != 0
        || (sub == SUB_UV && r & PERM_ACFG != 0)
        || (r & PERM_PCMR != 0 && r != PERM_PCMR);
    r != 0 && r & unimplemented != 0 && !refused
}

/// Exhaustive over the byte, on both subcommands. `audit` takes its floors as
/// parameters so a case can hold the shipped numbers instead of patching them.
fn audit(want_divergences: usize, want_cases: usize) -> (usize, usize) {
    let (mut fs, mut rng, mut state, plat, mut pad) = fixture();
    let (mut cases, mut diverged) = (0usize, 0usize);
    for sub in [SUB_PIN, SUB_UV] {
        for requested in 0u64..=255 {
            let got = probe(
                &mut fs, &mut rng, &mut state, &mut pad, &plat, sub, requested,
            );
            let want = oracle(sub, requested);
            cases += 1;
            if got == want {
                assert!(
                    !is_recorded_divergence(sub, requested),
                    "sub {sub:#x} perms {requested:#04x}: recorded as a divergence, but the \
                     shipped path now agrees with the requirement — retire the record"
                );
                continue;
            }
            diverged += 1;
            assert!(
                is_recorded_divergence(sub, requested),
                "sub {sub:#x} perms {requested:#04x}: requirement says {want:?}, \
                 shipped path says {got:?} — an UNRECORDED divergence"
            );
        }
    }
    assert_eq!(cases, want_cases, "the sweep stopped covering the byte");
    assert_eq!(
        diverged, want_divergences,
        "the divergence set moved: the requirement and the code now disagree \
         somewhere else, which is a finding either way"
    );
    (cases, diverged)
}

/// How many of the 512 the two disagree on. Flavour-dependent, because the
/// permission set the build implements is: under `largeblob-ext` the
/// `largeBlobs` option goes away and `lbw` joins the undefined bit as something
/// §6.5.5.7.2 step 2 says to refuse and this code admits. Written as two
/// measured constants rather than one, because a single number would have been
/// right about the default build and silently wrong about a flavour the gate
/// runs.
const RECORDED_DIVERGENCES: usize = if LARGE_BLOB_EXT { 72 } else { 48 };

/// The obligation itself, over all 512 cases.
#[test]
fn every_requestable_permission_byte_is_answered_as_the_requirement_says() {
    audit(RECORDED_DIVERGENCES, 512);
}

/// `PLAT-MODEL-001` says the model's five subsets are "the set a host can
/// actually obtain". Measured: all sixteen are obtainable, so the assumption is
/// an under-approximation of eleven subsets and not a description. This is the
/// number the model's `WidePerms` arm exists to answer.
#[test]
fn all_sixteen_subsets_of_the_modelled_permissions_are_obtainable() {
    let (mut fs, mut rng, mut state, plat, mut pad) = fixture();
    let model = PERM_MC | PERM_GA | PERM_CM | PERM_ACFG;
    let mut seen = [false; 16];
    let index = |p: u8| {
        // The model names four elements; index them in `PERM_*` bit order.
        usize::from(p & PERM_MC != 0)
            | usize::from(p & PERM_GA != 0) << 1
            | usize::from(p & PERM_CM != 0) << 2
            | usize::from(p & PERM_ACFG != 0) << 3
    };
    for requested in 1u64..=u64::from(model) {
        if requested & !u64::from(model) != 0 {
            continue;
        }
        if let Admit::Session(got) = probe(
            &mut fs, &mut rng, &mut state, &mut pad, &plat, SUB_PIN, requested,
        ) {
            seen[index(got)] = true;
        }
    }
    // The empty projection is reached by the token the model already carries:
    // consume_after_user_presence leaves largeBlobWrite and nothing else. Under
    // `largeblob-ext` this very request is one of the recorded divergences —
    // the build implements no `largeBlobs` option and admits it anyway — which
    // is why the assertion below is about the PROJECTION and not about the
    // request being admissible.
    let mut out = [0u8; 256];
    run_with(
        &mut pad,
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_perms_req(PIN, u64::from(PERM_LBW)),
        &mut out,
    )
    .unwrap();
    seen[index(state.paut.permissions)] = true;

    let missing: std::vec::Vec<usize> = (0..16).filter(|i| !seen[*i]).collect();
    assert!(
        missing.is_empty(),
        "not every modelled subset is obtainable after all — missing {missing:?}"
    );
}

/// The `pcmr` branch is a different object: it mints the flash record and never
/// touches the session token. A build that let it do both would hand a
/// power-cycle-surviving record the session permissions as well.
#[test]
fn a_persistent_grant_request_never_mints_a_session_token() {
    let (mut fs, mut rng, mut state, plat, mut pad) = fixture();
    for sub in [SUB_PIN, SUB_UV] {
        assert_eq!(
            probe(
                &mut fs,
                &mut rng,
                &mut state,
                &mut pad,
                &plat,
                sub,
                u64::from(PERM_PCMR)
            ),
            Admit::Persistent,
            "sub {sub:#x}: a lone pcmr request did not stop at the persistent record"
        );
    }
}

/// The byte is not the whole request: key 9 is a CBOR unsigned, so a host can
/// send a value above 0xFF. `as u8` truncates it before any rule looks at it,
/// and the 256-byte sweep above cannot see that. Two of the three cases below
/// mint a LIVE token carrying no permission at all from a request that named
/// only bits this build does not implement — fail-closed (every gate is a
/// single-bit test, so a zero byte opens nothing) but the same conformance
/// divergence one width out.
#[test]
fn permission_bits_above_the_byte_are_truncated_rather_than_refused() {
    let (mut fs, mut rng, mut state, plat, mut pad) = fixture();
    let mut diverged = 0;
    for requested in [0x100u64, 0xFFFF_FF00, 0xFFFF_FFFF] {
        let got = probe(
            &mut fs, &mut rng, &mut state, &mut pad, &plat, SUB_PIN, requested,
        );
        let truncated = requested as u8;
        let want =
            if truncated & PERM_BE != 0 || (truncated & PERM_PCMR != 0 && truncated != PERM_PCMR) {
                Admit::Refused(CtapError::UnauthorizedPermission)
            } else {
                Admit::Session(truncated)
            };
        assert_eq!(got, want, "perms {requested:#x}: not a plain truncation");
        if got != oracle(SUB_PIN, requested) {
            diverged += 1;
        }
    }
    assert_eq!(
        diverged, 2,
        "the high-bit divergence moved; 0xFFFF_FFFF agrees only because its low \
         byte carries `be`, which IS refused"
    );
}
