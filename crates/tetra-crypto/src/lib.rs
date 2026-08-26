//! Safe Rust bindings over the TETRA Authentication Algorithm (TAA1) suite.
//!
//! The underlying C implementation in `vendor/` is Midnight Blue's reverse-engineered,
//! publicly-released TAA1 (see `vendor/NOTICE`). It is compiled as-is by `build.rs` and linked
//! in; this crate only adds safe, array-typed wrappers around the handful of primitives needed
//! for TETRA air-interface authentication (ETSI EN 300 392-7 clause 4.1).
//!
//! Only the primitives needed for MS/SwMI authentication and DCK derivation are exposed here
//! (TA11/TA41, TA21, TA12/TA22, TB4). OTAR-related primitives (TA31/32/51/52/61/71/81/82/91/92,
//! TB5/6/7) exist in the vendored C and can be wrapped the same way when OTAR support is built.
//!
//! All primitives here are pure, deterministic functions of their inputs (no state, no I/O) —
//! the `unsafe` FFI calls are sound because every buffer is a fixed-size Rust array whose length
//! matches exactly what the C side reads/writes.

/// Raw FFI declarations, kept in their own module so their names (which mirror the ETSI
/// algorithm names exactly, e.g. `ta21`) don't collide with the safe wrapper functions below.
#[allow(non_snake_case)]
mod ffi {
    use std::os::raw::c_uchar;

    unsafe extern "C" {
        pub fn ta11_ta41(lpKeyK: *const c_uchar, lpChallengeRs: *const c_uchar, lpKsOut: *mut c_uchar);
        pub fn ta21(lpKeyK: *const c_uchar, lpChallengeRs: *const c_uchar, lpKspOut: *mut c_uchar);
        pub fn ta12_ta22(lpKeyKs: *const c_uchar, lpRand: *const c_uchar, lpResOut: *mut c_uchar, lpDckOut: *mut c_uchar);
        pub fn tb4(lpDck1: *const c_uchar, lpDck2: *const c_uchar, lpDckOut: *mut c_uchar);
    }
}

/// The 128-bit TETRA authentication key K, shared between an ITSI and its home SwMI.
pub type AuthKey = [u8; 16];
/// An 80-bit random seed (RS) or random challenge (RAND1/RAND2).
pub type Challenge80 = [u8; 10];
/// A 128-bit session authentication key (KS or KS').
pub type SessionKey = [u8; 16];
/// A 32-bit authentication response (RES1/RES2/XRES1/XRES2).
pub type AuthResponse = [u8; 4];
/// An 80-bit derived cipher key component (DCK1/DCK2) or the combined DCK.
pub type DckComponent = [u8; 10];

/// TA11 (equivalently TA41): derive the session authentication key KS used to authenticate an
/// MS, from the shared secret K and a random seed RS.
/// ETSI EN 300 392-7 clause 4.1.2 / Annex B.
pub fn ta11(k: &AuthKey, rs: &Challenge80) -> SessionKey {
    let mut out = [0u8; 16];
    unsafe {
        ffi::ta11_ta41(k.as_ptr(), rs.as_ptr(), out.as_mut_ptr());
    }
    out
}

/// TA21: derive the session authentication key KS' used to authenticate the infrastructure to
/// an MS, from the shared secret K and a random seed RS.
/// ETSI EN 300 392-7 clause 4.1.3 / Annex B.
pub fn ta21(k: &AuthKey, rs: &Challenge80) -> SessionKey {
    let mut out = [0u8; 16];
    unsafe {
        ffi::ta21(k.as_ptr(), rs.as_ptr(), out.as_mut_ptr());
    }
    out
}

/// TA12 (equivalently TA22): given a session key (KS or KS') and a random challenge
/// (RAND1 or RAND2), compute the authentication response (RES1/XRES1 or RES2/XRES2) and the
/// corresponding derived cipher key component (DCK1 or DCK2).
/// ETSI EN 300 392-7 clause 4.1.2/4.1.3 / Annex B.
pub fn ta12(session_key: &SessionKey, rand: &Challenge80) -> (AuthResponse, DckComponent) {
    let mut res = [0u8; 4];
    let mut dck = [0u8; 10];
    unsafe {
        ffi::ta12_ta22(session_key.as_ptr(), rand.as_ptr(), res.as_mut_ptr(), dck.as_mut_ptr());
    }
    (res, dck)
}

/// Combine DCK1 and DCK2 (one of which is all-zero for one-way authentication) into the final
/// Derived Cipher Key.
/// ETSI EN 300 392-7 clause 4.2.1, Figure 4.7.
pub fn tb4(dck1: &DckComponent, dck2: &DckComponent) -> DckComponent {
    let mut out = [0u8; 10];
    unsafe {
        ffi::tb4(dck1.as_ptr(), dck2.as_ptr(), out.as_mut_ptr());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vectors below are taken verbatim from Midnight Blue's own `tests.c` in
    /// MidnightBlueLabs/TETRA_crypto, and were re-verified in this repo by compiling the
    /// upstream test suite with gcc and running it before this crate was written — all vectors
    /// passed against the vendored source unmodified.
    #[test]
    fn ta11_known_answer_vectors() {
        let cases: [(AuthKey, Challenge80, SessionKey); 4] = [
            (
                [0x77, 0xe7, 0x9f, 0xee, 0x7f, 0xc6, 0x54, 0xdc, 0x65, 0x44, 0x64, 0x4f, 0xdf, 0x47, 0x68, 0x15],
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x9C, 0x84, 0x51, 0xA3, 0x56, 0x95, 0xD3, 0x3C, 0x30, 0x94, 0x37, 0x12, 0x02, 0x48, 0x54, 0x53],
            ),
            (
                [0xc6, 0x2e, 0x22, 0x85, 0x03, 0x40, 0xbc, 0xeb, 0x55, 0x52, 0x22, 0x28, 0x60, 0x17, 0x3d, 0x7e],
                [0x56, 0x5a, 0x72, 0xd6, 0x3c, 0xce, 0xed, 0x0b, 0x6f, 0x30],
                [0x77, 0xBC, 0x47, 0xF6, 0x5C, 0x87, 0xC1, 0xE7, 0x49, 0xB7, 0x4F, 0xDE, 0xA6, 0xB5, 0x46, 0x61],
            ),
            (
                [0x4e, 0xbb, 0x68, 0x9d, 0x87, 0x4a, 0xd6, 0x41, 0x79, 0x05, 0xc0, 0xed, 0xaa, 0x3f, 0x90, 0xec],
                [0x93, 0x5e, 0x49, 0xfc, 0xdc, 0xbb, 0x47, 0x58, 0x19, 0x55],
                [0x48, 0x9C, 0x79, 0xEA, 0x05, 0x2F, 0xDE, 0xFA, 0x90, 0x2A, 0x83, 0x3F, 0x26, 0xCF, 0x12, 0x7C],
            ),
            (
                [0x67, 0xfb, 0x13, 0x4d, 0xd7, 0x9c, 0x7d, 0x77, 0xf5, 0x2a, 0x5d, 0xce, 0xf2, 0x3d, 0xe6, 0xfd],
                [0xb8, 0x24, 0xff, 0xb1, 0x37, 0xa4, 0xef, 0x87, 0xe0, 0x7a],
                [0xB7, 0x14, 0x21, 0xBA, 0x11, 0xCF, 0xD5, 0x4A, 0xD6, 0xC4, 0xD2, 0x57, 0x92, 0x5A, 0x53, 0xB2],
            ),
        ];
        for (k, rs, expected_ks) in cases {
            assert_eq!(ta11(&k, &rs), expected_ks);
        }
    }

    #[test]
    fn ta21_known_answer_vectors() {
        let cases: [(AuthKey, Challenge80, SessionKey); 2] = [
            (
                [0x77, 0xe7, 0x9f, 0xee, 0x7f, 0xc6, 0x54, 0xdc, 0x65, 0x44, 0x64, 0x4f, 0xdf, 0x47, 0x68, 0x15],
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x9C, 0x84, 0x51, 0xA3, 0x56, 0x95, 0xD3, 0x3C, 0x30, 0x94, 0x37, 0x12, 0x02, 0x48, 0x54, 0x53],
            ),
            (
                [0xc6, 0x2e, 0x22, 0x85, 0x03, 0x40, 0xbc, 0xeb, 0x55, 0x52, 0x22, 0x28, 0x60, 0x17, 0x3d, 0x7e],
                [0x56, 0x5a, 0x72, 0xd6, 0x3c, 0xce, 0xed, 0x0b, 0x6f, 0x30],
                [0xFC, 0xFA, 0xF4, 0x55, 0x92, 0xDF, 0xC6, 0x5D, 0x8A, 0x1F, 0x5C, 0x45, 0xDC, 0xA2, 0x93, 0xDA],
            ),
        ];
        for (k, rs, expected_ksp) in cases {
            assert_eq!(ta21(&k, &rs), expected_ksp);
        }
    }

    #[test]
    fn tb4_known_answer_vectors() {
        let cases: [(DckComponent, DckComponent, DckComponent); 2] = [
            (
                [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xAA, 0xBB],
                [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xAA, 0xBB],
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ),
            (
                [0xBD, 0xF8, 0xE8, 0xD4, 0x7C, 0xA2, 0xED, 0xAE, 0x0C, 0xFB],
                [0x56, 0x3B, 0x92, 0xC2, 0xA2, 0x27, 0x5A, 0x0F, 0x61, 0x13],
                [0xEB, 0xC3, 0x7A, 0x16, 0xDE, 0x85, 0xB7, 0xA1, 0x6D, 0xE8],
            ),
        ];
        for (dck1, dck2, expected) in cases {
            assert_eq!(tb4(&dck1, &dck2), expected);
        }
    }

    /// ta12_ta22 has no named vector in the upstream tests.c suite (only its building blocks —
    /// the transform functions and HURDLE_enc_cbc — are individually verified there). This is a
    /// self-consistency check, NOT a known-answer test: it only proves the binding is
    /// deterministic and input-sensitive, not that the output matches a real TETRA network.
    #[test]
    fn ta12_is_deterministic_and_input_sensitive() {
        let ks: SessionKey = [0x11; 16];
        let rand: Challenge80 = [0x22; 10];
        let (res_a, dck_a) = ta12(&ks, &rand);
        let (res_b, dck_b) = ta12(&ks, &rand);
        assert_eq!(res_a, res_b, "ta12 must be deterministic");
        assert_eq!(dck_a, dck_b, "ta12 must be deterministic");

        let rand2: Challenge80 = [0x33; 10];
        let (res_c, _) = ta12(&ks, &rand2);
        assert_ne!(res_a, res_c, "different RAND must give a different RES");
    }
}
