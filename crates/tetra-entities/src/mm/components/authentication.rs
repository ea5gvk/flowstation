//! Air-interface authentication (SwMI authenticates the MS, and optionally vice versa), ETSI EN
//! 300 392-7 clause 4.1.2/4.1.3. OTAR and MS-initiated standalone authentication (U-AUTHENTICATION
//! DEMAND, Table A.5 — the MS challenging the SwMI without us asking first) are still not
//! implemented; only the piggybacked case is, where the MS attaches its own challenge (RAND2) to
//! its U-AUTHENTICATION RESPONSE to our demand.
//!
//! Flow implemented here:
//!   1. `begin` — BS picks RAND1 + RS, derives KS = TA11(K, RS), then (XRES1, DCK1) = TA12(KS,
//!      RAND1). Stores the pending session and returns the fields for a D-AUTHENTICATION demand.
//!   2. MS replies with U-AUTHENTICATION response, RES1, and — if it wants mutual authentication
//!      — a mutual flag and its own challenge RAND2.
//!   3. `handle_response` compares RES1 to the stored XRES1.
//!      - On mismatch: the session is dropped, any previously established DCK for that ISSI is
//!        revoked, `Rejected` is returned.
//!      - On match, no mutual challenge: DCK = TB4(DCK1, 0) (one-way), retained per-ISSI,
//!        `Accepted { dck, mutual_res2: None }`.
//!      - On match, WITH a mutual challenge (K and RAND2 supplied by the caller): KS' = TA21(K,
//!        RS) (same RS as the original demand), (RES2, DCK2) = TA12(KS', RAND2), DCK =
//!        TB4(DCK1, DCK2), retained per-ISSI, `Accepted { dck, mutual_res2: Some(RES2) }`. The
//!        caller sends RES2 back in a D-AUTHENTICATION RESULT with mutual_authentication_flag=1
//!        (Table A.4) — R1 (our verdict on the MS) and RES2 (our answer to its RAND2) travel in
//!        the same PDU, so mutual authentication costs only one extra round trip, not two.
//!   4. `collect_expired` is polled periodically (T354) to drop sessions the MS never answered.
//!
//! NOTE: retaining the DCK does not by itself encrypt anything — air-interface encryption is not
//! wired into the MAC layer, so traffic is unaffected regardless of whether a DCK exists here.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tetra_crypto::{AuthKey, AuthResponse, Challenge80, DckComponent};

/// T354, authentication protocol timer (ETSI EN 300 392-7 Annex C.1). The spec leaves the exact
/// value to the operator; this is a conservative default generous enough for a slow/busy MS to
/// answer over the air.
pub const T354_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct AuthSession {
    xres1: AuthResponse,
    dck1: DckComponent,
    demanded_at: Instant,
    /// Kept so `diagnose_mismatch` can re-run the derivation on failure, AND so a mutual
    /// challenge (which is keyed off the same RS as the original demand, per Table A.7's use of
    /// TA21) can be answered without asking the caller to remember it separately.
    rand1: Challenge80,
    rs: Challenge80,
}

/// Outcome of processing a U-AUTHENTICATION response.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// RES1 matched XRES1.
    Accepted {
        /// The derived cipher key: `TB4(DCK1, DCK2)`, with DCK2 = 0 for a one-way exchange.
        dck: DckComponent,
        /// Our answer to the MS's own challenge, if it asked for mutual authentication. `Some`
        /// here means the caller must send this back in a D-AUTHENTICATION RESULT with
        /// mutual_authentication_flag = 1 (Table A.4) — the MS will not consider the SwMI
        /// authenticated until it does.
        mutual_res2: Option<AuthResponse>,
    },
    /// RES1 did not match XRES1.
    Rejected,
    /// No pending session for this ISSI (expired, never started, or a stray/replayed response).
    NoSession,
}

/// Fields needed to build a `DAuthentication { sub_type: Demand, .. }` PDU.
pub struct DemandFields {
    pub rand1: Challenge80,
    pub rs: Challenge80,
}

#[derive(Default)]
pub struct AuthenticationManager {
    sessions: HashMap<u32, AuthSession>,
    /// DCKs of ISSIs that have completed authentication. Populated on a successful
    /// `handle_response`; this is what air-interface encryption would draw from once the AIE
    /// engine is wired into the MAC layer. Replaced wholesale on re-authentication (a new
    /// exchange supersedes the old key) and cleared by `forget`.
    dcks: HashMap<u32, DckComponent>,
}

fn random_80() -> Challenge80 {
    let mut buf = [0u8; 10];
    for b in buf.iter_mut() {
        *b = rand::random_range(0..=255) as u8;
    }
    buf
}

impl AuthenticationManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a one-way authentication exchange for `issi` using key `k`. Overwrites any existing
    /// pending session for the same ISSI (e.g. a retry). Returns the RAND1/RS to put in the
    /// D-AUTHENTICATION demand.
    pub fn begin(&mut self, issi: u32, k: &AuthKey) -> DemandFields {
        let rand1 = random_80();
        let rs = random_80();

        let ks = tetra_crypto::ta11(k, &rs);
        let (xres1, dck1) = tetra_crypto::ta12(&ks, &rand1);

        self.sessions.insert(
            issi,
            AuthSession {
                xres1,
                dck1,
                demanded_at: Instant::now(),
                rand1,
                rs,
            },
        );

        DemandFields { rand1, rs }
    }

    /// Process a U-AUTHENTICATION response's RES1 for `issi`. Consumes the pending session
    /// either way (success or failure): a session is single-use, matching the confirmed 2-pass
    /// protocol in EN 300 392-7 clause 4.1.1.
    ///
    /// `mutual_challenge`, when `Some((k, rand2))`, means the MS attached its own challenge and
    /// wants mutual authentication (Table A.7's mutual_authentication_flag = 1). `k` is needed
    /// again here (not stored in the session) because TA21 uses it directly, unlike the RES1
    /// check which only needs the already-derived XRES1.
    pub fn handle_response(&mut self, issi: u32, res1: AuthResponse, mutual_challenge: Option<(&AuthKey, &Challenge80)>) -> AuthOutcome {
        let Some(session) = self.sessions.remove(&issi) else {
            return AuthOutcome::NoSession;
        };

        if res1 != session.xres1 {
            // A failed exchange must not leave a previously-established DCK in place: the ISSI
            // has just failed to prove it holds K, so any key we still hold for it is suspect.
            self.dcks.remove(&issi);
            return AuthOutcome::Rejected;
        }

        let (dck2, mutual_res2) = match mutual_challenge {
            Some((k, rand2)) => {
                // TA21/TA22: EN 300 392-7 clause 4.1.3. KS' uses the SAME RS as the original
                // demand — the standard does not have the SwMI mint a second random seed for
                // the return leg of a piggybacked mutual exchange.
                let ks_prime = tetra_crypto::ta21(k, &session.rs);
                let (res2, dck2) = tetra_crypto::ta12(&ks_prime, rand2);
                (dck2, Some(res2))
            }
            None => ([0u8; 10], None),
        };
        let dck = tetra_crypto::tb4(&session.dck1, &dck2);
        self.dcks.insert(issi, dck);
        AuthOutcome::Accepted { dck, mutual_res2 }
    }

    /// The DCK established for `issi` by a successful authentication, if any.
    ///
    /// NOTE: nothing consumes this yet — air-interface encryption is not wired into the MAC
    /// layer, so holding a DCK has no effect on traffic. It exists so the key survives the
    /// authentication exchange instead of being discarded.
    pub fn dck_for(&self, issi: u32) -> Option<&DckComponent> {
        self.dcks.get(&issi)
    }

    /// True if `issi` currently holds an established DCK (i.e. it authenticated successfully and
    /// has not since failed or been forgotten).
    pub fn is_authenticated(&self, issi: u32) -> bool {
        self.dcks.contains_key(&issi)
    }

    /// Drop all authentication state for `issi` — both any pending challenge and any established
    /// DCK. Call this when the terminal deregisters or is removed from the registry, so a key
    /// does not outlive the registration it belongs to.
    pub fn forget(&mut self, issi: u32) {
        self.sessions.remove(&issi);
        self.dcks.remove(&issi);
    }

    /// DIAGNOSTIC ONLY. After a RES1 mismatch, re-run the derivation under a handful of
    /// plausible alternative interpretations and report which — if any — reproduces the value
    /// the terminal actually sent.
    ///
    /// This exists to answer one question: is the mismatch caused by how we *encode* the inputs
    /// (byte order of K, RAND1/RS swapped), or by the terminal using a different algorithm
    /// altogether? A hit points at an encoding bug we can fix; no hit anywhere is strong evidence
    /// the terminal is not running the standard TAA1 at all (operators may substitute their own
    /// TA11/TA12), which no amount of key-fiddling will solve.
    ///
    /// Returns a human-readable description of the matching variant, if one matched.
    pub fn diagnose_mismatch(k: &AuthKey, rs: &Challenge80, rand1: &Challenge80, received_res1: AuthResponse) -> Option<String> {
        let mut k_rev = *k;
        k_rev.reverse();
        let mut rs_rev = *rs;
        rs_rev.reverse();
        let mut rand1_rev = *rand1;
        rand1_rev.reverse();

        // Each candidate is (description, K, seed fed to TA11, challenge fed to TA12).
        let candidates: [(&str, AuthKey, Challenge80, Challenge80); 6] = [
            ("K byte-reversed", k_rev, *rs, *rand1),
            ("RAND1 and RS swapped", *k, *rand1, *rs),
            ("K byte-reversed AND RAND1/RS swapped", k_rev, *rand1, *rs),
            ("RS byte-reversed", *k, rs_rev, *rand1),
            ("RAND1 byte-reversed", *k, *rs, rand1_rev),
            ("RS and RAND1 both byte-reversed", *k, rs_rev, rand1_rev),
        ];

        for (desc, cand_k, cand_seed, cand_challenge) in candidates {
            let ks = tetra_crypto::ta11(&cand_k, &cand_seed);
            let (res, _) = tetra_crypto::ta12(&ks, &cand_challenge);
            if res == received_res1 {
                return Some(desc.to_string());
            }
        }
        None
    }

    /// The RAND1/RS of the challenge most recently issued to `issi`, if one is still pending.
    /// Used for diagnostics and to answer a mutual challenge — `handle_response` consumes the
    /// session, so call this BEFORE.
    pub fn pending_challenge(&self, issi: u32) -> Option<(Challenge80, Challenge80)> {
        self.sessions.get(&issi).map(|s| (s.rand1, s.rs))
    }

    /// Drop sessions the MS never answered within T354, returning their ISSIs so the caller can
    /// log / send a reject / retry as it sees fit. Call periodically (e.g. from the entity's
    /// tick).
    pub fn collect_expired(&mut self) -> Vec<u32> {
        let now = Instant::now();
        let expired: Vec<u32> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.duration_since(s.demanded_at) > T354_TIMEOUT)
            .map(|(issi, _)| *issi)
            .collect();
        for issi in &expired {
            self.sessions.remove(issi);
        }
        expired
    }

    /// True if a demand is currently outstanding for this ISSI.
    pub fn has_pending(&self, issi: u32) -> bool {
        self.sessions.contains_key(&issi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_K: AuthKey = [0x77, 0xe7, 0x9f, 0xee, 0x7f, 0xc6, 0x54, 0xdc, 0x65, 0x44, 0x64, 0x4f, 0xdf, 0x47, 0x68, 0x15];

    /// A second, distinct key — used to simulate the MS's own K when testing that mutual
    /// authentication uses it (not the SwMI's) for TA21.
    const TEST_K2: AuthKey = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];

    #[test]
    fn correct_response_is_accepted_and_session_is_consumed() {
        let mut mgr = AuthenticationManager::new();
        let demand = mgr.begin(2260571, &TEST_K);
        assert!(mgr.has_pending(2260571));

        // Recompute what a correct MS would answer with, independently of the manager.
        let ks = tetra_crypto::ta11(&TEST_K, &demand.rs);
        let (expected_res1, _) = tetra_crypto::ta12(&ks, &demand.rand1);

        match mgr.handle_response(2260571, expected_res1, None) {
            AuthOutcome::Accepted { mutual_res2, .. } => assert_eq!(mutual_res2, None, "no mutual challenge was given"),
            other => panic!("expected Accepted, got {other:?}"),
        }
        assert!(!mgr.has_pending(2260571), "session must be single-use");
    }

    /// Drive a full successful one-way exchange for `issi` and return the DCK the manager
    /// settled on.
    fn authenticate_ok(mgr: &mut AuthenticationManager, issi: u32) -> DckComponent {
        let demand = mgr.begin(issi, &TEST_K);
        let ks = tetra_crypto::ta11(&TEST_K, &demand.rs);
        let (res1, _) = tetra_crypto::ta12(&ks, &demand.rand1);
        match mgr.handle_response(issi, res1, None) {
            AuthOutcome::Accepted { dck, .. } => dck,
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn dck_is_retained_after_successful_authentication() {
        let mut mgr = AuthenticationManager::new();
        assert!(mgr.dck_for(2260571).is_none(), "no key before authenticating");
        assert!(!mgr.is_authenticated(2260571));

        let dck = authenticate_ok(&mut mgr, 2260571);

        assert!(mgr.is_authenticated(2260571));
        assert_eq!(mgr.dck_for(2260571), Some(&dck), "stored DCK must match the one returned");
    }

    #[test]
    fn reauthentication_replaces_the_stored_dck() {
        let mut mgr = AuthenticationManager::new();
        let first = authenticate_ok(&mut mgr, 2260571);
        let second = authenticate_ok(&mut mgr, 2260571);

        // RAND1/RS are freshly random each time, so the two DCKs should differ; whatever the
        // values, the stored one must be the newer.
        assert_ne!(first, second, "a new exchange must derive a fresh DCK");
        assert_eq!(mgr.dck_for(2260571), Some(&second), "the newer DCK must win");
    }

    #[test]
    fn failed_reauthentication_revokes_the_existing_dck() {
        let mut mgr = AuthenticationManager::new();
        authenticate_ok(&mut mgr, 2260571);
        assert!(mgr.is_authenticated(2260571));

        // A fresh challenge that the terminal answers wrongly must not leave the old key usable.
        mgr.begin(2260571, &TEST_K);
        assert_eq!(mgr.handle_response(2260571, [0xAA, 0xBB, 0xCC, 0xDD], None), AuthOutcome::Rejected);

        assert!(!mgr.is_authenticated(2260571), "a failed exchange must revoke the previous DCK");
        assert!(mgr.dck_for(2260571).is_none());
    }

    #[test]
    fn forget_clears_both_pending_session_and_dck() {
        let mut mgr = AuthenticationManager::new();
        authenticate_ok(&mut mgr, 2260571);
        mgr.begin(2260571, &TEST_K); // a new challenge outstanding on top of the established key
        assert!(mgr.has_pending(2260571));
        assert!(mgr.is_authenticated(2260571));

        mgr.forget(2260571);

        assert!(!mgr.has_pending(2260571));
        assert!(!mgr.is_authenticated(2260571));
    }

    /// The diagnostic must actually FIND a variant when one applies. Simulate a terminal that
    /// holds the byte-reversed key: compute what it would answer, then check the diagnostic
    /// identifies exactly that.
    #[test]
    fn diagnostic_identifies_a_byte_reversed_key() {
        let rs = [0x11u8; 10];
        let rand1 = [0x22u8; 10];

        let mut k_rev = TEST_K;
        k_rev.reverse();
        let ks = tetra_crypto::ta11(&k_rev, &rs);
        let (terminal_res1, _) = tetra_crypto::ta12(&ks, &rand1);

        let found = AuthenticationManager::diagnose_mismatch(&TEST_K, &rs, &rand1, terminal_res1);
        assert_eq!(found.as_deref(), Some("K byte-reversed"));
    }

    /// And it must find the swap case too.
    #[test]
    fn diagnostic_identifies_swapped_rand1_rs() {
        let rs = [0x33u8; 10];
        let rand1 = [0x44u8; 10];

        // A terminal that fed RAND1 where we feed RS, and vice versa.
        let ks = tetra_crypto::ta11(&TEST_K, &rand1);
        let (terminal_res1, _) = tetra_crypto::ta12(&ks, &rs);

        let found = AuthenticationManager::diagnose_mismatch(&TEST_K, &rs, &rand1, terminal_res1);
        assert_eq!(found.as_deref(), Some("RAND1 and RS swapped"));
    }

    /// A genuinely different algorithm must report NO match, so the operator is not sent chasing
    /// an encoding bug that isn't there.
    #[test]
    fn diagnostic_reports_no_match_for_an_unrelated_response() {
        let rs = [0x55u8; 10];
        let rand1 = [0x66u8; 10];
        let bogus = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(AuthenticationManager::diagnose_mismatch(&TEST_K, &rs, &rand1, bogus), None);
    }

    #[test]
    fn dcks_are_tracked_per_issi() {
        let mut mgr = AuthenticationManager::new();
        let a = authenticate_ok(&mut mgr, 1001);
        let b = authenticate_ok(&mut mgr, 1002);

        assert_eq!(mgr.dck_for(1001), Some(&a));
        assert_eq!(mgr.dck_for(1002), Some(&b));

        mgr.forget(1001);
        assert!(!mgr.is_authenticated(1001));
        assert!(mgr.is_authenticated(1002), "forgetting one ISSI must not affect another");
    }

    #[test]
    fn wrong_response_is_rejected() {
        let mut mgr = AuthenticationManager::new();
        mgr.begin(2260571, &TEST_K);
        let wrong = [0xAA, 0xBB, 0xCC, 0xDD];
        assert_eq!(mgr.handle_response(2260571, wrong, None), AuthOutcome::Rejected);
        assert!(!mgr.has_pending(2260571));
    }

    #[test]
    fn response_with_no_pending_session_is_no_session() {
        let mut mgr = AuthenticationManager::new();
        assert_eq!(mgr.handle_response(9999, [0, 0, 0, 0], None), AuthOutcome::NoSession);
    }

    // --- Mutual authentication ---

    #[test]
    fn mutual_challenge_yields_res2_and_a_dck_that_differs_from_one_way() {
        let mut mgr = AuthenticationManager::new();
        let demand = mgr.begin(2260571, &TEST_K);
        let ks = tetra_crypto::ta11(&TEST_K, &demand.rs);
        let (res1, _) = tetra_crypto::ta12(&ks, &demand.rand1);

        let rand2 = [0x99u8; 10];
        // Independently compute what the SwMI's answer SHOULD be, using the real TA21/TA12.
        let ks_prime = tetra_crypto::ta21(&TEST_K, &demand.rs);
        let (expected_res2, expected_dck2) = tetra_crypto::ta12(&ks_prime, &rand2);

        let outcome = mgr.handle_response(2260571, res1, Some((&TEST_K, &rand2)));
        let AuthOutcome::Accepted { dck, mutual_res2 } = outcome else {
            panic!("expected Accepted, got {outcome:?}");
        };
        assert_eq!(mutual_res2, Some(expected_res2), "RES2 must match an independent TA21+TA12 computation");

        let expected_dck1 = {
            // Same DCK1 the manager derived internally in `begin` — recompute it the same way.
            let (_, dck1) = tetra_crypto::ta12(&ks, &demand.rand1);
            dck1
        };
        assert_eq!(dck, tetra_crypto::tb4(&expected_dck1, &expected_dck2), "final DCK must combine DCK1 and DCK2");

        // And it must differ from what a one-way exchange (DCK2 = 0) would have produced.
        let one_way_dck = tetra_crypto::tb4(&expected_dck1, &[0u8; 10]);
        assert_ne!(dck, one_way_dck, "a mutual exchange's DCK must differ from a one-way exchange's");
    }

    #[test]
    fn mutual_uses_the_same_rs_as_the_original_demand_not_a_fresh_one() {
        let mut mgr = AuthenticationManager::new();
        let demand = mgr.begin(2260571, &TEST_K);
        let ks = tetra_crypto::ta11(&TEST_K, &demand.rs);
        let (res1, _) = tetra_crypto::ta12(&ks, &demand.rand1);

        let rand2 = [0x42u8; 10];
        let outcome = mgr.handle_response(2260571, res1, Some((&TEST_K, &rand2)));
        let AuthOutcome::Accepted { mutual_res2: Some(res2), .. } = outcome else {
            panic!("expected a mutual RES2");
        };

        // If the manager used the WRONG rs (e.g. a fresh random one), this independently
        // computed RES2 — using the actual demand.rs — would not match.
        let ks_prime = tetra_crypto::ta21(&TEST_K, &demand.rs);
        let (expected_res2, _) = tetra_crypto::ta12(&ks_prime, &rand2);
        assert_eq!(res2, expected_res2);
    }

    #[test]
    fn wrong_res1_is_still_rejected_even_with_a_mutual_challenge_attached() {
        let mut mgr = AuthenticationManager::new();
        mgr.begin(2260571, &TEST_K);
        let wrong_res1 = [0, 0, 0, 0];
        let rand2 = [0x77u8; 10];
        assert_eq!(mgr.handle_response(2260571, wrong_res1, Some((&TEST_K, &rand2))), AuthOutcome::Rejected);
    }

    /// Guards that TA21 actually uses the K it is given: two managers with an IDENTICAL pending
    /// session (constructed directly, since `begin` would randomize RAND1/RS differently each
    /// call) answer the mutual step with a different key each, and must produce different RES2s.
    #[test]
    fn mutual_response_depends_on_the_key_supplied() {
        let rand1 = [0x11u8; 10];
        let rs = [0x22u8; 10];
        let ks = tetra_crypto::ta11(&TEST_K, &rs);
        let (res1, dck1) = tetra_crypto::ta12(&ks, &rand1);
        let rand2 = [0x33u8; 10];

        let make_mgr = || {
            let mut mgr = AuthenticationManager::new();
            mgr.sessions.insert(
                2260571,
                AuthSession {
                    xres1: res1,
                    dck1,
                    demanded_at: Instant::now(),
                    rand1,
                    rs,
                },
            );
            mgr
        };
        let mut mgr_a = make_mgr();
        let mut mgr_b = make_mgr();

        let outcome_a = mgr_a.handle_response(2260571, res1, Some((&TEST_K, &rand2)));
        let outcome_b = mgr_b.handle_response(2260571, res1, Some((&TEST_K2, &rand2)));

        let (AuthOutcome::Accepted { mutual_res2: Some(res2_a), .. }, AuthOutcome::Accepted { mutual_res2: Some(res2_b), .. }) = (outcome_a, outcome_b)
        else {
            panic!("both should accept RES1 (unaffected by the mutual key)");
        };
        assert_ne!(res2_a, res2_b, "a different K must produce a different RES2");
    }
}
