//! One-way air-interface authentication (SwMI authenticates the MS), ETSI EN 300 392-7 clause
//! 4.1.2. This is deliberately the simplest of the four cases described there: no mutual
//! authentication, no OTAR, no migration handling. Mutual authentication (MS also challenging
//! the SwMI) can be added later by extending `AuthSession` with the MS's RAND2/response and a
//! `DAuthentication { sub_type: Response, .. }` reply.
//!
//! Flow implemented here:
//!   1. `begin` â€” BS picks RAND1 + RS, derives KS = TA11(K, RS), then (XRES1, DCK1) = TA12(KS,
//!      RAND1). Stores the pending session and returns the fields for a D-AUTHENTICATION demand.
//!   2. MS replies with U-AUTHENTICATION response, RES1.
//!   3. `handle_response` compares RES1 to the stored XRES1. On match, the session becomes
//!      `Authenticated`, the derived DCK (`TB4(DCK1, 0)` for one-way) is returned to the caller
//!      AND retained per-ISSI (see `dck_for`). On mismatch, the session is dropped, any
//!      previously established DCK for that ISSI is revoked, and `Rejected` is returned.
//!   4. `collect_expired` is polled periodically (T354) to drop sessions the MS never answered.
//!
//! NOTE: retaining the DCK does not by itself encrypt anything — air-interface encryption is not
//! wired into the MAC layer, so traffic is unaffected regardless of whether a DCK exists here.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tetra_crypto::{AuthResponse, Challenge80, DckComponent};

/// T354, authentication protocol timer (ETSI EN 300 392-7 Annex C.1). The spec leaves the exact
/// value to the operator; this is a conservative default generous enough for a slow/busy MS to
/// answer over the air.
pub const T354_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct AuthSession {
    xres1: AuthResponse,
    dck1: DckComponent,
    demanded_at: Instant,
}

/// Outcome of processing a U-AUTHENTICATION response.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthOutcome {
    /// RES1 matched XRES1. Carries the derived cipher key (DCK1 combined with a zero DCK2, since
    /// this is one-way authentication â€” see EN 300 392-7 clause 4.2.1).
    Accepted(DckComponent),
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
    pub fn begin(&mut self, issi: u32, k: &[u8; 16]) -> DemandFields {
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
            },
        );

        DemandFields { rand1, rs }
    }

    /// Process a U-AUTHENTICATION response's RES1 for `issi`. Consumes the pending session
    /// either way (success or failure): a session is single-use, matching the confirmed 2-pass
    /// protocol in EN 300 392-7 clause 4.1.1.
    pub fn handle_response(&mut self, issi: u32, res1: AuthResponse) -> AuthOutcome {
        let Some(session) = self.sessions.remove(&issi) else {
            return AuthOutcome::NoSession;
        };

        if res1 == session.xres1 {
            // One-way authentication: DCK2 = 0 (EN 300 392-7 clause 4.2.1).
            let dck = tetra_crypto::tb4(&session.dck1, &[0u8; 10]);
            self.dcks.insert(issi, dck);
            AuthOutcome::Accepted(dck)
        } else {
            // A failed exchange must not leave a previously-established DCK in place: the ISSI
            // has just failed to prove it holds K, so any key we still hold for it is suspect.
            self.dcks.remove(&issi);
            AuthOutcome::Rejected
        }
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

    const TEST_K: [u8; 16] = [
        0x77, 0xe7, 0x9f, 0xee, 0x7f, 0xc6, 0x54, 0xdc, 0x65, 0x44, 0x64, 0x4f, 0xdf, 0x47, 0x68, 0x15,
    ];

    #[test]
    fn correct_response_is_accepted_and_session_is_consumed() {
        let mut mgr = AuthenticationManager::new();
        let demand = mgr.begin(2260571, &TEST_K);
        assert!(mgr.has_pending(2260571));

        // Recompute what a correct MS would answer with, independently of the manager.
        let ks = tetra_crypto::ta11(&TEST_K, &demand.rs);
        let (expected_res1, _) = tetra_crypto::ta12(&ks, &demand.rand1);

        match mgr.handle_response(2260571, expected_res1) {
            AuthOutcome::Accepted(_dck) => {}
            other => panic!("expected Accepted, got {other:?}"),
        }
        assert!(!mgr.has_pending(2260571), "session must be single-use");
    }

    /// Drive a full successful exchange for `issi` and return the DCK the manager settled on.
    fn authenticate_ok(mgr: &mut AuthenticationManager, issi: u32) -> DckComponent {
        let demand = mgr.begin(issi, &TEST_K);
        let ks = tetra_crypto::ta11(&TEST_K, &demand.rs);
        let (res1, _) = tetra_crypto::ta12(&ks, &demand.rand1);
        match mgr.handle_response(issi, res1) {
            AuthOutcome::Accepted(dck) => dck,
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
        assert_eq!(mgr.handle_response(2260571, [0xAA, 0xBB, 0xCC, 0xDD]), AuthOutcome::Rejected);

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
        assert_eq!(mgr.handle_response(2260571, wrong), AuthOutcome::Rejected);
        assert!(!mgr.has_pending(2260571));
    }

    #[test]
    fn response_with_no_pending_session_is_no_session() {
        let mut mgr = AuthenticationManager::new();
        assert_eq!(mgr.handle_response(9999, [0, 0, 0, 0]), AuthOutcome::NoSession);
    }
}
