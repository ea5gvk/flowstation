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
//!      `Authenticated` and the derived DCK (`TB4(DCK1, 0)` for one-way) is returned to the
//!      caller. On mismatch, the session is dropped and `Rejected` is returned.
//!   4. `collect_expired` is polled periodically (T354) to drop sessions the MS never answered.

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
            AuthOutcome::Accepted(dck)
        } else {
            AuthOutcome::Rejected
        }
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
