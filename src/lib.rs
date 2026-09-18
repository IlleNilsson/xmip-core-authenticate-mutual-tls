#![forbid(unsafe_code)]

//! Authenticate by mutual-tls: the client certificate the TLS handshake
//! proved, bound to the connection.
//!
//! A `mutual-tls` handshake is proven at the transport: the TLS server
//! requested the client certificate, verified its chain to the anchors it
//! was configured with, and only then read a byte of content. This gate's job
//! is to record what the transport proved, not to redo the cryptography
//! (ADR-0033). The first gate presents the subject with the
//! `mutual-tls.handshake` proof the transport promoted — `verified`, and
//! nothing else counts — and this gate answers Proven for it, refused where
//! the proof is missing or says anything else, and refused where the node
//! narrows which issuers it takes and the reported issuer is not one.

use authenticate::x509::Name;
use authenticate::{AuthenticateError, Authenticator, Presented};
use context::Verified;
use xcore::{Mechanism, mechanism};

/// The proof the identify sibling attaches the transport's word under.
pub const HANDSHAKE: &str = "mutual-tls.handshake";

/// The word the transport promotes when its handshake verified the chain.
pub const VERIFIED: &str = "verified";

/// The evidence the transport reports the issuer's name under.
pub const ISSUER: &str = "tls.peer.issuer";

/// The mutual-tls authenticator: which issuers the node takes, if it narrows.
#[derive(Default)]
pub struct Verifier {
    issuers: Vec<Name>,
}

impl Verifier {
    /// Takes any client certificate the handshake proved.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take only certificates this issuer signed; call again for another.
    #[must_use]
    pub fn from_issuer(mut self, issuer: &str) -> Self {
        self.issuers.push(Name::parse(issuer));
        self
    }
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::mutual_tls()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != self.mechanism().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies mutual-tls"
            )));
        }
        let handshake = presented.proof(HANDSHAKE).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no {HANDSHAKE} proof was presented: the transport did not say it verified the peer"
            ))
        })?;
        if handshake.trim() != VERIFIED {
            return Err(AuthenticateError::new(format!(
                "the transport's word on the handshake is '{}', not '{VERIFIED}'",
                handshake.trim()
            )));
        }

        if !self.issuers.is_empty() {
            let issuer = presented
                .evidence
                .iter()
                .find(|(evidence, _)| evidence == ISSUER)
                .map(|(_, issuer)| Name::parse(issuer))
                .ok_or_else(|| {
                    AuthenticateError::new(
                        "the node takes named issuers only and the transport reported none",
                    )
                })?;

            if !self.issuers.contains(&issuer) {
                return Err(AuthenticateError::new(format!(
                    "the node does not take certificates issued by '{issuer}'"
                )));
            }
        }

        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presented(handshake: Option<&str>) -> Presented {
        let claim = Presented::passed(mechanism::mutual_tls(), "CN=partner-x.example,O=Partner X")
            .with_evidence(ISSUER, "CN=Partner CA, O=Partner X");

        match handshake {
            Some(word) => claim.with_proof(HANDSHAKE, word),
            None => claim,
        }
    }

    #[test]
    fn what_the_handshake_verified_is_proven() {
        let verified = Verifier::new()
            .verify(&presented(Some("verified")))
            .expect("proven");
        assert_eq!(verified, Verified::Proven);
    }

    #[test]
    fn a_claim_the_transport_did_not_vouch_for_is_refused_saying_so() {
        let failure = Verifier::new()
            .verify(&presented(None))
            .expect_err("no proof");
        assert!(failure.message.contains("did not say"), "{failure}");

        let failure = Verifier::new()
            .verify(&presented(Some("requested")))
            .expect_err("not verified");
        assert!(failure.message.contains("'requested'"), "{failure}");
    }

    #[test]
    fn a_node_that_names_its_issuers_takes_those_and_refuses_the_rest() {
        let taking = Verifier::new().from_issuer("O=Partner X,CN=Partner CA");
        taking
            .verify(&presented(Some("verified")))
            .expect("the named issuer, in another order");

        let failure = Verifier::new()
            .from_issuer("CN=Somebody Else")
            .verify(&presented(Some("verified")))
            .expect_err("another issuer");
        assert!(failure.message.contains("does not take"), "{failure}");

        let unreported = Presented::passed(mechanism::mutual_tls(), "CN=partner-x.example")
            .with_proof(HANDSHAKE, "verified");
        let failure = taking.verify(&unreported).expect_err("no issuer reported");
        assert!(failure.message.contains("reported none"), "{failure}");
    }

    #[test]
    fn another_mechanisms_claim_is_refused_by_name() {
        let claim = Presented::passed(mechanism::certificate(), "CN=partner-x.example");

        let failure = Verifier::new().verify(&claim).expect_err("not ours");
        assert!(failure.message.contains("certificate"), "{failure}");
    }
}
