// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A framework for authenticated, measured runtime policies.
//!
//! A *measured policy* is configuration supplied at runtime by an untrusted
//! source (typically the host) that must not be trusted until it has been
//! authenticated, and whose identity is measured into the guest's attestation so
//! a relying party can require a known-good policy.
//!
//! This crate provides the domain-agnostic machinery — verification, the digest
//! that binds a policy into attestation, and the load orchestration — while each
//! consumer supplies its own schema and capability ceiling by implementing
//! [`MeasuredPolicy`]. Device admission in the VPCI relay is the first consumer;
//! others (network relay rules, diagnostic surface, ...) plug in the same way.

#![forbid(unsafe_code)]

use std::error::Error;

/// Length in bytes of a policy measurement digest (SHA-384).
pub const DIGEST_LEN: usize = 48;

/// A domain-specific policy that plugs into the measured-policy framework.
///
/// The framework authenticates and measures the raw bytes; the implementor owns
/// the schema ([`parse`](Self::parse)) and the compiled-in capability ceiling
/// ([`validate`](Self::validate)). Both operate on untrusted input and must
/// never panic.
pub trait MeasuredPolicy: Sized {
    /// Stable identifier for this policy domain. Namespaces the artifact and its
    /// measurement so distinct domains cannot be confused.
    const DOMAIN: &'static str;

    /// The error returned when parsing or validation fails.
    type Error: Error + Send + Sync + 'static;

    /// Parses a policy from authenticated bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Rejects any policy that falls outside this domain's compiled-in
    /// capability ceiling. A policy may narrow the ceiling but never widen it.
    fn validate(&self) -> Result<(), Self::Error>;
}

/// Authenticates a policy blob before it is trusted.
///
/// This is the seam where the platform's root of trust is enforced: a measured
/// digest, or a signature chained to a trusted authority. An implementation
/// returns the trusted payload on success.
pub trait PolicyVerifier {
    /// Verifies `blob` and returns the authenticated payload.
    fn verify<'a>(&self, blob: &'a [u8]) -> Result<&'a [u8], VerificationError>;
}

/// The policy blob failed authenticity verification.
#[derive(Debug, thiserror::Error)]
#[error("policy failed verification")]
pub struct VerificationError;

/// An error returned by [`load`].
#[derive(Debug, thiserror::Error)]
pub enum LoadError<E> {
    /// The blob was not authentic.
    #[error(transparent)]
    Verification(#[from] VerificationError),
    /// The authenticated blob was malformed or outside the capability ceiling.
    #[error(transparent)]
    Policy(E),
}

/// Computes the measurement digest of a policy payload.
///
/// This is the value bound into the guest's attestation (extended into a runtime
/// measurement register) so a relying party can require a specific policy.
pub fn measure(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    use sha2::Digest;
    let mut hasher = sha2::Sha384::new();
    hasher.update(bytes);
    let mut digest = [0; DIGEST_LEN];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

/// Authenticates, parses, and validates a policy in one step.
///
/// Any failure yields a [`LoadError`] and no policy, so a caller that gets `Err`
/// admits nothing.
pub fn load<P: MeasuredPolicy>(
    verifier: &dyn PolicyVerifier,
    blob: &[u8],
) -> Result<P, LoadError<P::Error>> {
    let trusted = verifier.verify(blob)?;
    let policy = P::parse(trusted).map_err(LoadError::Policy)?;
    policy.validate().map_err(LoadError::Policy)?;
    Ok(policy)
}

/// A [`PolicyVerifier`] that trusts a policy whose measurement matches an
/// expected digest.
///
/// This models the *measured* trust path: `expected` comes from the platform's
/// attested measured config, not from a secret in the paravisor, so the
/// untrusted host cannot substitute a different policy.
pub struct MeasuredPolicyVerifier {
    expected: [u8; DIGEST_LEN],
}

impl MeasuredPolicyVerifier {
    /// Creates a verifier that trusts exactly the policy with this digest.
    pub fn new(expected: [u8; DIGEST_LEN]) -> Self {
        Self { expected }
    }
}

impl PolicyVerifier for MeasuredPolicyVerifier {
    fn verify<'a>(&self, blob: &'a [u8]) -> Result<&'a [u8], VerificationError> {
        if measure(blob) == self.expected {
            Ok(blob)
        } else {
            Err(VerificationError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal domain: payload must start with "ok" (schema) and be at most 8
    // bytes (ceiling).
    #[derive(Debug)]
    struct TestPolicy(Vec<u8>);

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error("malformed")]
        Malformed,
        #[error("exceeds ceiling")]
        ExceedsCeiling,
    }

    impl MeasuredPolicy for TestPolicy {
        const DOMAIN: &'static str = "test";
        type Error = TestError;

        fn parse(bytes: &[u8]) -> Result<Self, TestError> {
            if bytes.starts_with(b"ok") {
                Ok(TestPolicy(bytes.to_vec()))
            } else {
                Err(TestError::Malformed)
            }
        }

        fn validate(&self) -> Result<(), TestError> {
            if self.0.len() <= 8 {
                Ok(())
            } else {
                Err(TestError::ExceedsCeiling)
            }
        }
    }

    #[test]
    fn load_ok() {
        let blob = b"ok-data";
        let verifier = MeasuredPolicyVerifier::new(measure(blob));
        let policy: TestPolicy = load(&verifier, blob).unwrap();
        assert_eq!(policy.0, blob);
    }

    #[test]
    fn rejects_tampered_blob() {
        let blob = b"ok-data";
        let verifier = MeasuredPolicyVerifier::new(measure(blob));
        let err = load::<TestPolicy>(&verifier, b"ok-diff").unwrap_err();
        assert!(matches!(err, LoadError::Verification(_)));
    }

    #[test]
    fn surfaces_parse_error() {
        let blob = b"bad";
        let verifier = MeasuredPolicyVerifier::new(measure(blob));
        let err = load::<TestPolicy>(&verifier, blob).unwrap_err();
        assert!(matches!(err, LoadError::Policy(TestError::Malformed)));
    }

    #[test]
    fn surfaces_ceiling_error() {
        let blob = b"ok-too-long-to-pass";
        let verifier = MeasuredPolicyVerifier::new(measure(blob));
        let err = load::<TestPolicy>(&verifier, blob).unwrap_err();
        assert!(matches!(err, LoadError::Policy(TestError::ExceedsCeiling)));
    }

    #[test]
    fn measure_is_stable_and_sized() {
        assert_eq!(measure(b"abc"), measure(b"abc"));
        assert_ne!(measure(b"abc"), measure(b"abd"));
        assert_eq!(measure(b"abc").len(), DIGEST_LEN);
    }
}
