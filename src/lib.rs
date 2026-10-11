//! Community legal veto with caller-owned order metadata and no request history.
//!
//! Every action must call [`Gate::check`]. The service supplies a trusted
//! [`Verifier`] and a community-bound [`Store`]. A block is always permanent and
//! covers every action. Signature evidence is used only during verification and
//! is never passed to storage.
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod memory;
mod model;

use std::{future::Future, time::SystemTime};

pub use memory::MemoryStore;
pub use model::*;

/// A failure never means that an action is permitted.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Invalid input; the static explanation contains no supplied identifiers.
    #[error("invalid input: {0}")]
    Invalid(&'static str),
    /// Signature, signer authority, or actor authorization was refused.
    #[error("authorization refused")]
    Denied,
    /// The order belongs to a different community.
    #[error("community mismatch")]
    CommunityMismatch,
    /// The same order identifier already has different metadata.
    #[error("order identifier conflict")]
    Conflict,
    /// Storage is unavailable or returned invalid data. Do not allow the action.
    #[error("storage operation failed")]
    Storage,
    /// The clock cannot provide a supported Unix timestamp.
    #[error("clock unavailable")]
    Clock,
}

/// Library result, without sensitive backend error strings.
pub type Result<T> = std::result::Result<T, Error>;

/// External authorization boundary. No permissive implementation is provided.
///
/// Implementations must authenticate the complete immutable order, including
/// community, subject, reference, and entering actor. Qualified
/// e-signature validation is delegated here, not implemented by this crate.
pub trait Verifier: Send + Sync {
    /// Validate the legal signature and its authority for this exact order;
    /// also require the entering actor's authenticated root authorization.
    fn verify_legal(&self, order: &SignedOrder) -> impl Future<Output = Result<()>> + Send;

    /// Require fresh passkey confirmation by the subject of this exact permanent
    /// self-ban, with replay protection bound to its order ID and community.
    fn verify_self_ban(&self, order: &SignedOrder) -> impl Future<Output = Result<()>> + Send;
}

/// Trusted time source for hosts. A block itself never depends on time.
pub trait Clock: Send + Sync {
    /// Nonnegative Unix seconds.
    fn now(&self) -> Result<i64>;
}

/// Wall clock for server callers.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<i64> {
        unix_seconds(SystemTime::now())
    }
}

fn unix_seconds(time: SystemTime) -> Result<i64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| Error::Clock)?
        .as_secs()
        .try_into()
        .map_err(|_| Error::Clock)
}

/// Small community-bound persistence contract. Implementations are trusted.
///
/// Append is atomic and idempotent on identical metadata; conflicting IDs must
/// never overwrite records. Reads must be complete or return an error. No
/// method records checks, accepts signature evidence, or deletes orders.
pub trait Store: Send + Sync {
    /// Fixed community selected by the composition root, never by member input.
    fn community(&self) -> &str;
    /// Permanently append a verified record, enforcing its community binding.
    fn append(&self, record: &Record) -> impl Future<Output = Result<Append>> + Send;
    /// Retrieve permanent metadata by exact order ID.
    fn record(&self, id: &str) -> impl Future<Output = Result<Option<Record>>> + Send;
    /// Find one permanent self-ban for the exact subject. Unsupported stores
    /// refuse rather than asserting absence.
    fn self_ban_record(
        &self,
        _subject: &str,
    ) -> impl Future<Output = Result<Option<Record>>> + Send {
        std::future::ready(Err(Error::Storage))
    }
    /// Return all orders for a subject, ordered by ID.
    fn orders(&self, subject: &str) -> impl Future<Output = Result<Vec<Record>>> + Send;
    /// Return every permanent block for a revocation snapshot.
    fn revocations(&self) -> impl Future<Output = Result<Vec<Revocation>>> + Send;
    /// Aggregate orders, not people. No identifiers may appear in the result.
    fn counts(&self) -> impl Future<Output = Result<Counts>> + Send;
}

/// Veto facade. State is derived from immutable permanent orders.
pub struct Gate<S, V> {
    store: S,
    verifier: V,
}

impl<S: Store, V: Verifier> Gate<S, V> {
    /// Bind storage and external verification.
    pub fn new(store: S, verifier: V) -> Self {
        Self { store, verifier }
    }

    /// Validate and permanently record a signed legal order.
    pub async fn record_legal(&self, submission: &SignedOrder) -> Result<Append> {
        self.validate_submission(submission)?;
        if !matches!(submission.order.kind, OrderKind::Legal { .. }) {
            return Err(Error::Invalid("expected a legal order"));
        }
        self.verifier.verify_legal(submission).await?;
        self.store.append(&Record(submission.order.clone())).await
    }

    /// Record a freshly confirmed permanent self-ban of all actions.
    pub async fn self_ban(&self, submission: &SignedOrder) -> Result<Append> {
        self.validate_submission(submission)?;
        if submission.order.kind != OrderKind::SelfBan {
            return Err(Error::Invalid("expected a self-ban"));
        }
        self.verifier.verify_self_ban(submission).await?;
        self.store.append(&Record(submission.order.clone())).await
    }

    /// Check a subject before acting. Unknown subjects are green without a write.
    /// Red carries the permanent blocks, which cover every action.
    pub async fn check(&self, subject: &str) -> Result<State> {
        model::text(subject)?;
        let records = self.store.orders(subject).await?;
        if records.is_empty() {
            Ok(State::Green)
        } else {
            Ok(State::Red(
                records.into_iter().map(Revocation::from).collect(),
            ))
        }
    }

    /// Root-only audit lookup; endpoint authorization belongs to the service.
    pub async fn record(&self, id: &str) -> Result<Option<Record>> {
        model::text(id)?;
        self.store.record(id).await
    }

    /// Read a permanent self-ban receipt.
    /// The service must authenticate the owner before exposing any result.
    /// Absence is not admission, recovery authority or a legal green verdict.
    pub async fn self_ban_record(&self, subject: &str) -> Result<Option<Record>> {
        model::text(subject)?;
        let record = self.store.self_ban_record(subject).await?;
        if let Some(record) = &record {
            let order = record.order();
            order.validate().map_err(|_| Error::Storage)?;
            if order.community != self.store.community()
                || order.subject != subject
                || order.kind != OrderKind::SelfBan
            {
                return Err(Error::Storage);
            }
        }
        Ok(record)
    }

    /// Every permanent block for the caller's signed revocation snapshot.
    pub async fn revocations(&self) -> Result<Vec<Revocation>> {
        self.store.revocations().await
    }

    /// Subject-free order counts. Publication cadence belongs to the service.
    pub async fn counts(&self) -> Result<Counts> {
        self.store.counts().await
    }

    fn validate_submission(&self, submission: &SignedOrder) -> Result<()> {
        submission.order.validate()?;
        if submission.order.community != self.store.community() {
            return Err(Error::CommunityMismatch);
        }
        if submission.proof.is_empty() || submission.proof.len() > 1024 * 1024 {
            return Err(Error::Invalid("proof must contain 1 to 1048576 bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/clock.rs"]
mod clock_tests;
