use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Source of a restriction; no automatic administrator or moderation ban exists.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderKind {
    /// An external authority, authenticated by the verifier.
    Legal {
        /// Opaque authority identifier, not raw legal evidence.
        authority: String,
    },
    /// The subject's freshly confirmed permanent termination.
    SelfBan,
}

/// Permanent metadata supplied by the caller and authenticated as one record.
/// A block is always permanent and covers every action: it has no scope, no
/// start and no end, and nothing here can ever release it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// Target community, bound by the signature and storage capability.
    pub community: String,
    /// Caller-assigned stable, community-unique idempotency key.
    pub id: String,
    /// Opaque community pseudonym; never resolved to a real-world identity here.
    pub subject: String,
    /// External reference only; no order document or raw gate evidence.
    pub reference: String,
    /// Who entered the order; the subject itself for a self-ban.
    pub entered_by: String,
    /// Authenticated source of authority.
    pub kind: OrderKind,
}

impl Order {
    /// Stable v1 JSON encoding, domain-separated by kind, for verifier adapters.
    /// This encodes metadata only; qualified-signature formats may bind it through
    /// their own established encoding. It performs no cryptography.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let domain = match self.kind {
            OrderKind::Legal { .. } => "clbs/legal/v1",
            OrderKind::SelfBan => "clbs/self-ban/v1",
        };
        serde_json::to_vec(&(domain, self)).map_err(|_| Error::Invalid("order encoding"))
    }

    /// Validate metadata structure; this does not establish signer authority.
    pub fn validate(&self) -> Result<()> {
        for value in [
            &self.community,
            &self.id,
            &self.subject,
            &self.reference,
            &self.entered_by,
        ] {
            text(value)?;
        }
        match &self.kind {
            OrderKind::Legal { authority } => text(authority)?,
            OrderKind::SelfBan => {
                if self.entered_by != self.subject {
                    return Err(Error::Invalid("self-ban must be self-entered"));
                }
            }
        }
        Ok(())
    }
}

/// Ephemeral caller proof. Deliberately has no Debug or serialization support.
pub struct SignedOrder {
    /// Complete metadata authenticated by the verifier.
    pub order: Order,
    /// Signature/authorization envelope, never stored by clbs.
    pub proof: Vec<u8>,
}

/// Verified metadata. Construction is private; deserialization cannot bypass verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Record(pub(crate) Order);

impl Record {
    /// Restore metadata from a trusted caller-owned store after structural validation.
    /// This does not verify a legal signature or self-ban authorization. Never use
    /// it on member input; new submissions must pass through `Gate` verification.
    pub fn restore_trusted(order: Order) -> Result<Self> {
        order.validate()?;
        Ok(Self(order))
    }

    /// Borrow permanent metadata without exposing a mutable path.
    pub fn order(&self) -> &Order {
        &self.0
    }
}

/// Result of atomically recording metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Append {
    /// A new permanent order was committed.
    Inserted,
    /// Identical metadata already exists; no duplicate was written.
    Unchanged,
}

/// Minimal entry for internal revocation snapshots; no references or entering actors.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// Community to which the entry applies.
    pub community: String,
    /// Stable order ID for snapshot consumers.
    pub order_id: String,
    /// A community pseudonym. Revocation lists are not transparency reports.
    pub subject: String,
}

impl From<Record> for Revocation {
    fn from(record: Record) -> Self {
        let order = record.0;
        Self {
            community: order.community,
            order_id: order.id,
            subject: order.subject,
        }
    }
}

/// A check verdict; errors are separate and must never be treated as green.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    /// No order for this subject.
    Green,
    /// One or more permanent blocks; never released.
    Red(Vec<Revocation>),
}

/// Aggregate counts of orders, never distinct subjects or identifiers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    /// All permanent legal orders.
    pub legal_orders: u64,
    /// All permanent self-bans.
    pub self_bans: u64,
}

pub(crate) fn text(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        Err(Error::Invalid(
            "identifiers must be nonblank, at most 1024 bytes, and contain no controls",
        ))
    } else {
        Ok(())
    }
}

// Diagnostic formatting must not turn metadata or verdicts into an identity log.
impl fmt::Debug for OrderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Legal { .. } => "Legal([redacted])",
            Self::SelfBan => "SelfBan",
        })
    }
}

impl fmt::Debug for Order {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Order([redacted])")
    }
}

impl fmt::Debug for Revocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Revocation([redacted])")
    }
}
