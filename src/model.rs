use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Exact action scope. No wildcard, prefix matching, or implicit hierarchy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// Every action in this community.
    All,
    /// A nonempty set of exact, case-sensitive action identifiers.
    Actions(BTreeSet<String>),
}

impl Scope {
    /// Whether this scope covers the given exact action.
    pub fn covers(&self, action: &str) -> bool {
        match self {
            Self::All => true,
            Self::Actions(actions) => actions.contains(action),
        }
    }
}

/// Half-open validity interval `[starts_at, ends_at)`, in Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Period {
    /// Inclusive start; zero is valid.
    pub starts_at: i64,
    /// Exclusive end; `None` means permanent, without a sentinel timestamp.
    pub ends_at: Option<i64>,
}

impl Period {
    /// Determine activity without arithmetic or overflow at timestamp boundaries.
    pub fn contains(&self, at: i64) -> bool {
        self.starts_at <= at && self.ends_at.is_none_or(|end| at < end)
    }
}

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
    /// Actions covered by the order, applied literally.
    pub scope: Scope,
    /// Exact ordered period; expiration never deletes the record.
    pub period: Period,
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

    pub(crate) fn validate(&self) -> Result<()> {
        for value in [
            &self.community,
            &self.id,
            &self.subject,
            &self.reference,
            &self.entered_by,
        ] {
            text(value)?;
        }
        timestamp(self.period.starts_at)?;
        if self
            .period
            .ends_at
            .is_some_and(|end| end <= self.period.starts_at)
        {
            return Err(Error::Invalid("end must be after start"));
        }
        if let Scope::Actions(actions) = &self.scope {
            if actions.is_empty() || actions.len() > 256 {
                return Err(Error::Invalid("scope must contain 1 to 256 actions"));
            }
            for action in actions {
                text(action)?;
            }
        }
        match &self.kind {
            OrderKind::Legal { authority } => text(authority)?,
            OrderKind::SelfBan => {
                if self.scope != Scope::All
                    || self.period.ends_at.is_some()
                    || self.entered_by != self.subject
                {
                    return Err(Error::Invalid(
                        "self-ban must be permanent, all actions, and self-entered",
                    ));
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
    /// Preserve this exact action scope when enforcing the snapshot.
    pub scope: Scope,
    /// Consumers must also enforce this interval, even after publication.
    pub period: Period,
}

impl From<Record> for Revocation {
    fn from(record: Record) -> Self {
        let order = record.0;
        Self {
            community: order.community,
            order_id: order.id,
            subject: order.subject,
            scope: order.scope,
            period: order.period,
        }
    }
}

/// A check verdict; errors are separate and must never be treated as green.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    /// No applicable active order.
    Green,
    /// One or more active restrictions; scopes can overlap.
    Red(Vec<Revocation>),
}

/// Aggregate counts of orders, never distinct subjects or identifiers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    /// All legal orders, including future and expired ones.
    pub legal_orders: u64,
    /// All permanent self-bans.
    pub self_bans: u64,
    /// Legal orders active at the check time.
    pub active_legal_orders: u64,
    /// Self-bans active at the check time.
    pub active_self_bans: u64,
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

pub(crate) fn timestamp(at: i64) -> Result<()> {
    if at < 0 {
        Err(Error::Invalid("timestamp must be nonnegative"))
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
