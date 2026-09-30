use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use crate::{Append, Counts, Error, OrderKind, Record, Result, Revocation, Store, model};

/// Real in-memory store for tests and ephemeral development; clones share data.
/// Construct a separate instance for each community. Restarting loses all orders.
#[derive(Clone)]
pub struct MemoryStore {
    community: String,
    records: Arc<RwLock<BTreeMap<String, Record>>>,
}

impl MemoryStore {
    /// Bind an empty store to a validated community identifier.
    pub fn new(community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        model::text(&community)?;
        Ok(Self {
            community,
            records: Arc::default(),
        })
    }
}

impl Store for MemoryStore {
    fn community(&self) -> &str {
        &self.community
    }

    async fn append(&self, record: &Record) -> Result<Append> {
        if record.0.community != self.community {
            return Err(Error::CommunityMismatch);
        }
        record.0.validate()?;
        let mut records = self.records.write().map_err(|_| Error::Storage)?;
        if let Some(existing) = records.get(&record.0.id) {
            return if existing == record {
                Ok(Append::Unchanged)
            } else {
                Err(Error::Conflict)
            };
        }
        records.insert(record.0.id.clone(), record.clone());
        Ok(Append::Inserted)
    }

    async fn record(&self, id: &str) -> Result<Option<Record>> {
        model::text(id)?;
        Ok(self
            .records
            .read()
            .map_err(|_| Error::Storage)?
            .get(id)
            .cloned())
    }

    async fn active(&self, subject: &str, at: i64) -> Result<Vec<Record>> {
        model::text(subject)?;
        model::timestamp(at)?;
        Ok(self
            .records
            .read()
            .map_err(|_| Error::Storage)?
            .values()
            .filter(|record| record.0.subject == subject && record.0.period.contains(at))
            .cloned()
            .collect())
    }

    async fn revocations(&self, at: i64) -> Result<Vec<Revocation>> {
        model::timestamp(at)?;
        Ok(self
            .records
            .read()
            .map_err(|_| Error::Storage)?
            .values()
            .filter(|record| record.0.period.contains(at))
            .cloned()
            .map(Revocation::from)
            .collect())
    }

    async fn counts(&self, at: i64) -> Result<Counts> {
        model::timestamp(at)?;
        let mut counts = Counts::default();
        for record in self.records.read().map_err(|_| Error::Storage)?.values() {
            let active = u64::from(record.0.period.contains(at));
            match record.0.kind {
                OrderKind::Legal { .. } => {
                    counts.legal_orders += 1;
                    counts.active_legal_orders += active;
                }
                OrderKind::SelfBan => {
                    counts.self_bans += 1;
                    counts.active_self_bans += active;
                }
            }
        }
        Ok(counts)
    }
}
