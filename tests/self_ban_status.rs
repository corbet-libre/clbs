mod common;
use clbs::{Gate, MemoryStore};
use common::*;

struct LegacyStore(MemoryStore);
impl clbs::Store for LegacyStore {
    fn community(&self) -> &str {
        clbs::Store::community(&self.0)
    }
    async fn append(&self, r: &clbs::Record) -> clbs::Result<clbs::Append> {
        clbs::Store::append(&self.0, r).await
    }
    async fn record(&self, id: &str) -> clbs::Result<Option<clbs::Record>> {
        clbs::Store::record(&self.0, id).await
    }
    async fn active(&self, subject: &str, at: i64) -> clbs::Result<Vec<clbs::Record>> {
        clbs::Store::active(&self.0, subject, at).await
    }
    async fn revocations(&self, at: i64) -> clbs::Result<Vec<clbs::Revocation>> {
        clbs::Store::revocations(&self.0, at).await
    }
    async fn counts(&self, at: i64) -> clbs::Result<clbs::Counts> {
        clbs::Store::counts(&self.0, at).await
    }
}

#[tokio::test]
async fn a_store_without_receipt_lookup_refuses_instead_of_reporting_absence() {
    let gate = Gate::new(
        LegacyStore(MemoryStore::new("community-a").unwrap()),
        TestVerifier::new("community-a"),
        TestClock::new(150),
    );
    assert!(matches!(
        gate.self_ban_record("alice").await,
        Err(clbs::Error::Storage)
    ));
}

#[tokio::test]
async fn immutable_receipt_is_exact_and_survives_wall_clock_rollback() {
    let clock = TestClock::new(150);
    let gate = Gate::new(
        MemoryStore::new("community-a").unwrap(),
        TestVerifier::new("community-a"),
        clock.clone(),
    );
    assert!(gate.self_ban_record("alice").await.unwrap().is_none());
    gate.record_legal(&sign(legal("legal"))).await.unwrap();
    assert!(gate.self_ban_record("alice").await.unwrap().is_none());
    gate.self_ban(&sign(ban("terminal"))).await.unwrap();
    let record = gate.record("terminal").await.unwrap().unwrap();
    clock.set(99);
    assert!(matches!(
        gate.check("alice").await.unwrap(),
        clbs::State::Green
    ));
    assert!(gate.self_ban_record("alice").await.unwrap() == Some(record));
    assert!(gate.self_ban_record("bob").await.unwrap().is_none());
    assert!(gate.self_ban_record("").await.is_err());
}
