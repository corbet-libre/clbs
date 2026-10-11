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
    async fn orders(&self, subject: &str) -> clbs::Result<Vec<clbs::Record>> {
        clbs::Store::orders(&self.0, subject).await
    }
    async fn revocations(&self) -> clbs::Result<Vec<clbs::Revocation>> {
        clbs::Store::revocations(&self.0).await
    }
    async fn counts(&self) -> clbs::Result<clbs::Counts> {
        clbs::Store::counts(&self.0).await
    }
}

#[tokio::test]
async fn a_store_without_receipt_lookup_refuses_instead_of_reporting_absence() {
    let gate = Gate::new(
        LegacyStore(MemoryStore::new("community-a").unwrap()),
        TestVerifier::new("community-a"),
    );
    assert!(matches!(
        gate.self_ban_record("alice").await,
        Err(clbs::Error::Storage)
    ));
}

#[tokio::test]
async fn immutable_receipt_is_exact_and_the_block_never_ends() {
    let gate = Gate::new(
        MemoryStore::new("community-a").unwrap(),
        TestVerifier::new("community-a"),
    );
    assert!(gate.self_ban_record("alice").await.unwrap().is_none());
    gate.record_legal(&sign(legal("legal"))).await.unwrap();
    assert!(gate.self_ban_record("alice").await.unwrap().is_none());
    gate.self_ban(&sign(ban("terminal"))).await.unwrap();
    let record = gate.record("terminal").await.unwrap().unwrap();
    assert!(matches!(
        gate.check("alice").await.unwrap(),
        clbs::State::Red(_)
    ));
    assert!(gate.self_ban_record("alice").await.unwrap() == Some(record));
    assert!(gate.self_ban_record("bob").await.unwrap().is_none());
    assert!(gate.self_ban_record("").await.is_err());
}
