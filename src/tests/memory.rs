use super::*;
use crate::Order;

fn record() -> Record {
    Record(Order {
        community: "community-a".into(),
        id: "order-a".into(),
        subject: "subject-a".into(),
        reference: "reference-a".into(),
        entered_by: "root-a".into(),
        kind: OrderKind::Legal {
            authority: "court-a".into(),
        },
    })
}

#[tokio::test]
async fn poisoned_store_refuses_every_read_and_write() {
    let store = MemoryStore::new("community-a").unwrap();
    store.append(&record()).await.unwrap();
    let records = store.records.clone();
    let result = std::thread::spawn(move || {
        let _guard = records.write().unwrap();
        panic!("synthetic writer failure");
    })
    .join();
    assert!(result.is_err());
    assert_eq!(store.append(&record()).await, Err(Error::Storage));
    assert_eq!(store.record("order-a").await, Err(Error::Storage));
    assert_eq!(store.orders("subject-a").await, Err(Error::Storage));
    assert_eq!(store.revocations().await, Err(Error::Storage));
    assert_eq!(store.counts().await, Err(Error::Storage));
}

#[tokio::test]
async fn verified_record_cannot_cross_the_storage_community() {
    let store = MemoryStore::new("community-b").unwrap();
    assert_eq!(store.append(&record()).await, Err(Error::CommunityMismatch));
    assert_eq!(store.record("order-a").await.unwrap(), None);
    assert_eq!(store.counts().await.unwrap(), Counts::default());
}
