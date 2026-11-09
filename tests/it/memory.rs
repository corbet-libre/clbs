//! RAM store isolation, concurrent retry and clock contracts.
use crate::common::{TestVerifier, legal, sign};
use clbs::{Append, Counts, Error, Gate, MemoryStore, State, Store};

async fn isolation<S: Store + Clone>(first: S, second: S) {
    let a = Gate::new(first.clone(), TestVerifier::new("community-a"));
    let b = Gate::new(second.clone(), TestVerifier::new("community-b"));
    a.record_legal(&sign(legal("shared-id"))).await.unwrap();
    assert_eq!(b.check("alice").await.unwrap(), State::Green);
    assert_eq!(b.record("shared-id").await.unwrap(), None);
    assert!(b.revocations().await.unwrap().is_empty());
    assert_eq!(b.counts().await.unwrap(), Counts::default());
    let record = a.record("shared-id").await.unwrap().unwrap();
    assert_eq!(second.append(&record).await, Err(Error::CommunityMismatch));
    assert_eq!(
        b.record_legal(&sign(legal("wrong"))).await,
        Err(Error::CommunityMismatch)
    );
    let mut other = legal("shared-id");
    other.community = "community-b".into();
    other.subject = "bob".into();
    b.record_legal(&sign(other)).await.unwrap();
    assert_eq!(a.check("bob").await.unwrap(), State::Green);
    assert_eq!(a.counts().await.unwrap().legal_orders, 1);
    assert_eq!(b.counts().await.unwrap().legal_orders, 1);
    assert_eq!(a.revocations().await.unwrap()[0].subject, "alice");
    assert_eq!(b.revocations().await.unwrap()[0].subject, "bob");
}

#[tokio::test]
async fn memory_communities_and_clones_are_isolated() {
    isolation(
        MemoryStore::new("community-a").unwrap(),
        MemoryStore::new("community-b").unwrap(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_retries_commit_one_record() {
    let store = MemoryStore::new("community-a").unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let clone = store.clone();
        tasks.spawn(async move {
            Gate::new(clone, TestVerifier::new("community-a"))
                .record_legal(&sign(legal("same")))
                .await
        });
    }
    let mut inserted = 0;
    let mut unchanged = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap().unwrap() {
            Append::Inserted => inserted += 1,
            Append::Unchanged => unchanged += 1,
        }
    }
    assert_eq!((inserted, unchanged), (1, 7));
    assert_eq!(store.counts().await.unwrap().legal_orders, 1);
}

#[test]
fn invalid_community_identifiers_are_rejected() {
    for community in ["", " ", "a\0b", "a\nb"] {
        assert!(MemoryStore::new(community).is_err());
    }
}

#[test]
fn system_clock_returns_supported_samples_and_safe_errors() {
    use clbs::{Clock, SystemClock};
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let at = SystemClock.now().unwrap();
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(at >= 0);
    assert!((before..=after).contains(&(at as u64)));
    for error in [
        Error::Invalid("static validation failure"),
        Error::Denied,
        Error::CommunityMismatch,
        Error::Conflict,
        Error::Storage,
        Error::Clock,
    ] {
        assert!(!error.to_string().is_empty());
        assert!(std::error::Error::source(&error).is_none());
    }
    assert_eq!(format!("{:?}", clbs::OrderKind::SelfBan), "SelfBan");
}
