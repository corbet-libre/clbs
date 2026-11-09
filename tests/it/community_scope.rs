//! Community legal scope: default green, permanent red, isolation from members.
//!
//! Tests first for the P4 data-model lane: a legal record may target scope
//! `Community(id)` as well as `Member(id)`, with the same permanence rules
//! (red is permanent, the record is kept, self-burn stays member-only).

use crate::common;
use crate::common::{TestVerifier, legal, sign};
use clbs::{Append, Gate, MemoryStore, Order, Record, Scope, State, Store};

fn gate(store: MemoryStore) -> Gate<MemoryStore, TestVerifier> {
    Gate::new(store, TestVerifier::new("community-a"))
}

/// A legal order targeting the community itself. Subject must equal the
/// community (self-targeting); the entering actor stays the legal root, so no
/// new authority type is needed.
fn community_legal(id: &str) -> Order {
    Order {
        scope: Scope::Community,
        subject: "community-a".into(),
        ..legal(id)
    }
}

async fn member_records(store: &MemoryStore, subject: &str) -> Vec<Record> {
    store.orders(subject).await.unwrap()
}

#[tokio::test]
async fn community_is_green_without_orders() {
    assert_eq!(
        clbs::community_legal_state("community-a", &[]),
        State::Green
    );
    // An invalid id can never match a recorded order.
    assert_eq!(clbs::community_legal_state("", &[]), State::Green);
}

#[tokio::test]
async fn community_turns_red_and_stays_red() {
    let store = MemoryStore::new("community-a").unwrap();
    let gate = gate(store.clone());
    let submission = sign(community_legal("comm-1"));
    assert_eq!(
        gate.record_legal(&submission).await.unwrap(),
        Append::Inserted
    );
    // The record is kept and readable by audit lookup.
    assert_eq!(
        gate.record("comm-1").await.unwrap().unwrap().order(),
        &submission.order
    );
    // Red is permanent: the pure check keeps reporting it.
    let records = store.orders("community-a").await.unwrap();
    assert!(matches!(
        clbs::community_legal_state("community-a", &records),
        State::Red(_)
    ));
    assert!(matches!(
        clbs::community_legal_state("community-a", &records),
        State::Red(_)
    ));
    // Idempotent retry, conflicting metadata refused.
    assert_eq!(
        gate.record_legal(&submission).await.unwrap(),
        Append::Unchanged
    );
    let mut changed = submission.order.clone();
    changed.reference.push('x');
    assert_eq!(
        gate.record_legal(&sign(changed)).await,
        Err(clbs::Error::Conflict)
    );
    let records = store.orders("community-a").await.unwrap();
    assert!(matches!(
        clbs::community_legal_state("community-a", &records),
        State::Red(_)
    ));
}

#[tokio::test]
async fn member_and_community_blocks_are_isolated() {
    let store = MemoryStore::new("community-a").unwrap();
    let gate = gate(store.clone());
    // A member record does not redden the community.
    gate.record_legal(&sign(legal("member-1"))).await.unwrap();
    assert!(matches!(gate.check("alice").await.unwrap(), State::Red(_)));
    let records = member_records(&store, "alice").await;
    assert_eq!(
        clbs::community_legal_state("community-a", &records),
        State::Green
    );
    let community_records = store.orders("community-a").await.unwrap();
    assert_eq!(
        clbs::community_legal_state("community-a", &community_records),
        State::Green
    );
    // A community record does not redden any member.
    gate.record_legal(&sign(community_legal("comm-1")))
        .await
        .unwrap();
    assert_eq!(gate.check("bob").await.unwrap(), State::Green);
    match gate.check("alice").await.unwrap() {
        State::Red(entries) => assert_eq!(entries.len(), 1),
        State::Green => panic!("alice must stay blocked exactly once"),
    }
    let records = store.orders("community-a").await.unwrap();
    assert!(matches!(
        clbs::community_legal_state("community-a", &records),
        State::Red(_)
    ));
    // A community record for another community does not leak either.
    assert_eq!(
        clbs::community_legal_state("community-b", &records),
        State::Green
    );
}

#[tokio::test]
async fn self_ban_cannot_target_a_community() {
    let store = MemoryStore::new("community-a").unwrap();
    let gate = gate(store.clone());
    let mut submission = sign(common::ban("comm-ban"));
    submission.order.scope = Scope::Community;
    submission.order.subject = "community-a".into();
    submission.order.entered_by = "community-a".into();
    assert!(matches!(
        gate.self_ban(&submission).await,
        Err(clbs::Error::Invalid(_))
    ));
    assert!(
        clbs::community_legal_state("community-a", &store.orders("community-a").await.unwrap())
            == State::Green
    );
    // Structural validation refuses it before any verifier runs.
    let mut structural = common::ban("structural");
    structural.scope = Scope::Community;
    structural.subject = "community-a".into();
    structural.entered_by = "community-a".into();
    assert!(structural.validate().is_err());
    assert!(Record::restore_trusted(structural).is_err());
}

#[tokio::test]
async fn community_scope_uses_the_existing_authority() {
    let store = MemoryStore::new("community-a").unwrap();
    let gate = gate(store);
    // Same authority, same verifier path: an untrusted authority is denied.
    let mut untrusted = community_legal("untrusted");
    untrusted.kind = clbs::OrderKind::Legal {
        authority: "untrusted-court".into(),
    };
    assert_eq!(
        gate.record_legal(&sign(untrusted)).await,
        Err(clbs::Error::Denied)
    );
    // A community order naming a different community is structurally invalid.
    let mut foreign = community_legal("foreign");
    foreign.subject = "community-b".into();
    assert!(foreign.validate().is_err());
}

#[test]
fn orders_without_scope_deserialize_as_member() {
    let order = legal("legacy");
    let mut value = serde_json::to_value(&order).unwrap();
    value.as_object_mut().unwrap().remove("scope");
    let restored: Order = serde_json::from_value(value).unwrap();
    assert_eq!(restored.scope, Scope::Member);
    assert_eq!(restored.subject, "alice");
}
