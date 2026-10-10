//! Shared behavior contract exercised against memory and real libSQL storage.
mod common;

use clbs::{Append, Counts, Error, Gate, OrderKind, Scope, SignedOrder, State, Store};
use common::{TestClock, TestVerifier, ban, legal, sign};

async fn lifecycle<S: Store + Clone>(store: S) {
    let clock = TestClock::new(99);
    let gate = Gate::new(store, TestVerifier::new("community-a"), clock.clone());
    assert_eq!(gate.check("unknown").await.unwrap(), State::Green);
    assert_eq!(gate.record("absent").await.unwrap(), None);
    assert_eq!(gate.counts().await.unwrap(), Counts::default());
    assert!(gate.revocations().await.unwrap().is_empty());
    let submission = sign(legal("first"));
    assert_eq!(
        gate.record_legal(&submission).await.unwrap(),
        Append::Inserted
    );
    assert_eq!(gate.check("alice").await.unwrap(), State::Green);
    assert!(gate.revocations().await.unwrap().is_empty());
    clock.set(100);
    assert!(matches!(gate.check("alice").await.unwrap(), State::Red(_)));
    assert!(matches!(
        gate.check_action("alice", "publish").await.unwrap(),
        State::Red(_)
    ));
    for action in ["read", "Publish", "publish.extra", "pub", "*"] {
        assert_eq!(
            gate.check_action("alice", action).await.unwrap(),
            State::Green
        );
    }
    assert_eq!(gate.check("Alice").await.unwrap(), State::Green);
    clock.set(199);
    assert!(matches!(gate.check("alice").await.unwrap(), State::Red(_)));
    clock.set(200);
    assert_eq!(gate.check("alice").await.unwrap(), State::Green);
    assert!(gate.revocations().await.unwrap().is_empty());
    assert_eq!(
        gate.record("first").await.unwrap().unwrap().order(),
        &submission.order
    );
    assert_eq!(
        gate.counts().await.unwrap(),
        Counts {
            legal_orders: 1,
            ..Counts::default()
        }
    );
}

async fn overlap_and_counts<S: Store + Clone>(store: S) {
    let clock = TestClock::new(150);
    let gate = Gate::new(store, TestVerifier::new("community-a"), clock.clone());
    gate.record_legal(&sign(legal("b"))).await.unwrap();
    let mut second = legal("a");
    second.scope = Scope::All;
    second.period.ends_at = Some(300);
    gate.record_legal(&sign(second)).await.unwrap();
    let mut future = legal("future");
    future.period.starts_at = 500;
    future.period.ends_at = None;
    gate.record_legal(&sign(future)).await.unwrap();
    let mut self_ban = ban("self");
    self_ban.period.starts_at = 140;
    gate.self_ban(&sign(self_ban)).await.unwrap();
    assert_eq!(
        gate.counts().await.unwrap(),
        Counts {
            legal_orders: 3,
            self_bans: 1,
            active_legal_orders: 2,
            active_self_bans: 1
        }
    );
    let entries = gate.revocations().await.unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.order_id.as_str())
            .collect::<Vec<_>>(),
        ["a", "b", "self"]
    );
    let wire = serde_json::to_string(&entries).unwrap();
    for private in [
        "reference",
        "case-reference",
        "entered_by",
        "authority",
        "court",
        "root",
    ] {
        assert!(!wire.contains(private));
    }
    let report = serde_json::to_value(gate.counts().await.unwrap()).unwrap();
    assert_eq!(report.as_object().unwrap().len(), 4);
    assert!(
        report
            .as_object()
            .unwrap()
            .values()
            .all(serde_json::Value::is_u64)
    );
    clock.set(200);
    assert_eq!(gate.counts().await.unwrap().active_legal_orders, 1);
    assert!(matches!(
        gate.check_action("alice", "read").await.unwrap(),
        State::Red(_)
    ));
    clock.set(300);
    assert_eq!(gate.counts().await.unwrap().active_legal_orders, 0);
    assert_eq!(gate.revocations().await.unwrap().len(), 1);
    clock.set(i64::MAX);
    assert_eq!(gate.revocations().await.unwrap().len(), 2);
    assert_eq!(gate.counts().await.unwrap().active_self_bans, 1);
}

async fn retries_and_conflicts<S: Store + Clone>(store: S) {
    let gate = Gate::new(store, TestVerifier::new("community-a"), TestClock::new(150));
    let original = sign(legal("retry"));
    assert_eq!(
        gate.record_legal(&original).await.unwrap(),
        Append::Inserted
    );
    assert_eq!(
        gate.record_legal(&original).await.unwrap(),
        Append::Unchanged
    );
    let mut changed = original.order.clone();
    changed.period.ends_at = Some(201);
    assert_eq!(
        gate.record_legal(&sign(changed)).await,
        Err(Error::Conflict)
    );
    assert_eq!(
        gate.self_ban(&sign(ban("retry"))).await,
        Err(Error::Conflict)
    );
    assert_eq!(
        gate.record("retry").await.unwrap().unwrap().order(),
        &original.order
    );
    assert_eq!(gate.counts().await.unwrap().legal_orders, 1);
    // Even an idempotent retry must pass verification again.
    let invalid = SignedOrder {
        proof: vec![0; 64],
        ..original
    };
    assert_eq!(gate.record_legal(&invalid).await, Err(Error::Denied));
}

async fn verification_failures<S: Store + Clone>(store: S) {
    let gate = Gate::new(store, TestVerifier::new("community-a"), TestClock::new(150));
    let mut forged = sign(legal("forged"));
    forged.proof[0] ^= 1;
    assert_eq!(gate.record_legal(&forged).await, Err(Error::Denied));
    let mut unknown_authority = legal("other-authority");
    unknown_authority.kind = OrderKind::Legal {
        authority: "untrusted-court".into(),
    };
    assert_eq!(
        gate.record_legal(&sign(unknown_authority)).await,
        Err(Error::Denied)
    );
    let mut wrong_actor = legal("other-actor");
    wrong_actor.entered_by = "admin".into();
    assert_eq!(
        gate.record_legal(&sign(wrong_actor)).await,
        Err(Error::Denied)
    );
    let mut wrong_key = sign(legal("other-key"));
    use ed25519_dalek::Signer;
    wrong_key.proof = common::key(9)
        .sign(&wrong_key.order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    assert_eq!(gate.record_legal(&wrong_key).await, Err(Error::Denied));
    for index in 0..8 {
        let mut modified = sign(legal("tamper"));
        match index {
            0 => modified.order.id.push('x'),
            1 => modified.order.subject.push('x'),
            2 => modified.order.reference.push('x'),
            3 => modified.order.entered_by.push('x'),
            4 => modified.order.scope = Scope::All,
            5 => modified.order.period.starts_at += 1,
            6 => modified.order.period.ends_at = None,
            _ => {
                modified.order.kind = OrderKind::Legal {
                    authority: "other".into(),
                }
            }
        }
        assert_eq!(gate.record_legal(&modified).await, Err(Error::Denied));
    }
    let mut wrong_community = legal("wrong-community");
    wrong_community.community = "community-b".into();
    assert_eq!(
        gate.record_legal(&sign(wrong_community)).await,
        Err(Error::CommunityMismatch)
    );
    assert_eq!(gate.counts().await.unwrap(), Counts::default());
    assert_eq!(gate.check("alice").await.unwrap(), State::Green);
}

async fn self_ban_rules<S: Store + Clone>(store: S) {
    let clock = TestClock::new(100);
    let gate = Gate::new(store, TestVerifier::new("community-a"), clock.clone());
    let permanent = sign(ban("termination"));
    assert!(gate.record_legal(&permanent).await.is_err());
    assert!(gate.self_ban(&sign(legal("legal"))).await.is_err());
    for index in 0..5 {
        let mut invalid = sign(ban("invalid"));
        match index {
            0 => invalid.order.scope = Scope::Actions(["publish".into()].into()),
            1 => invalid.order.period.ends_at = Some(200),
            2 => invalid.order.entered_by = "root".into(),
            3 => invalid.order.period.starts_at = 101,
            _ => invalid.proof = vec![0; 64],
        }
        assert!(gate.self_ban(&invalid).await.is_err());
    }
    let mut other_subject = ban("other");
    other_subject.subject = "bob".into();
    other_subject.entered_by = "bob".into();
    assert_eq!(
        gate.self_ban(&sign(other_subject)).await,
        Err(Error::Denied)
    );
    assert_eq!(gate.self_ban(&permanent).await.unwrap(), Append::Inserted);
    assert_eq!(gate.self_ban(&permanent).await.unwrap(), Append::Unchanged);
    clock.set(i64::MAX);
    assert!(matches!(
        gate.check_action("alice", "anything").await.unwrap(),
        State::Red(_)
    ));
    assert_eq!(
        gate.record("termination").await.unwrap().unwrap().order(),
        &permanent.order
    );
    assert_eq!(
        gate.counts().await.unwrap(),
        Counts {
            self_bans: 1,
            active_self_bans: 1,
            ..Counts::default()
        }
    );
}

async fn invalid_input<S: Store + Clone>(store: S) {
    let clock = TestClock::new(100);
    let gate = Gate::new(store, TestVerifier::new("community-a"), clock.clone());
    for index in 0..13 {
        let mut invalid = sign(legal("invalid"));
        match index {
            0 => invalid.order.subject.clear(),
            1 => invalid.order.id = " ".into(),
            2 => invalid.order.reference = "\n".into(),
            3 => invalid.order.subject = "a\0b".into(),
            4 => invalid.order.period.starts_at = -1,
            5 => invalid.order.period.ends_at = Some(100),
            6 => invalid.order.period.ends_at = Some(99),
            7 => invalid.order.scope = Scope::Actions(Default::default()),
            8 => invalid.order.scope = Scope::Actions(["".into()].into()),
            9 => invalid.order.scope = Scope::Actions((0..257).map(|i| i.to_string()).collect()),
            10 => invalid.order.reference = "x".repeat(1025),
            11 => invalid.proof.clear(),
            _ => invalid.proof = vec![0; 1024 * 1024 + 1],
        }
        assert!(matches!(
            gate.record_legal(&invalid).await,
            Err(Error::Invalid(_))
        ));
    }
    assert!(gate.check("").await.is_err());
    assert!(gate.check_action("alice", "\0").await.is_err());
    assert!(gate.record(" ").await.is_err());
    assert_eq!(gate.counts().await.unwrap(), Counts::default());
    clock.set(-1);
    assert!(gate.check("alice").await.is_err());
    assert!(gate.revocations().await.is_err());
    assert!(gate.counts().await.is_err());
}

async fn timestamp_extremes<S: Store + Clone>(store: S) {
    let clock = TestClock::new(0);
    let gate = Gate::new(store, TestVerifier::new("community-a"), clock.clone());
    let mut order = legal("epoch");
    order.period.starts_at = 0;
    order.period.ends_at = Some(1);
    gate.record_legal(&sign(order)).await.unwrap();
    assert!(matches!(gate.check("alice").await.unwrap(), State::Red(_)));
    clock.set(1);
    assert_eq!(gate.check("alice").await.unwrap(), State::Green);
    let mut max = legal("max");
    max.period.starts_at = i64::MAX - 1;
    max.period.ends_at = Some(i64::MAX);
    gate.record_legal(&sign(max)).await.unwrap();
    clock.set(i64::MAX - 1);
    assert!(matches!(gate.check("alice").await.unwrap(), State::Red(_)));
    clock.set(i64::MAX);
    assert_eq!(gate.check("alice").await.unwrap(), State::Green);
}

async fn opaque_identifiers<S: Store + Clone>(store: S) {
    let gate = Gate::new(store, TestVerifier::new("community-a"), TestClock::new(150));
    let mut order = legal("x'; DROP TABLE clbs_orders; --");
    order.subject = "subject-雪-'?1".into();
    order.reference = "café".into();
    order.scope = Scope::Actions(["action-'?1".into()].into());
    gate.record_legal(&sign(order.clone())).await.unwrap();
    assert!(matches!(
        gate.check_action(&order.subject, "action-'?1")
            .await
            .unwrap(),
        State::Red(_)
    ));
    assert_eq!(
        gate.record(&order.id).await.unwrap().unwrap().order(),
        &order
    );
    assert_eq!(gate.check("alice").await.unwrap(), State::Green);
}

macro_rules! suite {
    ($module:ident, $factory:ident) => {
        mod $module {
            use super::*;
            macro_rules! case {
                ($name:ident) => {
                    #[tokio::test]
                    async fn $name() {
                        let (_directory, store) = common::$factory().await;
                        super::$name(store).await;
                    }
                };
            }
            case!(lifecycle);
            case!(overlap_and_counts);
            case!(retries_and_conflicts);
            case!(verification_failures);
            case!(self_ban_rules);
            case!(invalid_input);
            case!(timestamp_extremes);
            case!(opaque_identifiers);
        }
    };
}
suite!(memory, memory_fixture);

#[tokio::test]
async fn nested_diagnostics_redact_identity_bearing_metadata() {
    let (_, store) = common::memory_fixture().await;
    let gate = Gate::new(store, TestVerifier::new("community-a"), TestClock::new(150));
    let submission = sign(legal("sensitive-order-id"));
    gate.record_legal(&submission).await.unwrap();
    let record = gate.record("sensitive-order-id").await.unwrap().unwrap();
    let revocation = clbs::Revocation::from(record.clone());
    let state = gate.check("alice").await.unwrap();
    let debug = format!(
        "{:?} {:?} {:?} {:?} {:?}",
        submission.order, submission.order.kind, record, revocation, state
    );
    for secret in [
        "sensitive-order-id",
        "community-a",
        "alice",
        "case-reference",
        "root",
        "court",
    ] {
        assert!(!debug.contains(secret), "identity leaked through Debug");
    }
    assert!(matches!(state, State::Red(_)));
    // Authorized explicit serialization still carries the enforcement metadata.
    let wire = serde_json::to_string(&state).unwrap();
    assert!(wire.contains("sensitive-order-id"));
    assert!(wire.contains("alice"));
}

#[tokio::test]
async fn unknown_subject_has_no_action_restrictions_or_persisted_order() {
    let store = clbs::MemoryStore::new("community-a").unwrap();
    let gate = Gate::new(store, TestVerifier::new("community-a"), TestClock::new(150));
    assert_eq!(gate.check_action("unknown", "post").await, Ok(State::Green));
    assert_eq!(gate.record("unknown").await, Ok(None));
}

#[test]
fn trusted_storage_reconstruction_validates_metadata_without_authentication() {
    let order = legal("restored");
    assert_eq!(
        clbs::Record::restore_trusted(order.clone())
            .unwrap()
            .order(),
        &order
    );
    let mut invalid = order;
    invalid.period.ends_at = Some(invalid.period.starts_at);
    assert!(clbs::Record::restore_trusted(invalid).is_err());
}
