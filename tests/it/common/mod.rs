#![allow(dead_code)]

use clbs::{Error, Order, OrderKind, Result, Scope, SignedOrder, Verifier};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

// Test-only verifier for authentic signatures and a fixed authorized test actor.
// It is not a qualified e-signature or passkey adapter. No clbs logic is mocked.
#[derive(Clone)]
pub struct TestVerifier {
    community: String,
    legal: VerifyingKey,
    member: VerifyingKey,
}

impl TestVerifier {
    pub fn new(community: &str) -> Self {
        Self {
            community: community.into(),
            legal: key(7).verifying_key(),
            member: key(8).verifying_key(),
        }
    }

    fn verify(&self, submission: &SignedOrder, key: &VerifyingKey) -> Result<()> {
        if submission.order.community != self.community {
            return Err(Error::Denied);
        }
        let signature = Signature::from_slice(&submission.proof).map_err(|_| Error::Denied)?;
        key.verify_strict(&submission.order.signing_payload()?, &signature)
            .map_err(|_| Error::Denied)
    }
}

impl Verifier for TestVerifier {
    async fn verify_legal(&self, submission: &SignedOrder) -> Result<()> {
        if submission.order.kind
            != (OrderKind::Legal {
                authority: "court".into(),
            })
            || submission.order.entered_by != "root"
        {
            return Err(Error::Denied);
        }
        self.verify(submission, &self.legal)
    }

    async fn verify_self_ban(&self, submission: &SignedOrder) -> Result<()> {
        if submission.order.subject != "alice" {
            return Err(Error::Denied);
        }
        self.verify(submission, &self.member)
    }
}

pub fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

pub fn legal(id: &str) -> Order {
    Order {
        community: "community-a".into(),
        id: id.into(),
        subject: "alice".into(),
        reference: "case-reference".into(),
        entered_by: "root".into(),
        kind: OrderKind::Legal {
            authority: "court".into(),
        },
        scope: Scope::Member,
    }
}

pub fn ban(id: &str) -> Order {
    Order {
        kind: OrderKind::SelfBan,
        entered_by: "alice".into(),
        ..legal(id)
    }
}

pub fn sign(order: Order) -> SignedOrder {
    let signer = match order.kind {
        OrderKind::Legal { .. } => key(7),
        OrderKind::SelfBan => key(8),
    };
    let proof = signer
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    SignedOrder { order, proof }
}

pub async fn memory_fixture() -> ((), clbs::MemoryStore) {
    ((), clbs::MemoryStore::new("community-a").unwrap())
}
