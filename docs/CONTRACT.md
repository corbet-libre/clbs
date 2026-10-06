# clbs contract

## Binding scope

`clbs` is the community legal veto under `cvld → cmty → cgts` in the
v0.4 architecture. It starts green. Only an authorized, verified legal order
turns it red, with the exact ordered scope and period. Voluntary termination
uses the same permanent switch after fresh confirmation by the subject.
Check before every action. Keep orders permanently with reference, scope,
period and entering actor. Produce revocation entries and subject-free
transparency counts.

Cross-library rules: native Rust on current stable; LGPL-3.0-only WITH
LGPL-3.0-linking-exception; survey maintained libraries first; no custom
cryptographic primitives; storage through crlt; one database per community;
every table has a community key and every application query uses an index.
No login dates, request logs, raw gate data, or registry publication. Tests
use real database round trips on GitHub Actions, without workstation builds.

## Implemented API and authority boundary

- `Gate::record_legal` validates a `SignedOrder`, calls `Verifier::verify_legal`,
  then appends metadata. The verifier must authenticate the entire order,
  the legal authority's competence for its exact scope and community, and
  the entering actor's authenticated root authorization. A signature alone
  does not establish legal authority. clbs supplies no permissive verifier.
- `Gate::self_ban` calls the separate `Verifier::verify_self_ban` boundary.
  The verifier requires fresh, intent-bound passkey confirmation and replay
  protection. Metadata must identify the subject as the entering actor,
  cover all actions, start no later than now, and have no end date.
- Both verifier methods are required, asynchronous, and receive the complete
  metadata plus ephemeral proof bytes. Evidence is never sent to storage.
  No qualified e-signature or WebAuthn implementation is claimed. Adapters
  must use established verification implementations; failures return errors.
- `Order::signing_payload` provides versioned JSON bytes with separate legal
  and self-ban domains. Adapters may instead use their external signature
  format, but must bind every metadata field and verify its exact meaning.
  Tests use real Ed25519 signatures; these are not qualified signatures.
- IDs, subjects, references, authorities, communities and action identifiers
  are opaque, case-sensitive UTF-8 strings: nonblank, no control characters,
  at most 1024 bytes. No normalization, wildcard expansion, identity lookup,
  or hierarchy is inferred. Action sets contain 1–256 distinct actions.
  Proof envelopes contain 1–1048576 bytes.
- `Record` is immutable, constructible only inside clbs, and cannot be
  deserialized by callers. Custom storage implementations are trusted.
  Raw database administration remains a privileged boundary.

## State and time

`Gate::check(subject)` returns `Green` or `Red` carrying all active
restrictions. `check_action(subject, action)` returns only restrictions
covering that exact action; unrelated actions remain green. Multiple orders
combine by union; the expiry of one does not cancel another. A subject with
no orders is green and creates no row.

Periods are nonnegative signed 64-bit Unix seconds: inclusive start,
exclusive end, or no end for permanent orders. Empty/reversed periods are
invalid. Scheduled legal orders are retained but have no effect before their
start. Expired orders remain permanently queryable. A trusted `Clock` is read
once per time-dependent operation; check times are never persisted. The
service must supply reliable time. No scheduler or cleanup is needed.

Errors, including clock, row-limit, decoding and database failures, are not
green. The caller must refuse or retry the action. A check is a point-in-time
read: the service must coordinate checks with actions if stronger atomicity
is needed. clbs cannot cancel actions already in progress.

## Storage and idempotency

`Store` defines community binding, atomic append, exact-ID lookup, active
subject orders, active revocation entries and aggregate counts. `MemoryStore`
is an actual lock-protected in-memory implementation. `LibsqlStore` uses the
ready crlt API pinned to a reviewed commit from main.

`SCHEMA` is trusted DDL to append to the composition root's complete crlt
migration history. The service owns version numbers, connection configuration,
credentials and database routing. It must migrate before constructing stores
and after reopening. No leaf-owned migration version conflicts with other
libraries. `clbs_orders` has a composite primary key `(community_id, id)` and
indexes for subject/period, community/period and community/count queries.
crlt injects community predicates and checks each application query plan.

Append uses an immediate transaction. An identical order ID and metadata is
idempotent; changed metadata with that ID is a conflict. Even retries require
verification. The signature envelope is excluded from idempotency comparisons
and is never retained. There are no update, delete or unban methods. An
uncertain remote commit must be reconciled by exact-ID lookup and a verified
retry of identical metadata; no automatic write retry occurs.

All reads are complete or error; crlt's configurable `max_rows` bounds memory.
Aggregate queries return only four counts, while scanning the community's
covering count index. Large revocation snapshots need an adequate row limit;
there is currently no pagination protocol or durable notification outbox.

## Outputs and privacy

`record(id)` is for root-authorized audit endpoints. It retains order metadata
only: no document, login history, check timestamps, request log, or proof bytes.
`revocations()` returns a complete active snapshot ordered by order ID,
including community, order ID, pseudonym, exact scope and period. It omits
references, authority and entering actor. Consumers must enforce the scope
and expiry, refresh for newly entered or scheduled orders, and sign/version
snapshots through the owning service. Lists contain subjects and are internal
trust data, not public transparency reports.

`counts()` contains total legal orders, total self-bans, active legal orders,
and active self-bans. Counts measure orders, not distinct people; overlaps and
retries have explicit semantics. Publication cadence and any small-count
suppression belong to the service; identifiers never appear in this output.

clbs does not sign snapshots, advance epochs, delete account data, enforce
uniqueness on re-registration, or terminate peer conversations. Those effects
belong to the surrounding services. Global suspension is owned by `cgbl`,
not inferred from a community order. Order rescission and qualified-signature
adapters remain future contract work; permanent self-bans have no reversal.
