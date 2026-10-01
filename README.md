# clbs

**Legal veto gate: green by default; verified legal orders and confirmed
permanent self-bans apply their exact scope and period.**

Native Rust library under `cvld → cmty → cgts`. Stores permanent order metadata
through crlt, checks every action without recording access, and produces
revocation entries and aggregate transparency counts. Interfaces may change.
See [the implemented contract](docs/CONTRACT.md).

## Dependency survey

Surveyed crates.io listings and upstream GitHub sources on 2026-09-30:

| Candidate | Choice and reason |
|---|---|
| [crlt](https://github.com/corbet-foss/crlt) (LGPL with linking exception) | Selected. Main exposes scoped handles, migrations, transactions and index enforcement. Pinned git revision makes the initial integration reproducible. |
| [libsql](https://github.com/tursodatabase/libsql/tree/main/libsql) (MIT) | Official local/remote client, used through crlt. Its ready facade makes a direct-driver fallback unnecessary. |
| [casbin](https://crates.io/crates/casbin), [upstream](https://github.com/apache/casbin-rs) (Apache-2.0) | Maintained general authorization engine. Not selected: this gate needs literal scope/period checks and an immutable order ledger, not a configurable policy language. |
| [cedar-policy](https://crates.io/crates/cedar-policy), [upstream](https://github.com/cedar-policy/cedar) (Apache-2.0) | Maintained policy engine; same mismatch. Neither candidate validates qualified legal signatures or supplies this order contract. |
| [European Commission DSS](https://github.com/esig/dss) (LGPL-2.1) | Established electronic-signature implementation; candidate for a future external verifier adapter. Java/service integration and jurisdiction-specific authority checks are outside this crate. |

The facade owns only order validation and veto semantics. crlt/libSQL owns
persistence. `serde`/`serde_json` (MIT/Apache-2.0) encode typed metadata;
`thiserror` (MIT/Apache-2.0) defines sanitized errors. Test-only dependencies
are Tokio, tempfile and ed25519-dalek (BSD-3-Clause) for real signed fixtures.
There are no homegrown cryptographic primitives or GPL/AGPL-only dependencies.
No other cvld crate currently supplies qualified-signature authorization or
fresh self-ban confirmation; the minimal local `Verifier` trait defines that
boundary without assuming sibling APIs. Snapshot signing belongs to the caller.

## Integration

```rust,no_run
use clbs::{Gate, LibsqlStore, SCHEMA, SystemClock, Verifier, State};
use crlt::{Config, Db, Migration};

async fn example(verifier: impl Verifier) -> Result<(), Box<dyn std::error::Error>> {
    let db = Db::open(Config::new("file:///tmp/example-clbs.db", "")).await?;
    // In a composed service, append SCHEMA to its complete migration history.
    db.migrate(&[Migration::new(1, "clbs orders", SCHEMA)]).await?;
    let store = LibsqlStore::new(&db, "example-community")?;
    let gate = Gate::new(store, verifier, SystemClock);
    match gate.check_action("community-pseudonym", "publish").await? {
        State::Green => { /* Perform the action. */ }
        State::Red(_) => { /* Refuse within the returned scope. */ }
    }
    Ok(())
}
```

The service implements both `Verifier` methods, authenticating root-entered
legal orders or fresh passkey-confirmed self-bans. Supply a `SignedOrder` to
`record_legal` or `self_ban`; raw evidence is never stored. Retries with identical
metadata return `Append::Unchanged`; conflicts never overwrite an order.

Use `check(subject)` for all active restrictions, `check_action` for an exact
action, `record(id)` for authorized audit, `revocations()` for internal signed
snapshots, and `counts()` for subject-free order totals. Storage/clock errors
must refuse or defer actions. `MemoryStore` supports ephemeral tests; production
uses one libSQL database per community. Keep SQL/HTTP debug tracing disabled
in the service. Do not log order metadata or proof envelopes.

## Validation

GitHub Actions runs `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test` on stable Rust.
No Cargo commands run on the workstation. Tests cover real signed orders,
both storage implementations, libSQL persistence, isolation, failure cases,
and index plans. CI retains the resolved dependency lockfile as an artifact.

The optional Turso test skips unless both `TURSO_URL` and `TURSO_TOKEN` are
nonempty. Use a disposable test database: the test migrates its schema and
permanently appends test orders. Credentials are read only by that test,
never committed or configured in public CI. Never publish to a registry.

## Open integration work

Qualified e-signature/authority and fresh-passkey verifier adapters; signed
revocation publication and scheduled-order refresh; coordination between a
check and its action; rescission semantics for legal orders. See the contract
for row-limit behavior and the surrounding service's responsibilities.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
