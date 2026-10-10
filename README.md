# clbs

**Legal veto gate: green by default; verified legal orders and confirmed
permanent self-bans apply their exact scope and period.**

Reusable Rust library used by `cvld → cmty → cgts`. Submits selected order metadata
to a caller-owned atomic store, checks every action without recording access, and produces
revocation entries and aggregate transparency counts. Interfaces may change.
See [the implemented contract](docs/CONTRACT.md).

## Dependency survey

Surveyed crates.io listings and upstream GitHub sources on 2026-09-30:

| Candidate | Choice and reason |
|---|---|
| [crlt](https://git.corbet.ch/corbet-foss/crlt) (LGPL with linking exception) | Application storage option, implemented outside this leaf. |

| [casbin](https://crates.io/crates/casbin), [upstream](https://github.com/apache/casbin-rs) (Apache-2.0) | Maintained general authorization engine. Not selected: this gate needs literal scope/period checks and an immutable order ledger, not a configurable policy language. |
| [cedar-policy](https://crates.io/crates/cedar-policy), [upstream](https://github.com/cedar-policy/cedar) (Apache-2.0) | Maintained policy engine; same mismatch. Neither candidate validates qualified legal signatures or supplies this order contract. |
| [European Commission DSS](https://github.com/esig/dss) (LGPL-2.1) | Established electronic-signature implementation; candidate for a future external verifier adapter. Java/service integration and jurisdiction-specific authority checks are outside this crate. |

The facade owns order validation and veto semantics. The application owns
persistence through `Store`; this library opens no database. `serde`/`serde_json` (MIT/Apache-2.0) encode typed metadata;
`thiserror` (MIT/Apache-2.0) defines sanitized errors. Test-only dependencies
are Tokio and ed25519-dalek (BSD-3-Clause) for real signed fixtures.
There are no homegrown cryptographic primitives or GPL/AGPL-only dependencies.
No other cvld crate currently supplies qualified-signature authorization or
fresh self-ban confirmation; the minimal local `Verifier` trait defines that
boundary without assuming sibling APIs. Snapshot signing belongs to the caller.

## Integration

```rust,no_run
use clbs::{Gate, Store, SystemClock, Verifier, State};

async fn example(store: impl Store, verifier: impl Verifier) -> Result<(), Box<dyn std::error::Error>> {
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
must refuse or defer actions. `MemoryStore` is RAM-only and process-local;
production durability and cross-process isolation belong to the application's
`Store` implementation. Host reconstruction uses `Record::restore_trusted`,
which validates structure but does not authenticate a new legal order. Never
use that method to turn member-supplied metadata into authority.

The verifier receives ephemeral proof bytes and the full requested metadata.
It must use maintained signature/passkey implementations and explicit trust;
this crate does not claim qualified-signature verification. Provider acquisition,
credentials and any billable dispatch remain outside this local verification
port. Such acquisition needs a separate explicit price/budget authorization.
Local scope/period checks do not call providers, acquire quotes or trigger
fallback. Host compute/storage may cost money. No default numerical quotas,
jurisdiction or legal-authority rules are invented.

For deterministic local simulation, use MemoryStore, an injected Clock and
real signatures under explicit test trust. The same scope, time, overlap and
idempotency logic executes; a test verifier must never be installed as production
trust. No production proof type is minted by a simulation API. Raw evidence stays
in RAM, never goes to Store and is not logged. Host swap/dumps and temporary
upstream parsing copies remain outside the library's control.

## Validation

CI runs formatting, warning-free Clippy, native tests and complete source line
and branch coverage. Tests cover real signed orders, invalid metadata, exact
scope/period checks, isolated RAM stores, concurrent idempotent append and safe
errors. Database adapters, database tests, migrations and optional remote probes
belong to the application host. No live provider or database service was called.

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

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
