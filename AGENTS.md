# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Legal veto gate: green by default; only a verified legal order turns it red.
- Part of `cvld`. Architecture and contract: `~/agents/todo/active/cvld-gate-architecture/CVLD-CONTRACTS.md` and `CVLD-V0.2.md` (v0.4 section) on the operator's machine; the contract for this crate is copied into `docs/CONTRACT.md` when implementation starts.
- **Search before you write**: survey maintained crates first; prefer a thin facade over an established library; record candidates, choice and reasons in the README.
- No own cryptographic primitives. No login dates, no request logs, no raw gate data.
- RAM-only library. Durable adapters, SQL implementations, connections and credentials belong to the application through the atomic Store port.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add dependencies available only under GPL or AGPL.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` must pass.
- Do not build on the workstation. Push committed candidates and run checks on Crow.
- Tests: real signatures and state transitions, no mocks of our own logic; ample edge cases. Host database tests live with the host adapter.
- Commits: plain English, imperative; no AI attribution. Never publish to a registry.
