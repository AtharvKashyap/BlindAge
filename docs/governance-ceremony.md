# BlindAge Registry Governance Ceremony

How trust-registry updates are authorized, delayed, executed, and **externally
verified**. This governs the on-chain `RegistryAnchor` — the keccak hash,
`generated_at`, and version of the signed trust registry. It holds **public
trust data only**: issuer keys, status, rotation, revocation, transparency
roots. Constitution rule 3 is absolute — no identity, token, redemption,
domain, IP, or fingerprint data goes on-chain, not even hashed. Governance
controls *which public registry the world treats as canonical*, nothing about
users.

Governance never touches the double-anonymity properties. It cannot deanonymize
anyone; the worst a fully-compromised governance set can do is publish a bad
*public* registry — which is exactly what the transparency log and the
independent auditor are built to catch.

## Role model (OpenZeppelin `TimelockController`)

Updates go through OpenZeppelin's audited `TimelockController` (constitution
rule 4 applied to contracts: never hand-roll governance primitives). The
`RegistryAnchor` is owned by the timelock — `setAnchor` is `onlyOwner`, so the
**only** path to change the anchor is a timelock operation. Three roles:

- **Proposer** — may `schedule` an operation (and `cancel`). Scheduling starts
  the mandatory delay; it does not change state. Proposers decide *what* is
  queued.
- **Executor** — may `execute` a scheduled operation once its delay has
  elapsed. Executors decide *when* a queued, matured operation lands. An
  executor cannot queue anything new; a proposer cannot land anything.
- **Admin** — manages role membership. We deploy **self-administered**: the
  timelock is its own admin (the constructor's `admin` argument is the zero
  address, which skips granting an optional admin to a deployer EOA). Role
  changes therefore themselves go through the timelock — the same
  schedule/delay/execute discipline, no EOA backdoor.

The split of `schedule` from `execute` across **different** key holders is the
separation of duties: no single key can both queue and land an update. A queued
malicious update is visible on-chain for the full delay window before any
executor can act, giving auditors and the public time to react (or a proposer
to `cancel`).

## N-of-M options

`TimelockController` takes *sets* of proposers and executors. Two ways to get
M-of-N authorization:

1. **Multiple proposer/executor EOAs.** Grant the proposer role to several
   independent key holders and the executor role to a different, non-overlapping
   set. On its own this is 1-of-N per role (any one proposer can schedule) — use
   it when you want redundancy and role separation but not on-chain threshold
   enforcement. Thresholds come from option 2.
2. **A Gnosis Safe (multi-sig) as the sole proposer.** Grant the proposer role
   to a single address that is an M-of-N Safe. Now *scheduling* requires M
   signatures collected off-chain, and the timelock still enforces the delay.
   Executors can be a second, disjoint Safe (or a small operator set) so that
   *landing* an update also requires its own quorum. This is the recommended
   production shape: threshold authorization on the proposal, independent
   threshold (or role-separated operators) on execution, delay in between.

Keep proposer and executor sets **disjoint** so no key satisfies both roles.
The separation-of-duties test below is the executable proof that a proposer
key cannot execute.

## Delay policy

The timelock's minimum delay is the public review window between "queued" and
"landable".

- **Dev / demo:** `1` second, so the demo and chain tests run fast.
- **Production:** on the order of **days** (e.g. 24–72h). Long enough that the
  transparency log, the auditor, and human reviewers can inspect any queued
  update — and a proposer can `cancel` — before an executor can land it. Set it
  to your realistic incident-response time, not shorter.

Changing the delay is itself a timelocked operation (self-administered admin),
so a shortened delay is queued under the *old* delay and is publicly visible
before it takes effect.

## Key-holder ceremony checklist

For a production registry update:

1. **Prepare the artifact.** Regenerate `registry.json`, bump its `version` and
   `generated_at`, and re-sign it (Ed25519 + ML-DSA hybrid root). Compute
   `registry_keccak(registry)`.
2. **Independent review.** At least one reviewer who did not build the artifact
   confirms the diff is intended and that `version`/`generated_at` are strictly
   increasing (the anchor and publisher both reject non-monotonic updates).
3. **Schedule (proposer quorum).** The proposer Safe collects M signatures and
   submits `schedule(anchor, 0, setAnchor-calldata, predecessor, salt, delay)`.
   Record the operation id and the emitted event.
4. **Public delay window.** Announce the queued update. The transparency log now
   shows the pending change; anyone can recompute the hash and inspect it. Any
   proposer may `cancel` if it is wrong.
5. **Execute (executor quorum).** After the delay elapses, the executor set
   submits `execute(...)` with identical parameters. `setAnchor` fires
   `AnchorUpdated`.
6. **Verify.** Run the auditor against the mirror + chain (below) and confirm
   PASS and the new head version. Publish the auditor output.
7. **Rotate/retire keys** as needed — itself a scheduled, delayed operation.

Never let one person hold both a proposer and an executor key. Store keys in
hardware / HSM-backed signers. Treat the admin path (role changes) with the same
rigor as anchor updates — it is timelocked for exactly that reason.

## External verification: log + auditor

Governance is only trustworthy if outsiders can check it without asking the
operator. Two tools do this, both over public data only:

- **Transparency log** (`blindage.transparency.app.create_log_server`) — a
  stateless, cached view over the anchor's `AnchorUpdated` events, ordered by
  `(block, log index)` and served at `GET /log`. The chain *is* the log; this
  just presents it. Every schedule→execute cycle that lands leaves a permanent,
  publicly ordered record: version, `generated_at`, registry hash, block, tx.
  It fails closed (503) rather than serve a stale or partial history.
- **Independent auditor** (`blindage.transparency.auditor`) — cross-checks a
  registry *mirror* against the *chain*, with no trust in the operator:
  1. chain head reachable, event history reachable and monotonic;
  2. chain head matches the last logged event;
  3. the mirror's served `registry.json` hashes (keccak) to the head anchor;
  4. the mirror's `generated_at` matches the head.
  **Any** failure — tampered mirror, rolled-back version, unreachable mirror or
  RPC — is a distinct problem string and a non-zero exit. An auditor that skips
  is an auditor that lies, so nothing is ever "unknown → pass".

Run it:

```
python -m blindage.transparency.auditor \
  --mirror http://127.0.0.1:8080 --rpc http://127.0.0.1:8545 --contract <anchor>
```

Because the auditor recomputes the hash from the served bytes and compares to
the on-chain head, an operator who silently serves a *different* registry than
the one they anchored is caught immediately — that is the equivocation defense.

## Executable proof

The separation of duties is not just documented, it is tested against the real
OpenZeppelin contract on a local anvil chain:

- `tests/chain/test_anchor_integration.py::test_governance_separation_of_duties`
  deploys the timelock with `proposers=[A]`, `executors=[B]`, schedules the
  update as **A**, shows that **A cannot execute** (the reverting execute is
  denied — status 0 or a reverted call), and that only **B** can land it, after
  which `version() == 1`.
- `test_transparency_log_and_auditor_end_to_end` proves the log serves the
  ordered history and that the auditor **PASSes** an honest mirror, **FAILs** a
  tampered mirror (hash mismatch), and **FAILs** a down mirror.

Run the whole chain-gated suite with `./scripts/test_contracts.sh`, or see the
two-account governance path and the transparency instructions printed by
`scripts/run_chain_demo.sh`.
