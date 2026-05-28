# ADR-011: Staking via a registry-owned escrow + chained-call funding

- **Status:** Accepted
- **Date:** 2026-05-29
- **Phase:** P8 (staking — closes the "register with a stake" / slash "claims the stake" gap)

## Context

The bounty requires registration "with a stake" and slash to "claim the
stake." Until now `stake_amount` was a config field only — nothing was locked
or claimed. Implementing real staking requires moving native value, and the
nssa value model has a hard rule we must design around.

What the LEZ code says (researched from the `8c8f5b57` checkout):

- Every `Account` has a native `balance: u128`.
- **`validate_execution` rule 5:** a program may only *decrease* the balance of
  an account it **owns**. Increasing any account's balance is always allowed,
  subject to total-balance conservation (rule 8).
- Native value is actually moved by the **`authenticated_transfer`** program:
  `Transfer { amount }` over accounts `[sender, recipient]` (debit sender,
  credit recipient). It is the primitive mover.
- The **`vault`** program is a thin wrapper that routes
  `authenticated_transfer.Transfer` to a per-owner vault PDA
  (`compute_vault_account_id(vault_program, owner_id)`). Genesis funds each
  supply account into its **vault**.
- **Cross-program calls** exist: a program returns
  `ProgramOutput::with_chained_calls(vec![ChainedCall::new(program_id,
  pre_states, &instruction).with_pda_seeds(seeds)])`. `pda_seeds` authorizes
  the callee to mutate the `AccountId` derived from `(caller_program_id,
  seed)` — i.e. a program **can sign for its own PDA** (the `amm` LP-mint and
  `vault`'s own transfers both rely on this).

So a program cannot pull a member's funds by editing balances directly, but it
*can* chain a call to `authenticated_transfer` (the member authorizes it by
signing the tx), and it *can* directly decrease the balance of an account it
owns.

## Decision

A per-forum **escrow account is a registry-owned PDA** (claimed
`Claim::Pda(escrow_seed)`). Stake pools there.

- **Register (lock):** the `Register` guest, after recording the commitment,
  emits one chained call:
  `authenticated_transfer.Transfer { amount: stake_amount }` over
  `[member, escrow]`. The member signed the register tx, so their account is
  authorized and is debited; the escrow (registry-owned) is credited (a
  balance *increase*, allowed for any owner). Modeled on `amm::add`'s chained
  `token.Transfer(user → pool_vault)`.
- **Slash (claim):** the `Slash` guest directly moves
  `escrow.balance -= stake_amount; slasher.balance += stake_amount` in its own
  post-states. The registry **owns** the escrow, so rule 5 permits the
  decrease — **no chained call needed for the payout.** Slash gains the escrow
  + slasher accounts in its instruction.
- **Member funds:** native balance lands in a member's *vault* at genesis. To
  have a spendable `authenticated_transfer`-owned balance, the member claims
  from their vault once (`vault.Claim`) as demo setup (analogous to a faucet
  top-up); the daemon/runner performs this before register.

This keeps the cryptographic protocol (ADR-008, ADR-010) untouched — staking
is purely an economic layer on register/slash.

## Alternatives considered

- **CPI on both sides** (chain `authenticated_transfer.Transfer(escrow →
  slasher)` with `with_pda_seeds([escrow_seed])` on slash). Works (it's how
  `vault.Claim` pays out), but the registry owns the escrow, so the direct
  balance move is simpler and avoids a second chained call. Rejected for
  slash; kept as the fallback if escrow ownership turns out not to survive a
  credit.
- **Escrow = a vault PDA** addressed via `compute_vault_account_id`. Matches
  genesis precedent exactly, but then both register and slash must route
  through `vault`/`authenticated_transfer` (CPI both ways). More moving parts
  than a registry-owned escrow. Rejected for v1.
- **Parameter-only "stake"** (current state). Rejected — fails the
  "register with a stake" / "claims the stake" criteria; nothing is locked.

## Consequences

- `Register` and `Slash` instructions gain accounts (member + escrow;
  escrow + slasher) and the guests gain chained-call / balance-move logic.
  This ripples through `lez-runner`, the daemon DTOs/handlers, and the SDK.
- The guest must serialize `authenticated_transfer_core::Instruction::Transfer`
  — vendor the tiny enum into the registry core (same pattern as the vendored
  shamir module) to avoid a cross-dir path dep in the risc0 docker context.
- The demo must fund the member's spendable account (one `vault.Claim`), and
  the escrow PDA must be claimed at `Initialize`.
- Requires a guest rebuild + redeploy (new ImageID) and live e2e iteration —
  this is the slow part; the choreography below is the design under test.
- **Confirmed during build** (all via the `valid_staking_lifecycle` V03State
  e2e — see below): `authenticated_transfer.Transfer` credits a
  non-`authenticated_transfer`-owned recipient (the registry escrow) and
  **preserves its `program_owner` as the registry** (the
  `else { AccountPostState::new(..) }` branch in the auth-transfer guest), so
  slash's direct debit is legal. The escrow-is-a-vault fallback is not needed.

## Funding path (resolved from the faucet/vault/auth-transfer guests)

Native value lives in per-owner **vaults** (genesis funds vaults via the
faucet). The faucet funds vaults, not direct balances, so getting *direct*
balance onto the registry-owned escrow PDA is a fixed chain:

1. The wallet creates/controls a member account (`create_new_account_public`).
2. `faucet.Transfer { vault_program_id, recipient_id: member, amount }` →
   member's **vault** (permissionless — genesis calls it with an empty witness).
3. `vault.Claim { amount }` over `[member, member_vault]` (member-signed) →
   member's **direct** balance (the account becomes authenticated_transfer-owned).
4. `authenticated_transfer.Transfer { amount }` over `[member, escrow]`
   (member-signed; `WalletCore::NativeTokenTransfer::send_public_transfer`
   wraps this) → credits the escrow PDA's **direct** balance.
5. `Register [state, escrow]` asserts `escrow.balance >= stake_amount × members`.
6. `Slash [state, escrow, slasher]` direct-debits `stake_amount` → slasher.

`send_public_transfer` already exists; `vault.Claim` has no wallet facade and is
built manually in `lez-runner` (Message + WitnessSet + the account's nonce +
its signing key). The runner reshape (multi-account `initialize`/`register`/
`slash` + these funding steps) is implemented in `crates/lez-runner`.

## Build outcome (verified)

The reshape and the value model are confirmed; the verification venue changed
based on three findings from the live single-node sequencer:

1. **The guest needs an explicit deploy.** `Initialize` only executes after a
   `deploy-program` tx registers the guest bytecode with the sequencer (the
   `get_program_ids` set is genesis-only; custom programs must be deployed). It
   is not implicit in the runner's `load_program`. With the guest deployed,
   `Initialize` executes live and claims the registry-owned escrow PDA
   (verified: escrow `program_owner` = registry, balance 0).
2. **The faucet is genesis-only.** User transactions that invoke the faucet are
   *dropped* by design — LEZ's own `cannot_execute_faucet_program` /
   `user_tx_that_chain_calls_faucet_is_dropped` integration tests assert this.
   So the faucet→vault funding chain above is **not usable at runtime**; native
   funds only enter via genesis (config `supply_account` entries) or, on a
   public testnet, whatever faucet that deployment exposes. On the local
   single-node chain the wallet account and genesis supply accounts are
   unfunded, so there is no runtime funding path.
3. **The slasher must be an existing account.** Crediting a fresh
   default-owned account without a claim is rejected
   (`DefaultAccountModifiedWithoutClaim`), and the slasher does not sign the
   no-auth `Slash` tx so it cannot self-claim. The slasher is therefore a real
   participant (moderator/treasury) whose account already exists. (A future
   guest revision could claim a default-owned slasher the way auth-transfer
   claims a default recipient; deferred — it pairs with the next guest rebuild.)

**Verification venue.** Because runtime funding is impossible on the local
single-node chain, the faithful e2e runs **in process via `nssa::V03State`**
(`crates/lez-runner/tests/staking_lifecycle.rs`), which executes the deployed
guest through the same risc0 engine the sequencer uses and lets us seed a
funded member directly at genesis (what a real testnet faucet would do). It is
more rigorous than a flaky live run: deterministic, fast, CI-able. It asserts
the escrow is claimed by the registry, funded by a member-signed
`authenticated_transfer` (owner preserved), the register stake-check passes,
and slash drains the escrow to the slasher while revoking the member.

A genuine public-testnet run (`https://testnet.lez.logos.co`) is a follow-up:
the testnet runs a **different LEZ version** (its system-program ids differ
from rev `8c8f5b57`), so it needs the guest + runner rebuilt against the
testnet's rev and a testnet-level funding source — both currently unknown.
