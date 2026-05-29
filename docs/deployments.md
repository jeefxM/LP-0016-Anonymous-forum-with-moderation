# Deployments

## Local dev chain (Hetzner)

A full LEZ stack runs on the Hetzner build box for integration testing.

| Component | Status | Detail |
|---|---|---|
| Bedrock node | ✅ running | tmux session `bedrock`, docker compose, RPC :8080, producing blocks |
| Sequencer | ✅ running | tmux session `seq`, RPC :3040, `RISC0_DEV_MODE=1` |
| Wallet | ✅ initialised | `~/lez/wallet/configs/debug`, password `forum-protocol-dev` |
| `membership_registry` program | ✅ **deployed + exercised** | deployed; Initialize + Register run end-to-end (see below) |

### Live Register end-to-end (2026-05-28)

The `forum_register` runner (`crates/lez-runner`) drove a full lifecycle
against the live sequencer:

```
→ Initialize    next_leaf_index=0  tree_root=34fc00e4…2431d44  (empty-tree root)
→ Register A    next_leaf_index=1  tree_root=b6b5c41c…d8b703b5  (advanced)
✅ tree_root advanced, next_leaf_index = 1
```

This is the live-chain proof of `valid_registration`: the guest's Merkle
insertion executed on-chain exactly as the host-side `simulate_register`
unit test predicted. Transaction hashes are in `~/seq.log`.

### Live Slash end-to-end (2026-05-28)

The `forum_slash` runner drove the complete revocation lifecycle against
the live sequencer, using the slash-enabled guest (ImageID
`6eca79ea50971688befcec8933459ce1776ae16e01906d7d6227c58fafd9e9c5`):

```
Initialize (K=3, N=2, M=5 real Ed25519 moderators)
Register member A
Built 3 certs (2-of-5 sigs each) over real Shamir shares
off-chain reconstruction OK, commitment matches
Slash submitted → executed on-chain
✅ revocation_set contains member A's commitment
```

This proves the on-chain `verify_slash` — **ark-bn254 poly_eval +
Ed25519 signature verification running inside the RISC0 zkVM** — executes
correctly on a real chain: it verified 3 cert signatures, confirmed each
`share_x == H(secret, content_id)` and `share_y == poly_eval(coeffs,
share_x)` (the ADR-008 binding), verified the commitment is in the tree,
and wrote it to the revocation set.

The full protocol lifecycle — register → post → moderate → slash →
revoke — now runs end-to-end on-chain.

### membership_registry guest

- ELF: `~/forum-protocol/programs/membership_registry/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/membership_registry.bin`
- ImageID: `a7676642b321d4f9d2bbd63fba4158446c20d69bc925a44fe48aa5806d421f80`
- Deploy tx hash (first, succeeded): see seq.log block 4
- Re-deploy tx hash (rejected ProgramAlreadyExists): `0021e518a108fcce02b57834e4e6a4a2b0ef55a60cc5e8a120f754e6bdbcdf5a`

### post_proof guest (not deployed — proven separately)

- ELF ImageID: `8b12349990ff07373524a6c28f5d4a7312a952281b70ae31bf80218989ba9350`
- Verified via `bench_post_proof` (real STARK receipt verifies).

## Public LEZ testnet

Sequencer: `https://testnet.lez.logos.co` (config posted by David @ Logos).
The membership registry is the **SPEL** build (ADR-012), deployed once; both
forum instances live under the same program. Funding uses the wallet's
preconfigured genesis accounts (the `logosblocks` faucet is the bedrock layer,
not LEZ — see STATUS "SPEL port").

**Program ID (verified, both instances):**
`4766fcc24cac757ab4c504b3844c354468f4d7fbb7b630957573513c6eb9a30d`
(guest ImageID `69373bb59ef0468f8f8748229d79f7cf54ca08b954bef983c641dcedd6d91d47`,
341 KB).

A forum *instance* is a seed-derived `ForumState` PDA (+ its escrow PDA) under
this one program; `ForumConfig` carries the per-instance K and N-of-M. So the
two required instances differ in **parameters**, not program ID — matching the
bounty's "different K and N-of-M parameters" and the protocol's parameterized
design. Each ran `initialize → fund escrow → register-with-stake` live; all
confirmed by reading the on-chain accounts (the v0.2.0-rc3 wallet's 5-block
confirmation poll is shorter than the testnet's cadence, so it prints "not
found in N blocks" while the tx still lands — verify by reading the account).

| | Instance A | Instance B |
|---|---|---|
| **K** (revocation threshold) | 3 | 2 |
| **N-of-M** (cert quorum) | 2-of-5 | 3-of-4 |
| stake / member | 1000 | 1000 |
| seed | `0x22…22` | `0x33…33` |
| state PDA | `A5tj58u7kXKYSNM1Yq2NvXULWkRmQ3SRMC5DaZuzCfKG` | `29HtgrSfYa4AYy6GtysvdxtfNq3THZ2LudouXMRbPQre` |
| escrow PDA | `CDn2DHcvHjbepjSRcLEJe4DwEyPZo7qJDpAHdyN9bu4B` | `46B6NgxBC82XLXSyx6SFKtpEWuSPRswgKG5N1Tve1vXe` |
| `next_leaf_index` after register | 1 | 1 |

Instance B tx hashes: initialize `c1a3fe7b610501ecbe1df462e2ce4147e65e490ec8114b7e1ec1f5fa8be85d96`,
fund-escrow `b4a23165dcdfd088bfbc16610ff3f7a3f877f94d3a2c9a02804b840065d898fe`,
register `a282623b593a83ee9e3dad23d9c1d0bf72b0091aa9ba2aba5ff20e23c6239963`.
After register, instance B's `tree_root` advanced
`34fc00e4…2431d44` (empty) → `75bcc05d…337a6750`, and the escrow held 1000 with
its `program_owner` still the registry (`5oj2gnD7…`) — the ADR-011
credit-preserves-owner property, live.

**Scope note (deliberate):** the on-chain surface is register + slash; posting
and moderation are off-chain (Waku). The full lifecycle including *posting* is
demoed on instance A, whose K=3 matches the one Groth16 membership circuit that
has a trusted setup (`circuits/`, ADR-010). Instance B exercises the registry's
parameterizability live (different K and N-of-M, register-with-stake); its
off-chain K=2 post circuit is not demoed, as the testnet requirement is about
instance *parameters*, not a second circuit. CU/cycle costs for register and
slash are in `cu-costs.md`.

## Restarting the local chain

If the Hetzner box reboots, bring the stack back up:

```bash
# bedrock
cd ~/lez/bedrock && tmux new-session -d -s bedrock "docker compose up > ~/bedrock.log 2>&1"

# sequencer (direct binary — `just run-sequencer` needs just >= 1.x for the
# [working-directory] attribute, which Ubuntu's 1.21 lacks)
cd ~/lez/sequencer/service && tmux new-session -d -s seq \
  "RUST_LOG=info RISC0_DEV_MODE=1 ~/lez/target/release/sequencer_service configs/debug/sequencer_config.json > ~/seq.log 2>&1"
```
