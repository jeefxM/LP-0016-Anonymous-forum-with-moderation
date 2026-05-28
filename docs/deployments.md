# Deployments

## Local dev chain (Hetzner)

A full LEZ stack runs on the Hetzner build box for integration testing.

| Component | Status | Detail |
|---|---|---|
| Bedrock node | ✅ running | tmux session `bedrock`, docker compose, RPC :8080, producing blocks |
| Sequencer | ✅ running | tmux session `seq`, RPC :3040, `RISC0_DEV_MODE=1` |
| Wallet | ✅ initialised | `~/lez/wallet/configs/debug`, password `forum-protocol-dev` |
| `membership_registry` program | ✅ **deployed** | first deploy block created; re-deploy returns `ProgramAlreadyExists` (confirms on-chain) |

### membership_registry guest

- ELF: `~/forum-protocol/programs/membership_registry/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/membership_registry.bin`
- ImageID: `a7676642b321d4f9d2bbd63fba4158446c20d69bc925a44fe48aa5806d421f80`
- Deploy tx hash (first, succeeded): see seq.log block 4
- Re-deploy tx hash (rejected ProgramAlreadyExists): `0021e518a108fcce02b57834e4e6a4a2b0ef55a60cc5e8a120f754e6bdbcdf5a`

### post_proof guest (not deployed — proven separately)

- ELF ImageID: `8b12349990ff07373524a6c28f5d4a7312a952281b70ae31bf80218989ba9350`
- Verified via `bench_post_proof` (real STARK receipt verifies).

## Public LEZ testnet

Not yet deployed. The bounty requires two live instances with different
K and N-of-M parameters. Blocked on obtaining a public testnet endpoint +
faucet from the Logos team. Tracked separately.

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
