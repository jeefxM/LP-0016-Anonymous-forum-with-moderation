# Running a local LEZ sequencer

The membership_registry program and its integration tests need a running
LEZ stack. We run it on the Hetzner build box (x86_64, where the RISC0
docker builder and the LEZ workspace both compile cleanly). The dev Mac
talks to it over SSH.

## One-time setup

### Prerequisites (Ubuntu)

```bash
apt-get install -y just protobuf-compiler clang libssl-dev pkg-config
```

Plus the Rust + RISC0 toolchains (see `docs/adr/ADR-002`):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.94.0
curl -L https://risczero.com/install | bash
rzup install cargo-risczero 3.0.5
rzup install rust
rzup install cpp
```

### Clone LEZ and install circuits

```bash
git clone https://github.com/logos-blockchain/logos-execution-zone.git lez
cd lez && git checkout 8c8f5b57    # the rev our nssa_core dep is pinned to (ADR-007)

# LEZ's build needs the prebuilt ZK circuits (poc/pol/poq/zksign).
# The setup script lives in the logos-blockchain git dep checkout:
bash ~/.cargo/git/checkouts/logos-blockchain-*/*/scripts/setup-logos-blockchain-circuits.sh
# → installs v0.4.2 to ~/.logos-blockchain-circuits
```

### Build the sequencer + wallet

```bash
cd ~/lez
cargo build --release --bin sequencer_service --bin wallet
# Heavy first build: ~15-25 min on a 16-core box.
```

## Running the stack

LEZ runs three services. For our integration tests we need bedrock
(consensus/DA) + the sequencer; the indexer is optional.

```bash
# Terminal 1 — bedrock node (docker)
cd ~/lez/bedrock && docker compose up

# Terminal 2 — sequencer
cd ~/lez && just run-sequencer
# (RISC0_DEV_MODE=1 by default in the Justfile — fast, fake proofs.
#  For real-proof runs export RISC0_DEV_MODE=0.)
```

## Wallet first-run

```bash
cd ~/lez
just run-wallet check-health
# First run prompts for a password (seed for deterministic keygen).
# We use: forum-protocol-dev
# Expect: ✅All looks good!
```

## Deploying our program

```bash
# Build the guest ELF (docker-based, on the x86_64 box):
cd ~/forum-protocol/programs/membership_registry
cargo risczero build --manifest-path methods/guest/Cargo.toml
# → target/riscv32im-risc0-zkvm-elf/docker/membership_registry.bin

# Deploy:
cd ~/lez
just run-wallet deploy-program \
  ~/forum-protocol/programs/membership_registry/methods/guest/target/riscv32im-risc0-zkvm-elf/docker/membership_registry.bin
```

## Notes

- The dev Mac cannot run `cargo risczero build` (Apple Silicon docker
  fails on the x86_64 risc0-guest-builder image — see ADR-002). All guest
  builds and sequencer runs happen on Hetzner.
- `ruint` must be pinned to 1.17.0 in each guest's lockfile
  (`cargo update -p ruint --precise 1.17.0`) because the risc0 docker
  builder ships rustc 1.88, and ruint 1.18 needs 1.90.
- LEZ `main` was at `8c8f5b57` when we pinned. Bumping it is a one-line
  change to the guest manifests' `nssa_core` rev + an ADR-007 addendum.
