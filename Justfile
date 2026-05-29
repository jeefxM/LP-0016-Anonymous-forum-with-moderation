set shell := ["bash", "-euo", "pipefail", "-c"]

# Show available targets
default:
    @just --list

# Install JS deps
install:
    pnpm install

# Build everything (Rust + TS)
build:
    cargo build --workspace --release
    pnpm -r build

# Build RISC0 guest programs (slow — separate target)
build-guests:
    @echo "🔨 Building RISC0 guest programs"
    cargo risczero build --manifest-path programs/post_proof/methods/guest/Cargo.toml
    cargo risczero build --manifest-path programs/membership_registry/methods/guest/Cargo.toml

# Run all tests
test:
    cargo test --workspace --no-fail-fast
    pnpm test

# Lint everything
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo fmt --all -- --check
    pnpm lint

# Format everything
fmt:
    cargo fmt --all
    pnpm format

# Run the demo app dev server
dev:
    pnpm --filter app dev

# End-to-end demo: full lifecycle with real proofs (sequencer RISC0_DEV_MODE=0
# + Groth16 membership proof). Backend must be up first; see
# docs/deployments.md and app/README.md. Pass the nwaku /ws multiaddr via env:
#   NWAKU_PEER=/ip4/127.0.0.1/tcp/8000/ws/p2p/<peerId> just demo
demo:
    pnpm --filter @logos-forum/moderation-sdk build
    node scripts/demo.mjs

# Wipe build artifacts
clean:
    cargo clean
    rm -rf node_modules **/node_modules **/dist **/.next
