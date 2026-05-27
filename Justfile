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

# End-to-end demo with production RISC0 (bounty-required)
demo:
    @echo "🎬 Demo lands in P9"
    @false

# Wipe build artifacts
clean:
    cargo clean
    rm -rf node_modules **/node_modules **/dist **/.next
