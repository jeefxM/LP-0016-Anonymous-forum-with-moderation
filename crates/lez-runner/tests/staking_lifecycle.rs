//! Full staking lifecycle (ADR-011) against the LEZ execution engine, in
//! process via `nssa::V03State`. This is the faithful e2e for "register with
//! a stake" / "slash claims the stake": the same risc0-executed guest the
//! sequencer runs, the same `authenticated_transfer` value movement, the same
//! validate_execution rules — but deterministic, fast, and CI-able.
//!
//! Why not a live single-node run: the LEZ faucet is genesis-only (user faucet
//! txs are dropped by design — see LEZ's `cannot_execute_faucet_program`), and
//! the local chain exposes no other runtime funding. `V03State` lets us seed a
//! funded member directly (genesis), which is exactly what a real testnet
//! faucet would do, then exercise the real engine.
//!
//! Needs the built guest ELF. Set FORUM_REGISTRY_BIN, or it falls back to the
//! docker build output path. Run on Hetzner (x86 + the ELF):
//!   RISC0_DEV_MODE=1 cargo test --release --test staking_lifecycle -- --nocapture

use authenticated_transfer_core::Instruction as AuthTransferInstruction;
use ed25519_dalek::SigningKey;
use lez_runner::{decode_state, escrow_for_state, pda_for_seed};
use membership_registry_core::{ForumConfig, Instruction, MerklePath, TREE_DEPTH};
use moderation_cert::sign_vote;
use nssa::{
    program::Program,
    program_deployment_transaction,
    public_transaction::{Message, WitnessSet},
    AccountId, PrivateKey, ProgramDeploymentTransaction, PublicKey, PublicTransaction, V03State,
};
use nssa_core::{account::Nonce, program::ProgramId};
use post_proof_core::shamir;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use slash_evidence::build_slash_payload;

const K: u8 = 3;
const N: u8 = 2;
const M: usize = 5;
const STAKE: u128 = 1_000;

fn guest_bin_path() -> String {
    std::env::var("FORUM_REGISTRY_BIN").unwrap_or_else(|_| {
        format!(
            "{}/../../programs/membership_registry/methods/guest/target/\
             riscv32im-risc0-zkvm-elf/docker/membership_registry.bin",
            env!("CARGO_MANIFEST_DIR")
        )
    })
}

fn keypair() -> (PrivateKey, AccountId) {
    use rand::RngCore;
    let mut rng = OsRng;
    loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        if let Ok(sk) = PrivateKey::try_new(b) {
            let id = AccountId::from(&PublicKey::new_from_private_key(&sk));
            return (sk, id);
        }
    }
}

/// Build a public tx. Empty `signers` => no-auth (program-owned PDAs); else one
/// nonce per signer (each signer here signs at most once, starting at nonce 0).
fn tx<T: serde::Serialize>(
    program_id: ProgramId,
    accounts: Vec<AccountId>,
    signers: &[&PrivateKey],
    instruction: T,
) -> PublicTransaction {
    let nonces = vec![Nonce(0); signers.len()];
    let message = Message::try_new(program_id, accounts, nonces, instruction).expect("message");
    let witness = WitnessSet::for_message(&message, signers);
    PublicTransaction::new(message, witness)
}

fn commitment_of(secret: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"commit");
    h.update(secret);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..]);
    out
}

#[test]
fn valid_staking_lifecycle() {
    // Both are seeded with a spendable (authenticated_transfer-owned) balance
    // at genesis — what a faucet/testnet would provide. The slasher must be an
    // existing account: crediting a fresh default-owned account without a claim
    // is rejected (DefaultAccountModifiedWithoutClaim), and the slasher does
    // not sign the no-auth Slash tx so it cannot self-claim. In practice the
    // slasher is a real participant (a moderator/treasury) that already exists.
    let (member_sk, member) = keypair();
    let (_slasher_sk, slasher) = keypair();
    let slasher_seed_balance: u128 = 1;
    let mut state = V03State::new_with_genesis_accounts(
        &[(member, STAKE * 2), (slasher, slasher_seed_balance)],
        vec![],
        0,
    );

    // Deploy the membership_registry guest (the real risc0 ELF).
    let bytecode = std::fs::read(guest_bin_path()).expect("read guest ELF");
    let program = Program::new(bytecode.clone()).expect("valid program binary");
    let registry_id = program.id();
    let deploy = ProgramDeploymentTransaction::new(program_deployment_transaction::Message::new(
        bytecode,
    ));
    state
        .transition_from_program_deployment_transaction(&deploy)
        .expect("deploy membership_registry");

    let mut block: u64 = 1;
    let mut step = |state: &mut V03State, tx: &PublicTransaction| {
        state
            .transition_from_public_transaction(tx, block.into(), 0)
            .unwrap_or_else(|e| panic!("tx at block {block} rejected: {e:?}"));
        block += 1;
    };

    // ── Initialize: claims the state PDA + the registry-owned escrow PDA ──
    let seed = [7u8; 32];
    let pda = pda_for_seed(&program, seed);
    let escrow = escrow_for_state(&program, &pda);

    let mut mod_rng = OsRng;
    let mod_secrets: Vec<SigningKey> = (0..M).map(|_| SigningKey::generate(&mut mod_rng)).collect();
    let mod_pubs: Vec<[u8; 32]> = mod_secrets
        .iter()
        .map(|s| s.verifying_key().to_bytes())
        .collect();
    let config = ForumConfig {
        k_threshold: K,
        n_threshold: N,
        moderators: mod_pubs.clone(),
        stake_amount: STAKE,
    };
    step(
        &mut state,
        &tx(
            registry_id,
            vec![pda, escrow],
            &[],
            Instruction::Initialize { config, seed },
        ),
    );
    let escrow0 = state.get_account_by_id(escrow);
    assert_eq!(
        escrow0.program_owner, registry_id,
        "escrow claimed by registry at Initialize"
    );
    assert_eq!(escrow0.balance, 0, "escrow starts empty");

    // ── Stake: member signs an authenticated_transfer into the escrow ────
    step(
        &mut state,
        &tx(
            Program::authenticated_transfer_program().id(),
            vec![member, escrow],
            &[&member_sk],
            AuthTransferInstruction::Transfer { amount: STAKE },
        ),
    );
    let escrow1 = state.get_account_by_id(escrow);
    assert_eq!(escrow1.balance, STAKE, "escrow funded by the member's stake");
    assert_eq!(
        escrow1.program_owner, registry_id,
        "crediting the escrow preserves registry ownership (slash-debit legality)"
    );
    assert_eq!(
        state.get_account_by_id(member).balance,
        STAKE,
        "member's spendable balance dropped by the stake"
    );

    // ── Register member A (the guest's stake check passes only when funded) ─
    let mut secret = [0u8; 32];
    secret[..16].copy_from_slice(&[0xA5u8; 16]);
    let commitment = commitment_of(&secret);
    let empty_path: MerklePath = [[0u8; 32]; TREE_DEPTH];
    step(
        &mut state,
        &tx(
            registry_id,
            vec![pda, escrow],
            &[],
            Instruction::Register {
                commitment,
                path_before: empty_path,
                leaf_index: 0,
            },
        ),
    );
    let state1 = decode_state(state.get_account_by_id(pda).data.as_ref()).expect("decode state");
    assert_eq!(state1.next_leaf_index, 1, "member A registered at leaf 0");

    // ── K strikes; N moderators sign a cert over each post's Shamir share ─
    let content_ids = [[11u8; 32], [22u8; 32], [33u8; 32]];
    let certs: Vec<_> = content_ids
        .iter()
        .enumerate()
        .map(|(i, cid)| {
            let (x_fr, y_fr) = shamir::compute_share(&secret, K as usize, cid);
            let votes: Vec<_> = mod_secrets
                .iter()
                .take(N as usize)
                .map(|sk| {
                    sign_vote(
                        sk,
                        *cid,
                        i as u8,
                        shamir::fr_to_bytes(&x_fr),
                        shamir::fr_to_bytes(&y_fr),
                    )
                })
                .collect();
            moderation_cert::aggregate(&votes, N).expect("aggregate")
        })
        .collect();
    let payload =
        build_slash_payload(&certs, &mod_pubs, N, K, state1.tree_root, 0, empty_path, &[])
            .expect("off-chain slash payload");
    assert_eq!(payload.commitment, commitment, "reconstructed commitment matches");

    // ── Slash: revoke member A and pay the stake out of the escrow ───────
    step(
        &mut state,
        &tx(
            registry_id,
            vec![pda, escrow, slasher],
            &[],
            Instruction::Slash {
                reconstructed_secret: payload.reconstructed_secret,
                certificates: payload.certificates,
                leaf_index: 0,
                merkle_path: empty_path,
            },
        ),
    );

    let state2 = decode_state(state.get_account_by_id(pda).data.as_ref()).expect("decode state");
    assert!(
        state2.revocation_set.contains(&commitment),
        "member A revoked"
    );
    assert!(
        state2.revoked_secrets.contains(&secret),
        "member A's secret published for retroactive deanonymization"
    );
    assert_eq!(
        state.get_account_by_id(escrow).balance,
        0,
        "escrow drained by the stake claim"
    );
    assert_eq!(
        state.get_account_by_id(slasher).balance,
        slasher_seed_balance + STAKE,
        "slasher received the staked amount"
    );
}
