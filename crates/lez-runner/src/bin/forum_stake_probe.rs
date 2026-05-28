//! Read-only staking pre-flight (ADR-011). Verifies the environment before
//! the multi-tx e2e so any failure is localized to one cheap step:
//!   - the system program ids resolve,
//!   - the faucet PDA exists and holds native supply,
//!   - `get_accounts_nonces` behaves for a never-touched account,
//!   - escrow derivation matches the guest (pass the guest .bin as arg).
//!
//! Run on Hetzner:
//!   NSSA_WALLET_HOME_DIR=~/lez/wallet/configs/debug \
//!     cargo run --release --bin forum_stake_probe -- [membership_registry.bin]

use std::str::FromStr;

use anyhow::{anyhow, Result};
use lez_runner::{
    account_of, balance_of, escrow_for_state, faucet_pda, load_program, pda_for_seed,
    random_keypair, vault_for, AccountId, Program, WalletCore,
};
use sequencer_service_rpc::RpcClient as _;

#[tokio::main]
async fn main() -> Result<()> {
    let wallet_core = WalletCore::from_env().map_err(|e| anyhow!("wallet from_env: {e:?}"))?;

    // Block-production heartbeat: tip must advance.
    let b0 = wallet_core.sequencer_client.get_last_block_id().await;
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
    let b1 = wallet_core.sequencer_client.get_last_block_id().await;
    println!("== block tip ==\n  t0={b0:?}\n  t1={b1:?}  (advanced: {})", {
        match (&b0, &b1) {
            (Ok(a), Ok(b)) => format!("{}", a != b),
            _ => "unknown".to_string(),
        }
    });

    // Query any account ids passed as base58 args (e.g. a failed run's PDAs).
    for arg in std::env::args().skip(1) {
        if let Ok(id) = AccountId::from_str(&arg) {
            match account_of(&wallet_core, id).await {
                Ok(a) => println!(
                    "== account {arg} ==\n  balance={} owner={:?} data_len={}",
                    a.balance,
                    a.program_owner,
                    a.data.as_ref().len()
                ),
                Err(e) => println!("== account {arg} ==\n  not on chain: {e}"),
            }
        }
    }

    println!("== sequencer-known program ids ==");
    match wallet_core.sequencer_client.get_program_ids().await {
        Ok(m) => {
            for (name, id) in &m {
                println!("  {name} = {id:?}");
            }
        }
        Err(e) => println!("  get_program_ids errored: {e}"),
    }

    println!("== system program ids ==");
    println!("  faucet   = {:?}", Program::faucet().id());
    println!("  vault    = {:?}", Program::vault().id());
    println!(
        "  authxfer = {:?}",
        Program::authenticated_transfer_program().id()
    );

    let faucet = faucet_pda();
    println!("\n== faucet PDA ==\n  {faucet}");
    match account_of(&wallet_core, faucet).await {
        Ok(a) => println!("  balance = {}  owner = {:?}", a.balance, a.program_owner),
        Err(e) => println!("  NOT on chain / read failed: {e}"),
    }

    let (_sk, fresh) = random_keypair();
    println!("\n== fresh account nonce probe ==\n  {fresh}");
    match wallet_core.get_accounts_nonces(vec![fresh]).await {
        Ok(n) => println!("  get_accounts_nonces -> {n:?}"),
        Err(e) => println!("  get_accounts_nonces errored: {e}"),
    }
    println!("  balance = {}", balance_of(&wallet_core, fresh).await);
    println!("  vault   = {}", vault_for(fresh));

    if let Some(path) = std::env::args().skip(1).find(|a| std::path::Path::new(a).is_file()) {
        let program = load_program(&path)?;
        let seed = [7u8; 32];
        let state = pda_for_seed(&program, seed);
        let escrow = escrow_for_state(&program, &state);
        println!("\n== escrow derivation (seed=[7;32]) ==");
        println!("  program = {:?}", program.id());
        println!("  state   = {state}");
        println!("  escrow  = {escrow}");
    }

    println!("\nprobe OK");
    Ok(())
}
