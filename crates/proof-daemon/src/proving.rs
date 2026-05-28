//! Proving handlers — generate and verify anonymous post-proofs using the
//! Groth16 membership circuit (ADR-010). The daemon shells out to `node`
//! (witness generation over the circom wasm), the rapidsnark `prover`
//! (Groth16 proving), and `snarkjs` (Groth16 verification); all artifacts
//! live under `CIRCUIT_DIR`. Proving is ~5s (witness + prove) so it runs on
//! a blocking thread. Each call gets its own tempdir — the read-only zkey is
//! shared, the per-call witness/proof/public files are not.

use std::path::Path;
use std::process::Command;

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD, Engine};
use membership_registry_core::{MerklePath, TREE_DEPTH};
use serde_json::Value;

use crate::dto::{
    b64_decode, enc, parse_hex32, parse_merkle_path, PostEnvelopeDto, ProvePostReq, VerifyPostReq,
    VerifyPostResp,
};
use crate::error::{ApiError, ApiResult, ErrorKind};
use crate::state::{CircuitConfig, SharedState};

/// Public-signal count: nullifier(32) ‖ shareX(32) ‖ shareY(32) (outputs)
/// then treeRoot(32) ‖ epoch(1) ‖ contentId(32) (public inputs).
const N_PUBLIC: usize = 161;
const OFF_NULLIFIER: usize = 0;
const OFF_SHARE_X: usize = 32;
const OFF_SHARE_Y: usize = 64;
const OFF_TREE_ROOT: usize = 96;
const OFF_EPOCH: usize = 128;
const OFF_CONTENT_ID: usize = 129;

/// Produce a `PostEnvelope`: a Groth16 proof of non-revoked membership plus
/// the post-bound Shamir share. The caller supplies the Merkle siblings +
/// path bits (ADR-004 — the daemon doesn't track the tree). The `receipt`
/// field carries `base64(JSON {proof, publicSignals})`.
pub async fn prove_post(
    State(state): State<SharedState>,
    Json(req): Json<ProvePostReq>,
) -> ApiResult<Json<PostEnvelopeDto>> {
    // One zkey per K (ADR-010) — reject a mismatched threshold loudly rather
    // than producing a proof against the wrong circuit.
    if req.k_threshold != state.circuit.k {
        return Err(ApiError::bad_request(format!(
            "kThreshold {} != compiled circuit K {} (no zkey for this K)",
            req.k_threshold, state.circuit.k
        )));
    }

    let secret = parse_hex32(&req.secret, "secret")?;
    let tree_root = parse_hex32(&req.tree_root, "treeRoot")?;
    let content_id = parse_hex32(&req.content_id, "contentId")?;
    let siblings = parse_merkle_path(&req.merkle_siblings, "merkleSiblings")?;
    let epoch = req.epoch;
    let path_bits = req.path_bits;

    let state2 = state.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_prove(
            &state2.circuit,
            &secret,
            &siblings,
            path_bits,
            &tree_root,
            epoch,
            &content_id,
        )
    })
    .await
    .map_err(|e| ApiError::proof(format!("prover task join: {e}")))?
    .map_err(ApiError::proof)?;

    Ok(Json(PostEnvelopeDto {
        content_id: enc(&content_id),
        epoch,
        tree_root: enc(&tree_root),
        nullifier: enc(&out.nullifier),
        share_x: enc(&out.share_x),
        share_y: enc(&out.share_y),
        receipt: out.receipt,
    }))
}

struct ProveOut {
    nullifier: [u8; 32],
    share_x: [u8; 32],
    share_y: [u8; 32],
    receipt: String,
}

/// Blocking: build the circuit input, generate the witness (node + wasm),
/// prove (rapidsnark), and read back the proof + public signals.
fn run_prove(
    circuit: &CircuitConfig,
    secret: &[u8; 32],
    siblings: &MerklePath,
    path_bits: u32,
    tree_root: &[u8; 32],
    epoch: u64,
    content_id: &[u8; 32],
) -> Result<ProveOut, String> {
    let tmp = tempfile::Builder::new()
        .prefix("prove-")
        .tempdir()
        .map_err(|e| format!("tempdir: {e}"))?;
    let input_path = tmp.path().join("input.json");
    let wtns_path = tmp.path().join("witness.wtns");
    let proof_path = tmp.path().join("proof.json");
    let public_path = tmp.path().join("public.json");

    // Inputs as decimal strings (bytes 0..255; pathBits/epoch as full ints).
    let bytes = |b: &[u8; 32]| b.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let input = serde_json::json!({
        "secret": bytes(secret),
        "siblings": siblings.iter().map(|s| bytes(s)).collect::<Vec<_>>(),
        "pathBits": path_bits.to_string(),
        "treeRoot": bytes(tree_root),
        "epoch": epoch.to_string(),
        "contentId": bytes(content_id),
    });
    std::fs::write(&input_path, serde_json::to_vec(&input).unwrap())
        .map_err(|e| format!("write input.json: {e}"))?;

    // 1. witness generation — node resolves witness_calculator.js relative to
    //    generate_witness.js; cwd is the tempdir for the output file.
    run(
        Command::new(&circuit.node_bin)
            .arg(circuit.witness_gen())
            .arg(circuit.wasm())
            .arg(&input_path)
            .arg(&wtns_path)
            .current_dir(tmp.path()),
        "witness generation",
    )?;

    // 2. Groth16 prove (rapidsnark).
    run(
        Command::new(&circuit.prover_bin)
            .arg(circuit.zkey())
            .arg(&wtns_path)
            .arg(&proof_path)
            .arg(&public_path),
        "rapidsnark prover",
    )?;

    let public: Vec<String> = read_json(&public_path)?;
    if public.len() != N_PUBLIC {
        return Err(format!(
            "public.json has {} signals, expected {N_PUBLIC}",
            public.len()
        ));
    }
    let nullifier = signals_to_bytes(&public, OFF_NULLIFIER)?;
    let share_x = signals_to_bytes(&public, OFF_SHARE_X)?;
    let share_y = signals_to_bytes(&public, OFF_SHARE_Y)?;

    // receipt = base64(JSON {proof, publicSignals}); the verifier re-runs
    // snarkjs over exactly these and binds them to the envelope fields.
    let proof: Value = read_json(&proof_path)?;
    let receipt_obj = serde_json::json!({ "proof": proof, "publicSignals": public });
    let receipt = STANDARD.encode(serde_json::to_vec(&receipt_obj).unwrap());

    Ok(ProveOut {
        nullifier,
        share_x,
        share_y,
        receipt,
    })
}

/// Verify a `PostEnvelope`: the Groth16 proof must verify, its public signals
/// must bind byte-for-byte to the envelope (nullifier/shareX/shareY + the
/// treeRoot/epoch/contentId public inputs), and the envelope's root must be
/// the current on-chain root (stale roots are rejected).
///
/// The bind check is load-bearing: snarkjs only attests that *some* public
/// inputs satisfy the proof; without binding them to this envelope, a valid
/// proof could be replayed against a different (root, epoch, contentId).
///
/// Note: a post envelope is anonymous (nullifier + shares, no commitment),
/// so revocation cannot be checked here — it's enforced via root rotation
/// (see docs/protocol.md and ADR-004 consequences).
pub async fn verify_post(
    State(state): State<SharedState>,
    Json(req): Json<VerifyPostReq>,
) -> ApiResult<Json<VerifyPostResp>> {
    let receipt_bytes = b64_decode(&req.envelope.receipt, "receipt")?;
    let receipt: Value = serde_json::from_slice(&receipt_bytes)
        .map_err(|e| ApiError::new(ErrorKind::InvalidProof, format!("receipt json: {e}")))?;
    let proof = receipt
        .get("proof")
        .cloned()
        .ok_or_else(|| ApiError::new(ErrorKind::InvalidProof, "receipt missing proof"))?;
    let public_signals: Vec<Value> = receipt
        .get("publicSignals")
        .and_then(|v| v.as_array())
        .cloned()
        .ok_or_else(|| ApiError::new(ErrorKind::InvalidProof, "receipt missing publicSignals"))?;
    if public_signals.len() != N_PUBLIC {
        return Ok(invalid("publicSignals has wrong length"));
    }

    // Parse the envelope fields the public signals must match.
    let env_nullifier = parse_hex32(&req.envelope.nullifier, "envelope.nullifier")?;
    let env_share_x = parse_hex32(&req.envelope.share_x, "envelope.shareX")?;
    let env_share_y = parse_hex32(&req.envelope.share_y, "envelope.shareY")?;
    let env_tree_root = parse_hex32(&req.envelope.tree_root, "envelope.treeRoot")?;
    let env_content_id = parse_hex32(&req.envelope.content_id, "envelope.contentId")?;
    let env_epoch = req.envelope.epoch;

    let binds_bytes = |off: usize, want: &[u8; 32]| -> bool {
        (0..32).all(|j| sig_u64(&public_signals[off + j]) == Some(want[j] as u64))
    };
    if !(binds_bytes(OFF_NULLIFIER, &env_nullifier)
        && binds_bytes(OFF_SHARE_X, &env_share_x)
        && binds_bytes(OFF_SHARE_Y, &env_share_y)
        && binds_bytes(OFF_TREE_ROOT, &env_tree_root)
        && binds_bytes(OFF_CONTENT_ID, &env_content_id)
        && sig_u64(&public_signals[OFF_EPOCH]) == Some(env_epoch))
    {
        return Ok(invalid("public signals do not bind to the envelope"));
    }

    // Groth16 verify (snarkjs) over the receipt's proof + public signals.
    let state2 = state.clone();
    let public_val = Value::Array(public_signals);
    let verified = tokio::task::spawn_blocking(move || {
        run_verify(&state2.circuit, &proof, &public_val)
    })
    .await
    .map_err(|e| ApiError::proof(format!("verify task join: {e}")))?
    .map_err(ApiError::proof)?;
    if !verified {
        return Ok(invalid("groth16 verification failed"));
    }

    // The envelope's (= the proof's, after the bind check) root must be the
    // current on-chain root.
    let (_pda, s) = state.forum_state(&req.forum_id).await?;
    if env_tree_root != s.tree_root {
        return Ok(invalid("proof targets a stale tree_root"));
    }

    Ok(Json(VerifyPostResp {
        valid: true,
        reason: None,
    }))
}

/// Blocking: write the proof + public signals to a tempdir and run
/// `snarkjs groth16 verify`. Returns Ok(true)/Ok(false) for a clear
/// accept/reject, Err for an unexpected failure.
fn run_verify(circuit: &CircuitConfig, proof: &Value, public: &Value) -> Result<bool, String> {
    let tmp = tempfile::Builder::new()
        .prefix("verify-")
        .tempdir()
        .map_err(|e| format!("tempdir: {e}"))?;
    let proof_path = tmp.path().join("proof.json");
    let public_path = tmp.path().join("public.json");
    std::fs::write(&proof_path, serde_json::to_vec(proof).unwrap())
        .map_err(|e| format!("write proof.json: {e}"))?;
    std::fs::write(&public_path, serde_json::to_vec(public).unwrap())
        .map_err(|e| format!("write public.json: {e}"))?;

    let out = Command::new(&circuit.snarkjs_bin)
        .arg("groth16")
        .arg("verify")
        .arg(circuit.vkey())
        .arg(&public_path)
        .arg(&proof_path)
        .output()
        .map_err(|e| format!("spawn snarkjs ({}): {e}", circuit.snarkjs_bin))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if combined.contains("OK!") {
        Ok(true)
    } else if combined.contains("Invalid proof") {
        Ok(false)
    } else {
        Err(format!("snarkjs verify: unexpected output: {combined}"))
    }
}

// ── helpers ──────────────────────────────────────────────────────────

fn invalid(reason: &str) -> Json<VerifyPostResp> {
    Json(VerifyPostResp {
        valid: false,
        reason: Some(reason.to_string()),
    })
}

/// Run a command, mapping a non-zero exit to an error with captured stderr.
fn run(cmd: &mut Command, what: &str) -> Result<(), String> {
    let out = cmd
        .output()
        .map_err(|e| format!("spawn {what}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{what} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_slice(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// A snarkjs public signal as a u64 (decimal string or JSON number).
fn sig_u64(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

/// 32 byte-valued public signals (each < 256) -> raw bytes.
fn signals_to_bytes(public: &[String], start: usize) -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    for j in 0..32 {
        let v: u64 = public[start + j]
            .parse()
            .map_err(|_| format!("signal {} not an integer", start + j))?;
        if v > 255 {
            return Err(format!("signal {} = {v} is not a byte", start + j));
        }
        b[j] = v as u8;
    }
    Ok(b)
}

// Keep TREE_DEPTH referenced so the parse_merkle_path contract stays in sync
// with the circuit's compiled depth if either changes.
const _: () = assert!(TREE_DEPTH == 16);
