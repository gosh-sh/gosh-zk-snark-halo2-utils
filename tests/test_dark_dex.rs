//! Integration tests for DarkDexCircuitNew using the gosh-zk-snark-halo2-utils keygen/prove/verify flow.
//!
//! Follows the same pattern as test_bk_set_circuit.rs:
//!   keygen → save VK/PK/config/break_points → prove fixture(s) → verify via 3 strategies.
//!
//! Fixtures are loaded from tests/fixtures/dark_dex/.
//!
//! # Running (tests must run sequentially — keygen first, then prove, then verify)
//! ```bash
//! cargo test -p gosh-zk-snark-halo2-utils test_dark_dex_keygen -- --nocapture
//! cargo test -p gosh-zk-snark-halo2-utils test_dark_dex_prove -- --nocapture
//! cargo test -p gosh-zk-snark-halo2-utils test_dark_dex_verify -- --nocapture
//! cargo test -p gosh-zk-snark-halo2-utils test_dark_dex_prove_and_verify_all_fixtures -- --nocapture
//! ```

use std::sync::LazyLock;
use std::time::Instant;

use gosh_dark_dex_halo2_new_circuit::boc_helper::{serialize_cells_tree_root_first, BocFlattenData};
use gosh_dark_dex_halo2_new_circuit::dark_dex_circuit_new::DarkDexCircuitNew;
use gosh_dark_dex_halo2_new_circuit::poseidon::poseidon_hash;

use gosh_dense_balanced_tree::{
    bytes_to_fr, compute_root_native, fr_to_bytes, preprocess_dense_proof, DenseChainLink,
    MAX_CHAIN_LEN,
};
use gosh_zk_snark_halo2_utils::io::{read_break_points, read_vk, save_break_points};
use gosh_zk_snark_halo2_utils::keygen::generate_and_save_keys;
use gosh_zk_snark_halo2_utils::proof::Proof;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::plonk::VerifyingKey;
use halo2_base::utils::fs::gen_srs;
use serde::Deserialize;
use tvm_block::{Deserializable, Message, Serializable};

// ---------------------------------------------------------------------------
// Constants & paths
// ---------------------------------------------------------------------------

const K: u32 = 19;

fn base_circuit_params() -> BaseCircuitParams {
    BaseCircuitParams {
        k: K as usize,
        num_advice_per_phase: vec![4],
        num_fixed: 1,
        num_lookup_advice_per_phase: vec![1],
        lookup_bits: Some(18),
        num_instance_columns: 1,
    }
}

fn dark_dex_keys_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("keys")
}

fn dark_dex_config_params() -> BaseCircuitParams {
    let config_path = dark_dex_keys_dir().join("dark_dex_config_params.json");
    let json = std::fs::read_to_string(&config_path)
        .expect("dark_dex_config_params.json not found. Run test_dark_dex_keygen first.");
    serde_json::from_str(&json).unwrap()
}

fn read_instances_from_file(path: &std::path::Path) -> Vec<Fr> {
    let bytes = std::fs::read(path).unwrap();
    bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut repr = <Fr as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(chunk);
            Fr::from_repr(repr).expect("invalid Fr encoding in instances file")
        })
        .collect()
}

/// Static VK — deserialized once, reused across tests.
static DARK_DEX_VK: LazyLock<VerifyingKey<G1Affine>> = LazyLock::new(|| {
    let vk_bytes = std::fs::read(dark_dex_keys_dir().join("dark_dex_vk.bin"))
        .expect("dark_dex_vk.bin not found. Run test_dark_dex_keygen first.");
    read_vk(&vk_bytes, &dark_dex_config_params())
});

// ---------------------------------------------------------------------------
// JSON fixture structures (mirroring test_real_data.rs)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ChainLinkJson {
    active: bool,
    siblings_hex: Vec<String>,
    position: usize,
    leaf_hex: String,
}

#[derive(Deserialize)]
struct DexFixtureJson {
    #[allow(dead_code)]
    description: String,
    sk_u_hex: String,
    #[serde(default)]
    ephemeral_pubkey_hex: String,
    event_boc_base64: String,
    events_proof_siblings_hex: Vec<String>,
    events_proof_position: usize,
    account_dapp_id_hex: String,
    account_id_hex: String,
    block_id_hex: String,
    envelope_hash_hex: String,
    block_proof_siblings_hex: Vec<String>,
    block_proof_position: usize,
    num_active_chain_steps: usize,
    dense_chain: Vec<ChainLinkJson>,
}

// ---------------------------------------------------------------------------
// Fixture loading & parsing
// ---------------------------------------------------------------------------

fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dark_dex")
}

fn discover_fixtures() -> Vec<std::path::PathBuf> {
    let dir = fixtures_dir();
    if !dir.exists() {
        return vec![];
    }
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("dex_fixture") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    paths
}

fn load_fixture(path: &std::path::Path) -> DexFixtureJson {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse fixture {}: {}", path.display(), e))
}

fn hex_to_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("invalid hex string");
    assert_eq!(
        bytes.len(),
        32,
        "expected 32-byte hex value, got {}",
        bytes.len()
    );
    bytes.try_into().unwrap()
}

fn hex_to_fr(hex_str: &str) -> Fr {
    let bytes = hex_to_32(hex_str);
    Fr::from_repr(bytes).expect("hex value is not a valid Fr element")
}

/// Big-endian byte-to-Fr conversion for BOC field extraction.
fn bytes_to_fr_be(data: &[u8]) -> Fr {
    let mut val = Fr::from(0u64);
    for &byte in data.iter() {
        val = val * Fr::from(256u64) + Fr::from(byte as u64);
    }
    val
}

/// Event field byte offsets in the child cell's cell_repr_data.
const EVENT_SK_U_COMMIT_START: usize = 6;
const EVENT_SK_U_COMMIT_END: usize = 38;
const EVENT_VOUCHER_NOMINAL_START: usize = 38;
const EVENT_VOUCHER_NOMINAL_END: usize = 70;
const EVENT_TOKEN_TYPE_START: usize = 70;
const EVENT_TOKEN_TYPE_END: usize = 74;

struct ParsedFixture {
    sk_u: Fr,
    ephemeral_pubkey: Fr,
    entries: [BocFlattenData; 2],
    events_proof_siblings: Vec<[u8; 32]>,
    events_proof_position: usize,
    account_dapp_id: [u8; 32],
    account_id: [u8; 32],
    block_id: [u8; 32],
    envelope_hash_bytes: [u8; 32],
    block_proof_siblings: Vec<[u8; 32]>,
    block_proof_position: usize,
    dense_chain: Vec<DenseChainLink>,
    num_active_chain_steps: usize,
}

fn parse_fixture(json: &DexFixtureJson) -> ParsedFixture {
    let sk_u = hex_to_fr(&json.sk_u_hex);
    let ephemeral_pubkey = if json.ephemeral_pubkey_hex.is_empty() {
        Fr::from(0u64)
    } else {
        bytes_to_fr_be(&hex_to_32(&json.ephemeral_pubkey_hex))
    };

    let msg = Message::construct_from_base64(&json.event_boc_base64)
        .expect("Failed to parse event BOC");
    let msg_cell = msg.serialize().expect("Failed to serialize message");
    let serialized =
        serialize_cells_tree_root_first(&msg_cell).expect("Failed to flatten BOC");
    assert_eq!(serialized.len(), 2, "Expected exactly 2 cells in event BOC");
    let entries: [BocFlattenData; 2] = [serialized[0].clone(), serialized[1].clone()];

    let events_proof_siblings: Vec<[u8; 32]> = json
        .events_proof_siblings_hex
        .iter()
        .map(|s| hex_to_32(s))
        .collect();

    let block_proof_siblings: Vec<[u8; 32]> = json
        .block_proof_siblings_hex
        .iter()
        .map(|s| hex_to_32(s))
        .collect();

    let mut dense_chain: Vec<DenseChainLink> = json
        .dense_chain
        .iter()
        .map(|link| {
            let siblings: Vec<[u8; 32]> =
                link.siblings_hex.iter().map(|s| hex_to_32(s)).collect();
            DenseChainLink {
                active: link.active,
                siblings,
                position: link.position,
                leaf_native: hex_to_32(&link.leaf_hex),
            }
        })
        .collect();

    assert!(
        dense_chain.len() <= MAX_CHAIN_LEN,
        "Dense chain too long: {} > {}",
        dense_chain.len(),
        MAX_CHAIN_LEN
    );

    if dense_chain.len() < MAX_CHAIN_LEN {
        let repr_hash = &entries[0].repr_hash;
        let ext_msg_leaf = poseidon_hash_96_native(
            &hex_to_32(&json.account_dapp_id_hex),
            &hex_to_32(&json.account_id_hex),
            repr_hash,
        );
        let ext_out_root_bytes = if events_proof_siblings.is_empty() {
            ext_msg_leaf
        } else {
            let events_proof = preprocess_dense_proof(
                ext_msg_leaf,
                &events_proof_siblings,
                json.events_proof_position,
            );
            fr_to_bytes(compute_root_native(&events_proof))
        };
        let block_leaf = poseidon_hash_96_native(
            &hex_to_32(&json.block_id_hex),
            &hex_to_32(&json.envelope_hash_hex),
            &ext_out_root_bytes,
        );
        let block_proof = preprocess_dense_proof(
            block_leaf,
            &block_proof_siblings,
            json.block_proof_position,
        );
        let root_1_fr = compute_root_native(&block_proof);

        let mut current = root_1_fr;
        for link in dense_chain.iter().filter(|l| l.active) {
            let proof = preprocess_dense_proof(link.leaf_native, &link.siblings, link.position);
            current = compute_root_native(&proof);
        }

        let padding_leaf = fr_to_bytes(current);
        let depth = if !dense_chain.is_empty() {
            dense_chain[0].siblings.len()
        } else {
            block_proof_siblings.len()
        };

        while dense_chain.len() < MAX_CHAIN_LEN {
            dense_chain.push(DenseChainLink::inactive(padding_leaf, depth));
        }
    }

    ParsedFixture {
        sk_u,
        ephemeral_pubkey,
        entries,
        events_proof_siblings,
        events_proof_position: json.events_proof_position,
        account_dapp_id: hex_to_32(&json.account_dapp_id_hex),
        account_id: hex_to_32(&json.account_id_hex),
        block_id: hex_to_32(&json.block_id_hex),
        envelope_hash_bytes: hex_to_32(&json.envelope_hash_hex),
        block_proof_siblings,
        block_proof_position: json.block_proof_position,
        dense_chain,
        num_active_chain_steps: json.num_active_chain_steps,
    }
}

// ---------------------------------------------------------------------------
// Instance computation (native)
// ---------------------------------------------------------------------------

/// Native poseidon_hash_96: hash 3 × 32-byte inputs with 31-byte chunking.
fn poseidon_hash_96_native(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(a);
    buf[32..64].copy_from_slice(b);
    buf[64..96].copy_from_slice(c);

    let chunk = |start: usize, len: usize| -> Fr {
        let mut b32 = [0u8; 32];
        b32[..len].copy_from_slice(&buf[start..start + len]);
        bytes_to_fr(&b32)
    };

    let c0 = chunk(0, 31);
    let c1 = chunk(31, 31);
    let c2 = chunk(62, 31);
    let c3 = chunk(93, 3);

    let hash = poseidon_hash(&[c0, c1, c2, c3]);
    fr_to_bytes(hash)
}

/// Compute the five public instances for the circuit:
/// `[poseidon_commitment, final_root, voucher_nominal, token_type, ephemeral_pubkey]`.
fn compute_instances(parsed: &ParsedFixture) -> Vec<Fr> {
    // Instance 1: Poseidon(voucher_nominal, token_type, sk_u, sk_u_commit)
    let child_data = &parsed.entries[1].cell_repr_data;

    let sk_u_commit_bytes: [u8; 32] = child_data[EVENT_SK_U_COMMIT_START..EVENT_SK_U_COMMIT_END]
        .try_into()
        .unwrap();
    let sk_u_commit_val = Fr::from_repr(sk_u_commit_bytes).unwrap();
    let voucher_nominal_val =
        bytes_to_fr_be(&child_data[EVENT_VOUCHER_NOMINAL_START..EVENT_VOUCHER_NOMINAL_END]);
    let token_type_val =
        bytes_to_fr_be(&child_data[EVENT_TOKEN_TYPE_START..EVENT_TOKEN_TYPE_END]);

    let poseidon_commitment =
        poseidon_hash(&[voucher_nominal_val, token_type_val, parsed.sk_u, sk_u_commit_val]);

    // Instance 2: final_root after chain verification
    let repr_hash = &parsed.entries[0].repr_hash;
    let ext_msg_leaf = poseidon_hash_96_native(
        &parsed.account_dapp_id,
        &parsed.account_id,
        repr_hash,
    );

    let ext_out_root_bytes = if parsed.events_proof_siblings.is_empty() {
        ext_msg_leaf
    } else {
        let events_proof = preprocess_dense_proof(
            ext_msg_leaf,
            &parsed.events_proof_siblings,
            parsed.events_proof_position,
        );
        fr_to_bytes(compute_root_native(&events_proof))
    };

    let block_leaf_native = poseidon_hash_96_native(
        &parsed.block_id,
        &parsed.envelope_hash_bytes,
        &ext_out_root_bytes,
    );

    let block_proof = preprocess_dense_proof(
        block_leaf_native,
        &parsed.block_proof_siblings,
        parsed.block_proof_position,
    );
    let root_1_fr = compute_root_native(&block_proof);

    let final_root = if parsed.num_active_chain_steps == 0 {
        root_1_fr
    } else {
        let mut current = root_1_fr;
        for link in parsed
            .dense_chain
            .iter()
            .take(parsed.num_active_chain_steps)
        {
            assert!(link.active);
            let leaf_bytes = fr_to_bytes(current);
            assert_eq!(leaf_bytes, link.leaf_native, "Chain link leaf mismatch");
            let proof =
                preprocess_dense_proof(link.leaf_native, &link.siblings, link.position);
            current = compute_root_native(&proof);
        }
        current
    };

    // Instances 3 & 4: voucher_nominal, token_type, ephemeral_pubkey
    vec![
        poseidon_commitment,
        final_root,
        voucher_nominal_val,
        token_type_val,
        parsed.ephemeral_pubkey,
    ]
}

// ---------------------------------------------------------------------------
// Helper: build circuit from parsed fixture
// ---------------------------------------------------------------------------

fn build_circuit(parsed: ParsedFixture, params: BaseCircuitParams) -> DarkDexCircuitNew {
    DarkDexCircuitNew::new(
        parsed.sk_u,
        parsed.ephemeral_pubkey,
        parsed.entries,
        parsed.events_proof_siblings,
        parsed.events_proof_position,
        parsed.account_dapp_id,
        parsed.account_id,
        parsed.block_id,
        parsed.envelope_hash_bytes,
        parsed.block_proof_siblings,
        parsed.block_proof_position,
        parsed.dense_chain,
        parsed.num_active_chain_steps,
        params,
    )
}

fn build_circuit_for_proving(
    parsed: ParsedFixture,
    params: BaseCircuitParams,
    break_points: Vec<Vec<usize>>,
) -> DarkDexCircuitNew {
    DarkDexCircuitNew::new_for_proving(
        parsed.sk_u,
        parsed.ephemeral_pubkey,
        parsed.entries,
        parsed.events_proof_siblings,
        parsed.events_proof_position,
        parsed.account_dapp_id,
        parsed.account_id,
        parsed.block_id,
        parsed.envelope_hash_bytes,
        parsed.block_proof_siblings,
        parsed.block_proof_position,
        parsed.dense_chain,
        parsed.num_active_chain_steps,
        params,
        break_points,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Keygen: load first fixture → build circuit → generate VK/PK → save keys + break_points.
#[test]
fn test_dark_dex_keygen() {
    let t_total = Instant::now();

    let fixtures = discover_fixtures();
    assert!(
        !fixtures.is_empty(),
        "No fixture files found in {:?}",
        fixtures_dir()
    );

    // 1. Load and parse first fixture.
    let t = Instant::now();
    let json = load_fixture(&fixtures[0]);
    let parsed = parse_fixture(&json);
    println!("[timing] fixture load + parse: {:?}", t.elapsed());

    // 2. Build circuit for keygen.
    let t = Instant::now();
    let params = base_circuit_params();
    let circuit = build_circuit(parsed, params.clone());
    println!("[timing] circuit construction: {:?}", t.elapsed());

    // 3. Generate SRS.
    let t = Instant::now();
    let srs = gen_srs(K);
    println!("[timing] SRS generation: {:?}", t.elapsed());

    // 4. Generate and save keys.
    let keys_dir = dark_dex_keys_dir();
    std::fs::create_dir_all(&keys_dir).unwrap();
    let vk_path = keys_dir.join("dark_dex_vk.bin");
    let pk_path = keys_dir.join("dark_dex_pk.bin");
    let config_path = keys_dir.join("dark_dex_config_params.json");
    let bp_path = keys_dir.join("dark_dex_break_points.bin");

    let t = Instant::now();
    generate_and_save_keys(
        &srs,
        &circuit,
        &params,
        vk_path.to_str().unwrap(),
        pk_path.to_str().unwrap(),
        config_path.to_str().unwrap(),
    );
    println!("[timing] keygen + save: {:?}", t.elapsed());

    // 5. Extract and save break_points.
    let break_points = circuit.base_circuit_builder.borrow().break_points();
    save_break_points(&break_points, bp_path.to_str().unwrap());
    println!(
        "break_points saved: {} phases, {} total points",
        break_points.len(),
        break_points.iter().map(|v| v.len()).sum::<usize>()
    );

    println!("[timing] TOTAL: {:?}", t_total.elapsed());
    println!("dark-dex keygen: PASSED");
}

/// Prove first fixture → save proof + instances → verify + negative test.
///
/// Requires `test_dark_dex_keygen` to have run first.
#[test]
fn test_dark_dex_prove() {
    let t_total = Instant::now();

    let fixtures = discover_fixtures();
    assert!(!fixtures.is_empty(), "No fixture files found");

    let keys_dir = dark_dex_keys_dir();
    let pk_path = keys_dir.join("dark_dex_pk.bin");
    let vk_path = keys_dir.join("dark_dex_vk.bin");
    let config_path = keys_dir.join("dark_dex_config_params.json");
    let bp_path = keys_dir.join("dark_dex_break_points.bin");

    assert!(
        pk_path.exists() && config_path.exists() && bp_path.exists(),
        "Key files not found. Run test_dark_dex_keygen first."
    );

    // 1. Load fixture and compute instances.
    let t = Instant::now();
    let json = load_fixture(&fixtures[0]);
    let parsed = parse_fixture(&json);
    let instances = compute_instances(&parsed);
    println!("[timing] fixture load + parse + instances: {:?}", t.elapsed());
    println!(
        "instances: poseidon={}, final_root={}, voucher_nominal={}, token_type={}, ephemeral_pubkey={}",
        hex::encode(instances[0].to_repr()),
        hex::encode(instances[1].to_repr()),
        hex::encode(instances[2].to_repr()),
        hex::encode(instances[3].to_repr()),
        hex::encode(instances[4].to_repr()),
    );

    // 2. Load break_points and build circuit for proving.
    let t = Instant::now();
    let config_params = dark_dex_config_params();
    let break_points = read_break_points(bp_path.to_str().unwrap());
    let prove_circuit = build_circuit_for_proving(parsed, config_params, break_points);
    println!("[timing] circuit construction (proving): {:?}", t.elapsed());

    // 3. Generate SRS.
    let t = Instant::now();
    let srs = gen_srs(K);
    println!("[timing] SRS generation: {:?}", t.elapsed());

    // 4. Generate proof.
    let t = Instant::now();
    let proof = Proof::create_for_circuit_from_paths(
        &srs,
        pk_path.to_str().unwrap(),
        config_path.to_str().unwrap(),
        prove_circuit,
        &[&instances],
    );
    println!("[timing] proof generation: {:?}", t.elapsed());
    println!("proof size: {} bytes", proof.as_bytes().len());

    // 5. Save proof and instances.
    let proof_path = keys_dir.join("dark_dex_proof.bin");
    let instances_path = keys_dir.join("dark_dex_instances.bin");
    std::fs::write(&proof_path, proof.as_bytes()).unwrap();
    let instances_bytes: Vec<u8> = instances
        .iter()
        .flat_map(|f| f.to_repr().as_ref().to_vec())
        .collect();
    std::fs::write(&instances_path, &instances_bytes).unwrap();
    println!("proof saved to {:?}", proof_path);
    println!(
        "instances saved: {} field elements ({} bytes)",
        instances.len(),
        instances_bytes.len()
    );

    // 6. Verify proof — should pass.
    let t = Instant::now();
    let valid = proof.verify_with_vk_from_path(
        vk_path.to_str().unwrap(),
        &srs,
        config_path.to_str().unwrap(),
        &[&instances],
    );
    println!("[timing] proof verification: {:?}", t.elapsed());
    assert!(valid, "Proof verification should pass with correct instances");

    // 7. Negative test: wrong instances should fail.
    let wrong_instances = vec![
        Fr::from(42u64),
        Fr::from(99u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    ];
    let invalid = proof.verify_with_vk_from_path(
        vk_path.to_str().unwrap(),
        &srs,
        config_path.to_str().unwrap(),
        &[&wrong_instances],
    );
    assert!(
        !invalid,
        "Proof verification should fail with wrong instances"
    );

    println!("[timing] TOTAL: {:?}", t_total.elapsed());
    println!("dark-dex prove: PASSED");
}

/// Verify a previously saved proof by reading proof + VK from files.
///
/// Requires `test_dark_dex_prove` to have run first.
#[test]
fn test_dark_dex_verify_from_files() {
    let t_total = Instant::now();

    let keys_dir = dark_dex_keys_dir();
    let vk_path = keys_dir.join("dark_dex_vk.bin");
    let proof_path = keys_dir.join("dark_dex_proof.bin");
    let config_path = keys_dir.join("dark_dex_config_params.json");
    let instances_path = keys_dir.join("dark_dex_instances.bin");

    assert!(
        vk_path.exists()
            && proof_path.exists()
            && config_path.exists()
            && instances_path.exists(),
        "Key/proof/instances files not found. Run test_dark_dex_prove first."
    );

    // 1. Read proof from file.
    let t = Instant::now();
    let proof = Proof::new(std::fs::read(&proof_path).unwrap());
    println!("[timing] proof read from file: {:?}", t.elapsed());
    println!("proof size: {} bytes", proof.as_bytes().len());

    // 2. Read public instances from file.
    let t = Instant::now();
    let instances = read_instances_from_file(&instances_path);
    println!("[timing] instances read from file: {:?}", t.elapsed());
    println!("instances: {} field elements", instances.len());

    // 3. Generate SRS.
    let t = Instant::now();
    let srs = gen_srs(K);
    println!("[timing] SRS generation: {:?}", t.elapsed());

    // 4. Verify proof using VK from file.
    let t = Instant::now();
    let valid = proof.verify_with_vk_from_path(
        vk_path.to_str().unwrap(),
        &srs,
        config_path.to_str().unwrap(),
        &[&instances],
    );
    println!(
        "[timing] proof verification (from files): {:?}",
        t.elapsed()
    );
    assert!(valid, "Proof verification from files should pass");

    println!("[timing] TOTAL: {:?}", t_total.elapsed());
    println!("dark-dex verify-from-files: PASSED");
}

/// VK deserialized from bytes each call (uses verify_with_vk_from_bytes).
///
/// Requires `test_dark_dex_prove` to have run first.
#[test]
fn test_dark_dex_verify_with_vk_bytes() {
    let t_total = Instant::now();

    let keys_dir = dark_dex_keys_dir();
    let vk_path = keys_dir.join("dark_dex_vk.bin");
    let proof_path = keys_dir.join("dark_dex_proof.bin");
    let instances_path = keys_dir.join("dark_dex_instances.bin");

    assert!(
        vk_path.exists() && proof_path.exists() && instances_path.exists(),
        "Key/proof/instances files not found. Run test_dark_dex_prove first."
    );

    // 1. Read proof from file.
    let t = Instant::now();
    let proof = Proof::new(std::fs::read(&proof_path).unwrap());
    println!("[timing] proof read from file: {:?}", t.elapsed());

    // 2. Read public instances from file.
    let t = Instant::now();
    let instances = read_instances_from_file(&instances_path);
    println!("[timing] instances read from file: {:?}", t.elapsed());

    // 3. Generate SRS.
    let t = Instant::now();
    let srs = gen_srs(K);
    println!("[timing] SRS generation: {:?}", t.elapsed());

    // 4. Read VK bytes and verify.
    let t = Instant::now();
    let vk_bytes = std::fs::read(&vk_path).unwrap();
    println!("[timing] VK read from file: {:?}", t.elapsed());

    let t = Instant::now();
    let config_params: BaseCircuitParams = dark_dex_config_params();
    let valid = proof.verify_with_vk_from_bytes(&vk_bytes, &srs, &config_params, &[&instances]);
    println!(
        "[timing] proof verification (VK from bytes, includes deserialization): {:?}",
        t.elapsed()
    );
    assert!(valid, "Proof verification with VK from bytes should pass");

    println!("[timing] TOTAL: {:?}", t_total.elapsed());
    println!("dark-dex verify-with-vk-bytes: PASSED");
}

/// VK is a static object (deserialized once via LazyLock).
///
/// Requires `test_dark_dex_prove` to have run first.
#[test]
fn test_dark_dex_verify_with_static_vk() {
    let t_total = Instant::now();

    let keys_dir = dark_dex_keys_dir();
    let proof_path = keys_dir.join("dark_dex_proof.bin");
    let instances_path = keys_dir.join("dark_dex_instances.bin");

    assert!(
        proof_path.exists() && instances_path.exists(),
        "Proof/instances files not found. Run test_dark_dex_prove first."
    );

    // 1. Read proof from file.
    let t = Instant::now();
    let proof = Proof::new(std::fs::read(&proof_path).unwrap());
    println!("[timing] proof read from file: {:?}", t.elapsed());

    // 2. Read public instances from file.
    let t = Instant::now();
    let instances = read_instances_from_file(&instances_path);
    println!("[timing] instances read from file: {:?}", t.elapsed());

    // 3. Generate SRS.
    let t = Instant::now();
    let srs = gen_srs(K);
    println!("[timing] SRS generation: {:?}", t.elapsed());

    // 4. Force LazyLock init.
    let t = Instant::now();
    let vk: &VerifyingKey<G1Affine> = &DARK_DEX_VK;
    println!(
        "[timing] VK LazyLock init (deserialization, once): {:?}",
        t.elapsed()
    );

    // 5. Verify proof — VK already deserialized.
    let t = Instant::now();
    let valid = proof.verify_with_vk(vk, &srs, &[&instances]);
    println!(
        "[timing] proof verification (static VK, no deserialization): {:?}",
        t.elapsed()
    );
    assert!(valid, "Proof verification with static VK should pass");

    println!("[timing] TOTAL: {:?}", t_total.elapsed());
    println!("dark-dex verify-with-static-vk: PASSED");
}

/// Prove and verify all fixtures with a shared VK/PK.
///
/// Requires `test_dark_dex_keygen` to have run first.
#[test]
fn test_dark_dex_prove_and_verify_all_fixtures() {
    let t_total: Instant = Instant::now();

    let fixtures = discover_fixtures();
    assert!(!fixtures.is_empty(), "No fixture files found");
    println!("Found {} fixture(s)", fixtures.len());

    let keys_dir = dark_dex_keys_dir();
    let pk_path = keys_dir.join("dark_dex_pk.bin");
    let vk_path = keys_dir.join("dark_dex_vk.bin");
    let config_path = keys_dir.join("dark_dex_config_params.json");
    let bp_path = keys_dir.join("dark_dex_break_points.bin");

    assert!(
        pk_path.exists() && config_path.exists() && bp_path.exists(),
        "Key files not found. Run test_dark_dex_keygen first."
    );

    let srs = gen_srs(K);
    let config_params = dark_dex_config_params();
    let saved_break_points = read_break_points(bp_path.to_str().unwrap());

    struct ProofResult {
        filename: String,
        chain_steps: usize,
        prove_ms: u128,
        verify_ms: u128,
        proof_size: usize,
    }
    let mut results: Vec<ProofResult> = Vec::new();

    for fixture_path in &fixtures {
        let filename = fixture_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let stem = fixture_path
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        println!("\n========== {} ==========", filename);

        let json = load_fixture(fixture_path);
        let chain_steps = json.num_active_chain_steps;
        println!("  chain_steps: {}", chain_steps);

        let parsed = parse_fixture(&json);
        let instances = compute_instances(&parsed);

        // Build circuit for proving.
        let prove_circuit =
            build_circuit_for_proving(parsed, config_params.clone(), saved_break_points.clone());

        // Generate proof.
        let t = Instant::now();
        let proof = Proof::create_for_circuit_from_paths(
            &srs,
            pk_path.to_str().unwrap(),
            config_path.to_str().unwrap(),
            prove_circuit,
            &[&instances],
        );
        let prove_ms = t.elapsed().as_millis();
        println!(
            "  proof generation: {}ms ({} bytes)",
            prove_ms,
            proof.as_bytes().len()
        );

        // Save proof and instances for this fixture.
        let fix_proof_path = keys_dir.join(format!("dark_dex_all_{}_proof.bin", stem));
        let fix_instances_path = keys_dir.join(format!("dark_dex_all_{}_instances.bin", stem));
        std::fs::write(&fix_proof_path, proof.as_bytes()).unwrap();
        let instances_bytes: Vec<u8> = instances
            .iter()
            .flat_map(|f| f.to_repr().as_ref().to_vec())
            .collect();
        std::fs::write(&fix_instances_path, &instances_bytes).unwrap();

        // Verify: strategy 1 — VK from file path.
        let t = Instant::now();
        let valid = proof.verify_with_vk_from_path(
            vk_path.to_str().unwrap(),
            &srs,
            config_path.to_str().unwrap(),
            &[&instances],
        );
        let verify_ms = t.elapsed().as_millis();
        assert!(valid, "Verification failed for {}", filename);

        // Verify: strategy 2 — VK from bytes.
        let vk_bytes = std::fs::read(&vk_path).unwrap();
        let valid2 =
            proof.verify_with_vk_from_bytes(&vk_bytes, &srs, &config_params, &[&instances]);
        assert!(valid2, "VK-from-bytes verification failed for {}", filename);

        // Verify: strategy 3 — static VK.
        let valid3 = proof.verify_with_vk(&DARK_DEX_VK, &srs, &[&instances]);
        assert!(valid3, "Static VK verification failed for {}", filename);

        println!("  {} PASSED (all 3 verification strategies)", filename);

        results.push(ProofResult {
            filename,
            chain_steps,
            prove_ms,
            verify_ms,
            proof_size: proof.as_bytes().len(),
        });
    }

    // Print summary table.
    println!("\n╔════════════════════════════════════════════╤════════╤══════════╤══════════╤════════════╗");
    println!(
        "║ fixture                                    │ steps  │  prove   │  verify  │ proof_size ║"
    );
    println!("╠════════════════════════════════════════════╪════════╪══════════╪══════════╪════════════╣");
    for r in &results {
        println!(
            "║ {:<42} │   {:>2}   │ {:>6}ms │ {:>6}ms │   {:>6}B  ║",
            r.filename, r.chain_steps, r.prove_ms, r.verify_ms, r.proof_size,
        );
    }
    println!("╚════════════════════════════════════════════╧════════╧══════════╧══════════╧════════════╝");
    println!(
        "\nAll {} fixture(s) passed with shared VK/PK!",
        results.len()
    );
    println!("[timing] TOTAL: {:?}", t_total.elapsed());
}
