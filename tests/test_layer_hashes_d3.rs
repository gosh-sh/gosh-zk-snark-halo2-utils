/*mod common;

use std::collections::HashMap;
use std::time::Instant;

use gosh_dense_balanced_tree::{bytes_to_fr, DenseChainLink, MAX_CHAIN_LEN};
use layer_hashes_update_halo2_circuit::primary_circuit::helpers::CircuitTestInput;
use layer_hashes_update_halo2_circuit::{FIRST_ROOT_HASH_OFFSET, MAX_LAYERS};

// ---------------------------------------------------------------------------
// Fixture loading (depth=3 real data)
// ---------------------------------------------------------------------------

const FIXTURES_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/layer_hashes"
);

/// The fixture used for keygen (any fixture works; we pick one for determinism).
const KEYGEN_FIXTURE: &str = "circuit_test_data_L5_H12288_prevH1024_S11.json";

fn keygen_fixture_path() -> std::path::PathBuf {
    std::path::Path::new(FIXTURES_DIR).join(KEYGEN_FIXTURE)
}

/// Collect all `circuit_test_data_*.json` fixture paths, sorted for determinism.
fn all_fixture_paths() -> Vec<std::path::PathBuf> {
    let dir = std::path::Path::new(FIXTURES_DIR);
    assert!(dir.is_dir(), "Fixtures dir not found: {FIXTURES_DIR}");
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            if p.extension().map_or(false, |ext| ext == "json")
                && p.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("circuit_test_data_")
            {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "No circuit_test_data_*.json fixtures found in {FIXTURES_DIR}");
    paths
}

#[derive(serde::Deserialize)]
struct ChainLinkJson {
    active: bool,
    siblings_hex: Vec<String>,
    position: usize,
    leaf_hex: String,
}

#[derive(serde::Deserialize)]
struct CircuitFixtureJson {
    block_envelope_hex: String,
    attestation_hex: String,
    bk_set: HashMap<String, String>,
    num_layers: usize,
    layer_hash_byte_offsets: Vec<usize>,
    root_hashes_hex: Vec<String>,
    prev_max_level_layer_hash_hex: String,
    num_prev_chain_steps: usize,
    prev_chain_proofs: Vec<ChainLinkJson>,
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex::decode(s).unwrap_or_else(|_| panic!("invalid hex: {s}"));
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

fn load_fixture(path: &std::path::Path) -> CircuitTestInput {
    let json_str = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let f: CircuitFixtureJson = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));

    let block_data = hex::decode(&f.block_envelope_hex).expect("invalid block_envelope_hex");
    let attestation = hex::decode(&f.attestation_hex).expect("invalid attestation_hex");

    let bk_set: HashMap<u16, Vec<u8>> = f
        .bk_set
        .iter()
        .map(|(k, v)| {
            let idx: u16 = k.parse().expect("bk_set key must be u16");
            (idx, hex::decode(v).expect("invalid pubkey hex"))
        })
        .collect();

    let root_hashes: Vec<[u8; 32]> = f.root_hashes_hex.iter().map(|s| hex_to_32(s)).collect();

    assert!(f.num_layers >= 1, "num_layers must be >= 1 to derive history_proofs_byte_offset");
    let first_offset = f.layer_hash_byte_offsets[0];
    assert!(first_offset >= FIRST_ROOT_HASH_OFFSET, "first layer_hash_byte_offset {} is too small", first_offset);
    let history_proofs_byte_offset = first_offset - FIRST_ROOT_HASH_OFFSET;

    let prev_chain_proofs: Vec<DenseChainLink> = f
        .prev_chain_proofs
        .iter()
        .map(|link| DenseChainLink {
            active: link.active,
            siblings: link.siblings_hex.iter().map(|s| hex_to_32(s)).collect(),
            position: link.position,
            leaf_native: hex_to_32(&link.leaf_hex),
        })
        .collect();

    assert_eq!(root_hashes.len(), MAX_LAYERS);
    assert_eq!(f.layer_hash_byte_offsets.len(), MAX_LAYERS);
    assert_eq!(prev_chain_proofs.len(), MAX_CHAIN_LEN);

    CircuitTestInput {
        block_data,
        attestation,
        bk_set,
        history_proofs_byte_offset,
        root_hashes,
        num_layers: f.num_layers,
        prev_max_level_layer_hash: bytes_to_fr(&hex_to_32(&f.prev_max_level_layer_hash_hex)),
        num_prev_chain_steps: f.num_prev_chain_steps,
        prev_chain_proofs,
    }
}

// ===========================================================================
// Depth=3 tests (real fixture data)
// ===========================================================================

/// Generate VK/PK/config for depth=3 circuits using real fixture data.
#[test]
fn test_layer_hashes_keygen_d3() {
    let t_total = Instant::now();

    let path = keygen_fixture_path();
    assert!(path.exists(), "Fixture not found: {}. Keygen requires the real data fixture.", path.display());

    let t = Instant::now();
    let input = load_fixture(&path);
    println!("[timing] fixture parsing: {:?}", t.elapsed());
    println!(
        "keygen input (d3): num_layers={}, num_prev_chain_steps={}, block_data={} bytes, bk_set={} signers, \
         siblings_depth={}",
        input.num_layers, input.num_prev_chain_steps, input.block_data.len(), input.bk_set.len(),
        input.prev_chain_proofs[0].siblings.len(),
    );

    common::run_keygen(&input, 3);
    println!("[timing] TOTAL keygen d3: {:?}", t_total.elapsed());
}

#[test]
fn test_layer_hashes_real_data_prove_d3() {
    let path = keygen_fixture_path();
    assert!(path.exists(), "Fixture not found: {}. Run keygen first or check fixture path.", path.display());

    let t = Instant::now();
    let input = load_fixture(&path);
    println!("[timing] fixture parsing: {:?}", t.elapsed());
    println!(
        "prove input (d3): num_layers={}, num_prev_chain_steps={}, block_data={} bytes, bk_set={} signers",
        input.num_layers, input.num_prev_chain_steps, input.block_data.len(), input.bk_set.len()
    );

    common::run_prove(&input, 3, "layer_hashes_real_d3_L5");
}

#[test]
fn test_layer_hashes_real_data_verify_from_files_d3() {
    common::run_verify_from_files(3, "layer_hashes_real_d3_L5");
}

#[test]
fn test_layer_hashes_real_data_verify_with_vk_bytes_d3() {
    common::run_verify_with_vk_bytes(3, "layer_hashes_real_d3_L5");
}

#[test]
fn test_layer_hashes_real_data_verify_with_static_vk_d3() {
    common::run_verify_with_static_vk(3, "layer_hashes_real_d3_L5");
}

// ===========================================================================
// All-fixtures test: same d3 key proves & verifies every fixture
// ===========================================================================

/// Prove and verify every `circuit_test_data_*.json` fixture with the same d3 key.
/// This confirms the VK/PK generated by `test_layer_hashes_keygen_d3` is universal
/// across all depth=3 test data.
#[test]
fn test_layer_hashes_prove_and_verify_all_fixtures_d3() {
    let fixtures = all_fixture_paths();
    println!("Found {} fixture(s):", fixtures.len());
    for p in &fixtures {
        println!("  - {}", p.file_name().unwrap().to_str().unwrap());
    }

    for fixture_path in &fixtures {
        let name = fixture_path.file_stem().unwrap().to_str().unwrap();
        let label = format!("layer_hashes_all_{name}");
        println!("\n========== {name} ==========");

        let t = Instant::now();
        let input = load_fixture(fixture_path);
        println!(
            "[timing] fixture parsing: {:?}  (num_layers={}, block_data={} bytes, bk_set={} signers)",
            t.elapsed(), input.num_layers, input.block_data.len(), input.bk_set.len()
        );

        common::run_prove(&input, 3, &label);
        common::run_verify_from_files(3, &label);
        common::run_verify_with_vk_bytes(3, &label);
        common::run_verify_with_static_vk(3, &label);

        println!("========== {name}: OK ==========");
    }
}*/
