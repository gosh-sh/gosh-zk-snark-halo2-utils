use std::sync::LazyLock;
use std::time::Instant;

use gosh_zk_snark_halo2_utils::io::read_vk;
use gosh_zk_snark_halo2_utils::keygen::generate_and_save_keys;
use gosh_zk_snark_halo2_utils::proof::Proof;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::plonk::VerifyingKey;
use halo2_base::utils::fs::gen_srs;
use layer_hashes_update_halo2_circuit::primary_circuit::helpers::{
    build_circuit, build_instances, CircuitTestInput,
};
use layer_hashes_update_halo2_circuit::test_helpers::K;

// ---------------------------------------------------------------------------
// Depth-parameterized paths
// ---------------------------------------------------------------------------

pub fn keys_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("keys")
}

pub fn vk_path(depth: usize) -> std::path::PathBuf {
    keys_dir().join(format!("layer_hashes_d{depth}_vk.bin"))
}
pub fn pk_path(depth: usize) -> std::path::PathBuf {
    keys_dir().join(format!("layer_hashes_d{depth}_pk.bin"))
}
pub fn config_path(depth: usize) -> std::path::PathBuf {
    keys_dir().join(format!("layer_hashes_d{depth}_config_params.json"))
}

pub fn proof_file(label: &str) -> std::path::PathBuf {
    keys_dir().join(format!("{label}_proof.bin"))
}
pub fn instances_file(label: &str) -> std::path::PathBuf {
    keys_dir().join(format!("{label}_instances.bin"))
}

pub fn read_saved_config_params(depth: usize) -> BaseCircuitParams {
    let path = config_path(depth);
    let json = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{} not found. Run test_layer_hashes_keygen_d{depth} first.", path.display()));
    serde_json::from_str(&json).unwrap()
}

pub fn read_instances_from_file(path: &std::path::Path) -> Vec<Fr> {
    let bytes = std::fs::read(path).unwrap();
    bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut repr = <Fr as PrimeField>::Repr::default();
            repr.as_mut().copy_from_slice(chunk);
            Fr::from_repr(repr).expect("invalid Fr encoding")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Static VKs — one per depth, deserialized once from file
// ---------------------------------------------------------------------------

pub static VK_D3: LazyLock<VerifyingKey<G1Affine>> = LazyLock::new(|| {
    let vk_bytes = std::fs::read(vk_path(3))
        .expect("layer_hashes_d3_vk.bin not found. Run test_layer_hashes_keygen_d3 first.");
    read_vk(&vk_bytes, &read_saved_config_params(3))
});

pub static VK_D8: LazyLock<VerifyingKey<G1Affine>> = LazyLock::new(|| {
    let vk_bytes = std::fs::read(vk_path(8))
        .expect("layer_hashes_d8_vk.bin not found. Run test_layer_hashes_keygen_d8 first.");
    read_vk(&vk_bytes, &read_saved_config_params(8))
});

// ---------------------------------------------------------------------------
// Pipeline helpers (depth-parameterized)
// ---------------------------------------------------------------------------

/// Run keygen: build circuit from `input`, generate VK/PK/config, save to disk.
pub fn run_keygen(input: &CircuitTestInput, depth: usize) {
    let t = Instant::now();
    let circuit = build_circuit(input, K);
    println!("[timing] circuit construction: {:?}", t.elapsed());
    println!("base_circuit_params: {:?}", circuit.params.base_circuit_params);

    let config_params = circuit.params.base_circuit_params.clone();

    let t = Instant::now();
    let srs = gen_srs(K);
    println!("[timing] SRS generation: {:?}", t.elapsed());

    std::fs::create_dir_all(keys_dir()).unwrap();

    let t = Instant::now();
    generate_and_save_keys(
        &srs,
        &circuit,
        &config_params,
        vk_path(depth).to_str().unwrap(),
        pk_path(depth).to_str().unwrap(),
        config_path(depth).to_str().unwrap(),
    );
    println!("[timing] keygen + save: {:?}", t.elapsed());
}

/// Prove: build circuit from `input`, override params from saved config,
/// generate proof using saved PK, save proof + instances with `label`.
pub fn run_prove(input: &CircuitTestInput, depth: usize, label: &str) {
    assert!(pk_path(depth).exists(), "Run test_layer_hashes_keygen_d{depth} first.");

    let instances = build_instances(input);

    // Save instances.
    let instances_bytes: Vec<u8> = instances
        .iter()
        .flat_map(|f| f.to_repr().as_ref().to_vec())
        .collect();
    std::fs::write(instances_file(label), &instances_bytes).unwrap();
    println!("instances: {} field elements ({} bytes)", instances.len(), instances_bytes.len());

    // Build circuit with saved config params.
    let config_params = read_saved_config_params(depth);
    let mut circuit = build_circuit(input, K);
    circuit.override_base_circuit_params(config_params);

    let srs = gen_srs(K);

    let t = Instant::now();
    let proof = Proof::create_for_circuit_from_paths(
        &srs,
        pk_path(depth).to_str().unwrap(),
        config_path(depth).to_str().unwrap(),
        circuit,
        &[&instances],
    );
    println!("[timing] proof generation: {:?}", t.elapsed());
    println!("proof size: {} bytes", proof.as_bytes().len());

    std::fs::write(proof_file(label), proof.as_bytes()).unwrap();

    // Sanity: verify right away.
    let t = Instant::now();
    let valid = proof.verify_with_vk_from_path(
        vk_path(depth).to_str().unwrap(),
        &srs,
        config_path(depth).to_str().unwrap(),
        &[&instances],
    );
    println!("[timing] proof verification: {:?}", t.elapsed());
    assert!(valid, "Proof should verify");

    // Negative: wrong instances must fail.
    let wrong = vec![Fr::from(42u64)];
    assert!(
        !proof.verify_with_vk_from_path(
            vk_path(depth).to_str().unwrap(),
            &srs,
            config_path(depth).to_str().unwrap(),
            &[&wrong],
        ),
        "Wrong instances must fail"
    );
}

/// Verify from saved files (proof + instances + shared VK via path).
pub fn run_verify_from_files(depth: usize, label: &str) {
    let pp = proof_file(label);
    let ip = instances_file(label);
    assert!(pp.exists() && ip.exists(), "Run prove test for '{label}' first.");

    let proof = Proof::new(std::fs::read(&pp).unwrap());
    let instances = read_instances_from_file(&ip);
    let srs = gen_srs(K);

    let t = Instant::now();
    let valid = proof.verify_with_vk_from_path(
        vk_path(depth).to_str().unwrap(),
        &srs,
        config_path(depth).to_str().unwrap(),
        &[&instances],
    );
    println!("[timing] verify (VK from file): {:?}", t.elapsed());
    assert!(valid, "{label}: verification from files failed");
}

/// Verify: VK deserialized from raw bytes each call.
pub fn run_verify_with_vk_bytes(depth: usize, label: &str) {
    let pp = proof_file(label);
    let ip = instances_file(label);
    assert!(pp.exists() && ip.exists(), "Run prove test for '{label}' first.");

    let proof = Proof::new(std::fs::read(&pp).unwrap());
    let instances = read_instances_from_file(&ip);
    let srs = gen_srs(K);

    let t = Instant::now();
    let vk_bytes = std::fs::read(vk_path(depth)).unwrap();
    let config_params = read_saved_config_params(depth);
    let valid = proof.verify_with_vk_from_bytes(&vk_bytes, &srs, &config_params, &[&instances]);
    println!("[timing] verify (VK from bytes, incl. deserialization): {:?}", t.elapsed());
    assert!(valid, "{label}: verification with VK bytes failed");
}

/// Verify: static VK (LazyLock, deserialized once).
pub fn run_verify_with_static_vk(depth: usize, label: &str) {
    let pp = proof_file(label);
    let ip = instances_file(label);
    assert!(pp.exists() && ip.exists(), "Run prove test for '{label}' first.");

    let proof = Proof::new(std::fs::read(&pp).unwrap());
    let instances = read_instances_from_file(&ip);
    let srs = gen_srs(K);

    let t = Instant::now();
    let vk: &VerifyingKey<G1Affine> = match depth {
        3 => &VK_D3,
        8 => &VK_D8,
        _ => panic!("No static VK for depth={depth}"),
    };
    println!("[timing] VK LazyLock init: {:?}", t.elapsed());

    let t = Instant::now();
    let valid = proof.verify_with_vk(vk, &srs, &[&instances]);
    println!("[timing] verify (static VK, no deserialization): {:?}", t.elapsed());
    assert!(valid, "{label}: verification with static VK failed");
}
