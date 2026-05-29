/*use std::sync::LazyLock;
use std::time::Instant;

use bk_set_change_verifier_halo2_circuit_with_better_sha256::primary_circuit::PrimaryBkSetVerifierCircuit;
use bk_set_change_verifier_halo2_circuit_with_better_sha256::test_helpers::*;
use gosh_zk_snark_halo2_utils::io::read_vk;
use gosh_zk_snark_halo2_utils::keygen::generate_and_save_keys;
use gosh_zk_snark_halo2_utils::proof::Proof;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::plonk::VerifyingKey;
use halo2_base::utils::fs::gen_srs;

fn bk_set_keys_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("keys")
}

fn bk_set_config_params() -> BaseCircuitParams {
    let config_path = bk_set_keys_dir().join("bk_set_config_params.json");
    let json = std::fs::read_to_string(&config_path)
        .expect("bk_set_config_params.json not found. Run test_bk_set_keygen_prove_verify first.");
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
static BK_SET_VK: LazyLock<VerifyingKey<G1Affine>> = LazyLock::new(|| {
    let vk_bytes = std::fs::read(bk_set_keys_dir().join("bk_set_vk.bin"))
        .expect("bk_set_vk.bin not found. Run test_bk_set_keygen_prove_verify first.");
    read_vk(&vk_bytes, &bk_set_config_params())
});

/// Full keygen → prove → verify cycle for PrimaryBkSetVerifierCircuit.
#[test]
fn test_bk_set_keygen_prove_verify() {
    let t_total = Instant::now();

    // 1. Generate test data (all signers sign).
    let t = Instant::now();
    let test_data = bk_set_block_data_gen::generator::generate_test_data_all_sign(10)
        .expect("generate_test_data_all_sign failed");
    println!("[timing] test data generation: {:?}", t.elapsed());

    // 2. Construct circuit for keygen.
    let t = Instant::now();
    let circuit = PrimaryBkSetVerifierCircuit::<Fr>::new(
        test_data.block_envelope_bytes.clone(),
        test_data.attestation_bytes.clone(),
        test_data.old_bk_set.clone(),
        K as usize,
        NUM_UNUSABLE_ROWS,
        LOOKUP_BITS,
        LIMB_BITS,
        NUM_LIMBS,
        MAX_SIGNERS,
    );
    println!("[timing] circuit construction: {:?}", t.elapsed());
    println!(
        "base_circuit_params: {:?}",
        circuit.params.base_circuit_params
    );

    let config_params = circuit.params.base_circuit_params.clone();

    // 3. Generate SRS.
    let t = Instant::now();
    let srs = gen_srs(K);
    println!("[timing] SRS generation: {:?}", t.elapsed());

    // 4. Generate and save keys to project "keys" subfolder.
    let keys_dir = bk_set_keys_dir();
    std::fs::create_dir_all(&keys_dir).unwrap();
    let vk_path = keys_dir.join("bk_set_vk.bin");
    let pk_path = keys_dir.join("bk_set_pk.bin");
    let config_path = keys_dir.join("bk_set_config_params.json");

    let t = Instant::now();
    generate_and_save_keys(
        &srs,
        &circuit,
        &config_params,
        vk_path.to_str().unwrap(),
        pk_path.to_str().unwrap(),
        config_path.to_str().unwrap(),
    );
    println!("[timing] keygen + save: {:?}", t.elapsed());

    // 5. Construct a new circuit with the same data for proving, override params.
    let mut prove_circuit = PrimaryBkSetVerifierCircuit::<Fr>::new(
        test_data.block_envelope_bytes.clone(),
        test_data.attestation_bytes.clone(),
        test_data.old_bk_set.clone(),
        K as usize,
        NUM_UNUSABLE_ROWS,
        LOOKUP_BITS,
        LIMB_BITS,
        NUM_LIMBS,
        MAX_SIGNERS,
    );
    prove_circuit.override_base_circuit_params(config_params);

    // 6. Compute public instances and save to file.
    let old_bk_set_commitment =
        compute_bk_set_poseidon_instance(&test_data.old_bk_set, LIMB_BITS, NUM_LIMBS);
    let new_bk_set_commitment =
        compute_bk_set_poseidon_instance(&prove_circuit.new_bk_set, LIMB_BITS, NUM_LIMBS);
    let instances = vec![old_bk_set_commitment, new_bk_set_commitment];
    let instances_path = keys_dir.join("bk_set_instances.bin");
    let instances_bytes: Vec<u8> = instances.iter().flat_map(|f| f.to_repr().as_ref().to_vec()).collect();
    std::fs::write(&instances_path, &instances_bytes).unwrap();
    println!("instances saved: {} field elements ({} bytes)", instances.len(), instances_bytes.len());

    // 7. Generate proof.
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

    // 7b. Save proof to file.
    let proof_path = keys_dir.join("bk_set_proof.bin");
    std::fs::write(&proof_path, proof.as_bytes()).unwrap();
    println!("proof saved to {:?}", proof_path);

    // 8. Verify proof — should pass.
    let t = Instant::now();
    let valid = proof.verify_with_vk_from_path(
        vk_path.to_str().unwrap(),
        &srs,
        config_path.to_str().unwrap(),
        &[&instances],
    );
    println!("[timing] proof verification: {:?}", t.elapsed());
    assert!(valid, "Proof verification should pass with correct instances");

    // 9. Negative test: wrong instances should fail.
    let wrong_instances = vec![Fr::from(42u64), Fr::from(99u64)];
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
    println!("bk-set keygen → prove → verify: PASSED");
}

/// Verify a previously saved proof by reading proof + VK from files.
///
/// Requires `test_bk_set_keygen_prove_verify` to have run first.
#[test]
fn test_bk_set_verify_from_files() {
    let t_total = Instant::now();

    let keys_dir = bk_set_keys_dir();
    let vk_path = keys_dir.join("bk_set_vk.bin");
    let proof_path = keys_dir.join("bk_set_proof.bin");
    let config_path = keys_dir.join("bk_set_config_params.json");
    let instances_path = keys_dir.join("bk_set_instances.bin");

    assert!(
        vk_path.exists() && proof_path.exists() && config_path.exists() && instances_path.exists(),
        "Key/proof/instances files not found. Run test_bk_set_keygen_prove_verify first."
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

    // 3. Generate SRS (needed for verifier params).
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
    println!("[timing] proof verification (from files): {:?}", t.elapsed());
    assert!(valid, "Proof verification from files should pass");

    println!("[timing] TOTAL: {:?}", t_total.elapsed());
    println!("bk-set verify-from-files: PASSED");
}

/// VK deserialized from bytes each call (uses verify_with_vk_from_bytes).
/// Proof and instances are read from files.
///
/// Requires `test_bk_set_keygen_prove_verify` to have run first.
#[test]
fn test_bk_set_verify_with_embedded_vk() {
    let t_total = Instant::now();

    let keys_dir = bk_set_keys_dir();
    let vk_path = keys_dir.join("bk_set_vk.bin");
    let proof_path = keys_dir.join("bk_set_proof.bin");
    let instances_path = keys_dir.join("bk_set_instances.bin");

    assert!(
        vk_path.exists() && proof_path.exists() && instances_path.exists(),
        "Key/proof/instances files not found. Run test_bk_set_keygen_prove_verify first."
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

    // 3. Generate SRS (needed for verifier params).
    let t = Instant::now();
    let srs = gen_srs(K);
    println!("[timing] SRS generation: {:?}", t.elapsed());

    // 4. Read VK bytes and verify using verify_with_vk_from_bytes.
    let t = Instant::now();
    let vk_bytes = std::fs::read(&vk_path).unwrap();
    println!("[timing] VK read from file: {:?}", t.elapsed());

    let t = Instant::now();
    let config_params = bk_set_config_params();
    let valid = proof.verify_with_vk_from_bytes(
        &vk_bytes,
        &srs,
        &config_params,
        &[&instances],
    );
    println!("[timing] proof verification (VK from bytes, includes deserialization): {:?}", t.elapsed());
    assert!(valid, "Proof verification with VK from bytes should pass");

    println!("[timing] TOTAL: {:?}", t_total.elapsed());
    println!("bk-set verify-with-embedded-vk: PASSED");
}

/// VK is a static object (deserialized once via LazyLock), skipping
/// deserialization cost on repeated verifications.
/// Proof and instances are read from files.
///
/// Requires `test_bk_set_keygen_prove_verify` to have run first.
#[test]
fn test_bk_set_verify_with_static_vk() {
    let t_total = Instant::now();

    let keys_dir = bk_set_keys_dir();
    let proof_path = keys_dir.join("bk_set_proof.bin");
    let instances_path = keys_dir.join("bk_set_instances.bin");

    assert!(
        proof_path.exists() && instances_path.exists(),
        "Proof/instances files not found. Run test_bk_set_keygen_prove_verify first."
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

    // 3. Generate SRS (needed for verifier params).
    let t = Instant::now();
    let srs = gen_srs(K);
    println!("[timing] SRS generation: {:?}", t.elapsed());

    // 4. Force LazyLock init (VK deserialization) — measure separately.
    let t = Instant::now();
    let vk: &VerifyingKey<G1Affine> = &BK_SET_VK;
    println!("[timing] VK LazyLock init (deserialization, once): {:?}", t.elapsed());

    // 5. Verify proof — VK already deserialized.
    let t = Instant::now();
    let valid = proof.verify_with_vk(
        vk,
        &srs,
        &[&instances],
    );
    println!("[timing] proof verification (static VK, no deserialization): {:?}", t.elapsed());
    assert!(valid, "Proof verification with static VK should pass");

    println!("[timing] TOTAL: {:?}", t_total.elapsed());
    println!("bk-set verify-with-static-vk: PASSED");
}*/
