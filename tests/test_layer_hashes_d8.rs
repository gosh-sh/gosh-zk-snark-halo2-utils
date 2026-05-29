/*mod common;

use std::time::Instant;

use layer_hashes_update_halo2_circuit::primary_circuit::helpers::prepare_circuit_test_input;

// ===========================================================================
// Depth=8 tests (synthetic data from prepare_circuit_test_input)
// ===========================================================================

/// Generate VK/PK/config for depth=8 circuits using synthetic data.
#[test]
fn test_layer_hashes_keygen_d8() {
    let t_total = Instant::now();

    let t = Instant::now();
    let input = prepare_circuit_test_input(5, 1, 1);
    println!("[timing] synthetic data generation: {:?}", t.elapsed());
    println!(
        "keygen input (d8): num_layers={}, num_prev_chain_steps={}, block_data={} bytes, bk_set={} signers, \
         siblings_depth={}",
        input.num_layers, input.num_prev_chain_steps, input.block_data.len(), input.bk_set.len(),
        input.prev_chain_proofs[0].siblings.len(),
    );

    common::run_keygen(&input, 8);
    println!("[timing] TOTAL keygen d8: {:?}", t_total.elapsed());
}

/// Prove with FRESH synthetic data (different random data than keygen),
/// verifying that any depth=8 input shares the same VK.
#[test]
fn test_layer_hashes_synthetic_prove_d8() {
    let t = Instant::now();
    let input = prepare_circuit_test_input(5, 1, 1);
    println!("[timing] synthetic data generation: {:?}", t.elapsed());
    println!(
        "prove input (d8): num_layers={}, num_prev_chain_steps={}, block_data={} bytes, bk_set={} signers",
        input.num_layers, input.num_prev_chain_steps, input.block_data.len(), input.bk_set.len()
    );

    common::run_prove(&input, 8, "layer_hashes_synthetic_d8");
}

#[test]
fn test_layer_hashes_synthetic_verify_from_files_d8() {
    common::run_verify_from_files(8, "layer_hashes_synthetic_d8");
}

#[test]
fn test_layer_hashes_synthetic_verify_with_vk_bytes_d8() {
    common::run_verify_with_vk_bytes(8, "layer_hashes_synthetic_d8");
}

#[test]
fn test_layer_hashes_synthetic_verify_with_static_vk_d8() {
    common::run_verify_with_static_vk(8, "layer_hashes_synthetic_d8");
}
*/