use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::{keygen_pk, keygen_vk, Circuit},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};

use crate::io::save_config_params;

/// Generate VK and PK for any `Circuit<Fr>` implementation and save them to files.
///
/// This is the primary keygen API for circuits that implement `Circuit<Fr>` directly
/// (e.g., PrimaryBkSetVerifierCircuit, LayerHashesUpdateCircuit).
///
/// The circuit must already have its params configured (via its constructor).
pub fn generate_and_save_keys<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    circuit: &C,
    config_params: &BaseCircuitParams,
    vk_path: &str,
    pk_path: &str,
    config_params_path: &str,
) {
    let vk = keygen_vk(params, circuit).expect("keygen_vk failed");
    let pk = keygen_pk(params, vk.clone(), circuit).expect("keygen_pk failed");

    let mut vk_buf: Vec<u8> = Vec::new();
    vk.write(&mut vk_buf, SerdeFormat::RawBytesUnchecked).unwrap();
    std::fs::write(vk_path, vk_buf).unwrap();

    let mut pk_buf: Vec<u8> = Vec::new();
    pk.write(&mut pk_buf, SerdeFormat::RawBytesUnchecked).unwrap();
    std::fs::write(pk_path, pk_buf).unwrap();

    save_config_params(config_params, config_params_path);
}
