use std::fs::File;
use std::io::{Read, Write};

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};

/// Read KZG SRS parameters from a file.
pub fn read_kzg_params(path: &str) -> ParamsKZG<Bn256> {
    let params_buf: Vec<u8> = std::fs::read(path).unwrap();
    let mut params_slice: &[u8] = &params_buf;
    ParamsKZG::<Bn256>::read_custom(&mut params_slice, SerdeFormat::RawBytesUnchecked)
        .expect("Reading KZG params should not fail")
}

/// Read circuit configuration parameters from a JSON file.
pub fn read_config_params(path: &str) -> BaseCircuitParams {
    let mut file = File::open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    serde_json::from_str(&contents).expect("Config params JSON was not well-formatted")
}

/// Save circuit configuration parameters to a JSON file.
pub fn save_config_params(config_params: &BaseCircuitParams, path: &str) {
    let json = serde_json::to_string(config_params).unwrap();
    let mut file = File::create(path).unwrap();
    file.write_all(json.as_bytes()).unwrap();
}

/// Deserialize a proving key from bytes using `BaseCircuitBuilder<Fr>` for config.
///
/// This works universally for any circuit whose `configure_with_params` delegates
/// to `BaseCircuitBuilder::configure_with_params`.
pub fn read_pk(pk_bytes: &[u8], config_params: &BaseCircuitParams) -> ProvingKey<G1Affine> {
    let mut pk_slice: &[u8] = pk_bytes;
    ProvingKey::read::<_, BaseCircuitBuilder<Fr>>(
        &mut pk_slice,
        SerdeFormat::RawBytesUnchecked,
        config_params.clone(),
    )
    .expect("Reading proving key should not fail")
}

/// Read a proving key from a file.
pub fn read_pk_from_path(path: &str, config_params: &BaseCircuitParams) -> ProvingKey<G1Affine> {
    let pk_bytes = std::fs::read(path).unwrap();
    read_pk(&pk_bytes, config_params)
}

/// Deserialize a verifying key from bytes using `BaseCircuitBuilder<Fr>` for config.
///
/// This works universally for any circuit whose `configure_with_params` delegates
/// to `BaseCircuitBuilder::configure_with_params`.
pub fn read_vk(vk_bytes: &[u8], config_params: &BaseCircuitParams) -> VerifyingKey<G1Affine> {
    let mut vk_slice: &[u8] = vk_bytes;
    VerifyingKey::read::<_, BaseCircuitBuilder<Fr>>(
        &mut vk_slice,
        SerdeFormat::RawBytesUnchecked,
        config_params.clone(),
    )
    .expect("Reading verifying key should not fail")
}

/// Read a verifying key from a file.
pub fn read_vk_from_path(path: &str, config_params: &BaseCircuitParams) -> VerifyingKey<G1Affine> {
    let vk_bytes = std::fs::read(path).unwrap();
    read_vk(&vk_bytes, config_params)
}

/// Read break points from a binary file (legacy format: 2 bytes per u16, little-endian).
pub fn read_break_points(path: &str) -> Vec<Vec<usize>> {
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    if buffer.len() % 2 != 0 {
        panic!("Break points file has odd byte count");
    }

    let mut break_points = Vec::with_capacity(buffer.len() / 2);
    for chunk in buffer.chunks_exact(2) {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        break_points.push(value as usize);
    }

    vec![break_points]
}

/// Save break points to a binary file (legacy format: 2 bytes per u16, little-endian).
pub fn save_break_points(break_points: &[Vec<usize>], path: &str) {
    assert!(break_points.len() == 1, "Expected single-phase break points");
    let mut file = File::create(path).unwrap();
    for &value in &break_points[0] {
        file.write_all(&value.to_le_bytes()[0..2]).unwrap();
    }
}
