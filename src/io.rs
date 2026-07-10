use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};

/// Default `SerdeFormat` used by the `save_vk_to_path` / `save_pk_to_path`
/// helpers. Matches the format consumed by `read_vk*` / `read_pk*` above.
const SAVE_KEY_SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytesUnchecked;

/// Write a byte slice to `path`, creating any missing parent directories.
pub fn save_bytes(path: &str, data: &[u8]) {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, data).unwrap();
}

/// Serialize a verifying key with `SerdeFormat::RawBytesUnchecked` and write
/// it to `path`, creating any missing parent directories.
pub fn save_vk_to_path(vk: &VerifyingKey<G1Affine>, path: &str) {
    let mut buf: Vec<u8> = Vec::new();
    vk.write(&mut buf, SAVE_KEY_SERDE_FORMAT).unwrap();
    save_bytes(path, &buf);
}

/// Serialize a proving key with `SerdeFormat::RawBytesUnchecked` and write
/// it to `path`, creating any missing parent directories.
pub fn save_pk_to_path(pk: &ProvingKey<G1Affine>, path: &str) {
    let mut buf: Vec<u8> = Vec::new();
    pk.write(&mut buf, SAVE_KEY_SERDE_FORMAT).unwrap();
    save_bytes(path, &buf);
}

/// Like [`read_config_params`] but returns `None` instead of panicking when
/// the file is missing or unparseable. Useful for drive-cache-vs-keygen
/// branches.
pub fn try_read_config_params(path: &str) -> Option<BaseCircuitParams> {
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

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

/// Read break points from a binary file (4 bytes per u32, little-endian).
pub fn read_break_points(path: &str) -> Vec<Vec<usize>> {
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    if buffer.len() % 4 != 0 {
        panic!("Break points file byte count is not a multiple of 4");
    }

    let mut break_points = Vec::with_capacity(buffer.len() / 4);
    for chunk in buffer.chunks_exact(4) {
        let value = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        break_points.push(value as usize);
    }

    vec![break_points]
}

/// Save break points to a binary file (4 bytes per u32, little-endian).
pub fn save_break_points(break_points: &[Vec<usize>], path: &str) {
    assert!(break_points.len() == 1, "Expected single-phase break points");
    let mut file = File::create(path).unwrap();
    for &value in &break_points[0] {
        assert!(
            value <= u32::MAX as usize,
            "Break point value {} exceeds u32::MAX",
            value
        );
        file.write_all(&(value as u32).to_le_bytes()).unwrap();
    }
}
