//! Hermez Perpetual Powers of Tau (`.ptau`) → halo2-canonical raw SRS.
//!
//! Purpose: replace self-generated / ad-hoc KZG SRS material with the
//! community-audited Hermez ceremony as the trust root for on-chain
//! Halo2/KZG verification.
//!
//! Flow this module implements (matches `bootstrap_hermez_srs.sh` in
//! `bridge/scripts/`, but as a library instead of a shell binary):
//!
//! 1. Read `powersOfTau28_hez_final_20.ptau` (SnarkJs format, K=20)
//!    via `halo2_kzg_srs::Srs::<Bn256>::read_partial` at K=20.
//! 2. Materialize the halo2-canonical raw SRS bytes at K=20 via
//!    `Srs::write_raw` and verify their SHA-256 matches
//!    [`HERMEZ_K20_RAW_SRS_SHA256`] — this is the trust anchor.
//! 3. Extract the k-invariant verifier-only points `g[0]`, `g2`, `s_g2`
//!    from the K=20 raw blob (they never change under `downsize`).
//! 4. If `desired_k < 20`, downsize the SRS and re-serialize; otherwise
//!    reuse the K=20 raw blob directly.
//!
//! ## Two `halo2curves` versions in the compile graph
//!
//! `halo2_kzg_srs` pins `halo2curves` at PSE tag `0.3.1`. Our
//! `halo2-base` (axiom fork) uses a different `halo2curves`. Both are
//! byte-compatible for uncompressed BN254 affine (`G1Affine` 64 B,
//! `G2Affine` 128 B), so we cross the boundary via **bytes only** —
//! no `halo2curves`-typed values ever escape this module. The resulting
//! raw SRS bytes are consumable by
//! `ParamsKZG::<Bn256>::read_custom(RawBytesUnchecked)` (halo2-base
//! side) and the extracted point bytes are consumable by
//! [`crate::kzg_helper::build_kzg_verifier_params_from_points`].

use std::io::{Read, Seek};

use halo2_curves::bn256::Bn256;
use halo2_kzg_srs::{Srs, SrsFormat};
use sha2::{Digest, Sha256};

/// SHA-256 of the halo2-canonical raw SRS at K=20 produced from
/// `powersOfTau28_hez_final_20.ptau` via `halo2_kzg_srs`
/// (`read_partial(SnarkJs, 20)` → `write_raw`). This must match the anchor
/// hard-coded in `bridge/scripts/bootstrap_hermez_srs.sh`
/// (`80394564e2598883dbb5d7d61630287f34e29cdd806d7ef74f68acc6bffeb608`).
pub const HERMEZ_K20_RAW_SRS_SHA256: [u8; 32] = [
    0x80, 0x39, 0x45, 0x64, 0xe2, 0x59, 0x88, 0x83, 0xdb, 0xb5, 0xd7, 0xd6, 0x16, 0x30, 0x28, 0x7f,
    0x34, 0xe2, 0x9c, 0xdd, 0x80, 0x6d, 0x7e, 0xf7, 0x4f, 0x68, 0xac, 0xc6, 0xbf, 0xfe, 0xb6, 0x08,
];

/// URL of the Polygon zkEVM GCS mirror of `powersOfTau28_hez_final_20.ptau`.
///
/// Same source `bootstrap_hermez_srs.sh` uses. Not fetched by this module —
/// downloading is the caller's responsibility (this module only takes a
/// `Read + Seek`).
pub const HERMEZ_K20_PTAU_URL: &str =
    "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_20.ptau";

/// Expected size (bytes) of `powersOfTau28_hez_final_20.ptau`.
/// Matches `PTAU_EXPECTED_SIZE` in `bootstrap_hermez_srs.sh`.
pub const HERMEZ_K20_PTAU_SIZE: u64 = 1_208_042_648;

/// The three KZG points a verifier needs (uncompressed BN254 affine bytes).
/// These are `k`-invariant: `downsize` only truncates `g[..]`/`g_lagrange[..]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KzgVerifierBytes {
    /// `g[0]` (64-byte uncompressed `G1Affine`). BN254 curve constant.
    pub g0: [u8; 64],
    /// `g2` (128-byte uncompressed `G2Affine`). BN254 curve constant.
    pub g2: [u8; 128],
    /// `s_g2` = `[s] · G2` (128-byte uncompressed `G2Affine`). This is the
    /// **only** ceremony-specific point — it encodes the Hermez trapdoor.
    pub s_g2: [u8; 128],
}

/// Everything a caller needs after processing the ptau file.
pub struct PtauMaterial {
    /// halo2-canonical raw SRS bytes at the requested `k`. Layout:
    /// `[u32 k LE][g[0..n] raw][g_lagrange[0..n] raw][g2 raw][s_g2 raw]`.
    /// Consumable directly by `ParamsKZG::<Bn256>::read_custom(RawBytesUnchecked)`.
    pub raw_srs: Vec<u8>,
    /// The three k-invariant verifier points, extracted from the K=20 blob.
    pub verifier_bytes: KzgVerifierBytes,
    /// SHA-256 of the K=20 raw SRS materialized from this ptau reader.
    /// Verified to equal [`HERMEZ_K20_RAW_SRS_SHA256`] before this struct
    /// is returned.
    pub k20_sha256: [u8; 32],
}

/// Read a Hermez `.ptau` reader (SnarkJs format, K=20), verify the K=20 raw
/// SRS SHA-256 trust anchor, extract verifier bytes, and (if needed)
/// downsize to `desired_k`.
///
/// Panics if the anchor SHA does not match — this is fail-loud by design:
/// a mismatch means the ptau was tampered with, the `halo2_kzg_srs` output
/// format changed, or the wrong ceremony was supplied.
///
/// * `reader` — a `Read + Seek` over `powersOfTau28_hez_final_20.ptau`.
/// * `desired_k` — target circuit `k` (`1..=20`). If `20`, the K=20 raw
///   blob is reused; otherwise the SRS is downsized and re-serialized.
pub fn read_hermez_ptau_and_verify<R: Read + Seek>(
    reader: &mut R,
    desired_k: u32,
) -> PtauMaterial {
    assert!(
        (1..=20).contains(&desired_k),
        "desired_k must be in 1..=20 (the ptau is K=20 depth), got {desired_k}"
    );

    let mut srs = Srs::<Bn256>::read_partial(reader, SrsFormat::SnarkJs, 20);

    // Materialize K=20 raw SRS bytes (~128 MB) to hash for the trust anchor
    // and to extract k-invariant verifier points from a known layout.
    let mut buf20: Vec<u8> = Vec::with_capacity(4 + (1usize << 20) * 128 + 256);
    srs.write_raw(&mut buf20);

    let k20_sha256: [u8; 32] = Sha256::digest(&buf20).into();
    assert_eq!(
        k20_sha256, HERMEZ_K20_RAW_SRS_SHA256,
        "K=20 raw SRS SHA-256 anchor mismatch: expected {} got {}",
        hex_lower(&HERMEZ_K20_RAW_SRS_SHA256),
        hex_lower(&k20_sha256),
    );

    let verifier_bytes = extract_verifier_bytes_from_raw(&buf20, 20);

    let raw_srs = if desired_k == 20 {
        buf20
    } else {
        drop(buf20);
        srs.downsize(desired_k);
        let n = 1usize << desired_k;
        let mut buf = Vec::with_capacity(4 + n * 128 + 256);
        srs.write_raw(&mut buf);
        buf
    };

    PtauMaterial {
        raw_srs,
        verifier_bytes,
        k20_sha256,
    }
}

/// Extract `g[0]`, `g2`, `s_g2` slices from a halo2-canonical raw SRS blob
/// at the given `k`. No cryptographic checks — a byte slice operation on a
/// known layout.
fn extract_verifier_bytes_from_raw(raw: &[u8], k: u32) -> KzgVerifierBytes {
    let n: usize = 1 << k;
    let g1_size = 64;
    let g2_size = 128;
    let header = 4;
    let g_len = n * g1_size;
    let g_lagrange_len = n * g1_size;
    let expected_len = header + g_len + g_lagrange_len + 2 * g2_size;
    assert_eq!(
        raw.len(),
        expected_len,
        "raw SRS length mismatch: expected {expected_len} got {}",
        raw.len(),
    );

    let mut g0 = [0u8; 64];
    let mut g2 = [0u8; 128];
    let mut s_g2 = [0u8; 128];
    g0.copy_from_slice(&raw[header..header + g1_size]);
    let g2_start = header + g_len + g_lagrange_len;
    g2.copy_from_slice(&raw[g2_start..g2_start + g2_size]);
    s_g2.copy_from_slice(&raw[g2_start + g2_size..g2_start + 2 * g2_size]);

    KzgVerifierBytes { g0, g2, s_g2 }
}

/// Render a byte slice as a Rust `pub const NAME: [u8; N] = [ ... ];` snippet.
/// Rows of 12 hex bytes with a leading doc line for readability.
///
/// Intended to be pasted directly into
/// `tvm_vm/src/executor/zk_halo2_utils.rs`.
pub fn emit_rust_const_byte_array(name: &str, doc: &str, bytes: &[u8]) -> String {
    let mut out = String::new();
    for line in doc.lines() {
        out.push_str("/// ");
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(&format!(
        "pub const {name}: [u8; {}] = [\n",
        bytes.len()
    ));
    for chunk in bytes.chunks(12) {
        out.push_str("    ");
        for (i, b) in chunk.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(&format!("0x{b:02x},"));
        }
        out.push('\n');
    }
    out.push_str("];\n");
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
