//! Verifier-only KZG SRS reconstruction from a handful of raw points.

use halo2_base::halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};

/// Reconstruct a **verifier-only** `ParamsKZG<Bn256>` from the three KZG points
/// SHPLONK verification actually consumes (`g[0]`, `g2`, `[s]·G2`), skipping the
/// multi-MB `g[..]` / `g_lagrange[..]` vectors the prover needs but the verifier
/// never touches.
///
/// This is what lets an on-chain / embedded verifier ship ~320 bytes of KZG
/// material instead of a full ~64 MB SRS. The reconstructed `ParamsKZG` is
/// suitable for `verify_proof::<_, VerifierSHPLONK<_>, _, _, _>` at the given
/// `k`; it is **not** usable for proving.
///
/// * `k` — circuit `k` the returned params should report (`n = 1 << k`).
///   Must match the `k` the proof/VK were generated at.
/// * `g0_bytes` — 64-byte uncompressed `G1Affine` = `g[0]`. This is a BN254
///   curve constant (identical across every well-formed BN254 KZG SRS).
/// * `g2_bytes` — 128-byte uncompressed `G2Affine` = the G2 generator. Also a
///   BN254 curve constant.
/// * `s_g2_bytes` — 128-byte uncompressed `G2Affine` = `[s] · G2`. This is the
///   **only** ceremony-specific point; it encodes the trapdoor `s` of the KZG
///   setup the proof was created against. Verification only succeeds if this
///   matches the ceremony that produced the proof.
pub fn build_kzg_verifier_params_from_points(
    k: u32,
    g0_bytes: &[u8; 64],
    g2_bytes: &[u8; 128],
    s_g2_bytes: &[u8; 128],
) -> ParamsKZG<Bn256> {
    use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;

    // Build a minimal K=0 raw-serialized blob (388 bytes) so
    // `ParamsKZG::read_custom` accepts it (K=0 reads exactly one G1 point for
    // `g` and one for `g_lagrange`). The values we care about are `g2` and
    // `s_g2`; the `g_lagrange[0]` slot is filled with `g[0]` as a benign
    // placeholder — it is overwritten by `from_parts` below.
    let mut blob = Vec::with_capacity(388);
    blob.extend_from_slice(&0u32.to_le_bytes()); // header k = 0 → n = 1
    blob.extend_from_slice(g0_bytes); // g[0]
    blob.extend_from_slice(g0_bytes); // g_lagrange[0] (placeholder)
    blob.extend_from_slice(g2_bytes); // g2
    blob.extend_from_slice(s_g2_bytes); // s_g2
    let mut cursor: &[u8] = &blob;
    let dummy = ParamsKZG::<Bn256>::read_custom(&mut cursor, SerdeFormat::RawBytesUnchecked)
        .expect("Parsing embedded KZG verifier blob should not fail");

    let g0 = G1Affine::from_raw_bytes_unchecked(g0_bytes);
    dummy.from_parts(k, vec![g0], Some(vec![]), dummy.g2(), dummy.s_g2())
}
