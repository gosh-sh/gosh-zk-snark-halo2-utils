# gosh-zk-snark-halo2-utils

Thin halo2 helper crate. Hides the `BaseCircuitBuilder<Fr>` boilerplate for
KZG/BN254 SHPLONK proofs so any `Circuit<Fr>` whose `configure_with_params`
delegates to `BaseCircuitBuilder::configure_with_params` can be proven and
verified through a single uniform API.

Backend: `halo2-base` (axiom fork) pulled from
`gosh-sh/halo2-lib-zkevm-sha256-and-bls12-381`, branch `bump-halo2-lib-v0.4.1`.
Curve: BN254. Multiopen: SHPLONK. Transcript: Blake2b.

## Modules

- `io` — read/write KZG SRS (`ParamsKZG<Bn256>`), `BaseCircuitParams` (JSON),
  `ProvingKey`/`VerifyingKey` (bytes or path, `SerdeFormat::RawBytesUnchecked`),
  break points (LE u32 binary).
- `keygen` — `generate_and_save_keys::<C: Circuit<Fr>>(...)` writes VK, PK,
  and config params side-by-side.
- `proof` — `Proof(Vec<u8>)` newtype with
  `create_for_circuit{,_from_paths}` and `verify_with_vk{,_from_bytes,_from_path}`.
  `verify_with_vk` takes a pre-deserialized VK so callers can amortize the
  expensive `EvaluationDomain` build (K=19 takes seconds).
- `kzg_helper` — `build_kzg_verifier_params_from_points(k, g0, g2, s_g2)`
  reconstructs a verifier-only `ParamsKZG<Bn256>` from ~320 bytes of raw
  points, skipping the multi-MB `g[..]` vector needed only by the prover.
- `ptau` — Hermez Perpetual-Powers-of-Tau `.ptau` → halo2-canonical raw SRS
  plus `KzgVerifierBytes { g0, g2, s_g2 }`. Trust root pinned via
  `HERMEZ_K20_RAW_SRS_SHA256`; replaces ad-hoc/self-generated SRS with the
  community-audited ceremony as the basis for on-chain verification.

## How tvm-sdk uses it

Used **only** by `tvm-sdk/tvm_vm` under the `gosh` cargo feature
(`Cargo.toml:67, 139`).

- `tvm_vm/src/executor/zk_halo2.rs` — `ZKHALO2VERIFY` opcode (`0xC7 0x49`).
  Constructs a `Proof::new(bytes)` from cell data and calls
  `verify_with_vk(&vk, &params, &[&pub_inputs])` against a cached Dark DEX
  W=128 / K=19 VK (built once via `OnceLock`, optionally pre-warmed on
  node startup with `warmup_halo2()`).
- `tvm_vm/src/executor/zk_halo2_utils.rs` — imports `io::read_vk` to
  reconstruct the embedded `DARK_DEX_W128_VK_BYTES` constant with
  `dark_dex_w128_config_params()`.
- `tvm_vm/src/executor/zk_halo2_with_vk.rs` — `ZKHALO2VERIFYWITHVK` opcode
  (`0xC7 0x4A`), same `Proof::verify_with_vk` path with a caller-supplied VK.

## Repo layout

- `src/{lib,io,keygen,proof,kzg_helper,ptau}.rs` — the library
- `params/kzg_bn254_19.srs` — KZG SRS for K=19 (dev/test only)

## Build

`rust-toolchain = nightly`. Dev profile pins `opt-level = 3` (slow compile,
fast run — standard for halo2 work in this tree).

```
cargo build
cargo test
```
