# gosh-zk-snark-halo2-utils

Thin halo2 helper crate. Hides the `BaseCircuitBuilder<Fr>` boilerplate for
KZG/BN254 SHPLONK proofs so any `Circuit<Fr>` whose `configure_with_params`
delegates to `BaseCircuitBuilder::configure_with_params` can be proven and
verified through a single uniform API.

Backend: `halo2-base` (axiom fork) pulled from
`gosh-sh/halo2-lib-zkevm-sha256-and-bls12-381`, branch `main`.
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

`ZKHALO2VERIFYWITHVK` (`0xC7 0x4A`) lives in `zk_halo2_with_vk.rs` and uses
the same `Proof::verify_with_vk` path with a caller-supplied VK blob.

## Repo layout

- `src/{lib,io,keygen,proof}.rs` — the library
- `params/kzg_bn254_19.srs` — KZG SRS for K=19 (dev/test only)
- `keys/` — fixture VKs/PKs/proofs/instances for Dark DEX and BK-set circuits
- `tests/` — Dark DEX, BK-set verifier, and layer-hash (d3/d8) round-trip tests

## Build

`rust-toolchain = nightly`. Dev profile pins `opt-level = 3` (slow compile,
fast run — standard for halo2 work in this tree).

```
cargo build
cargo test
```

Dev-deps additionally pull `gosh-dense-balanced-tree`, `dex-halo2-circuit`,
and `tvm_block` (for tests only — not exposed by the library).
