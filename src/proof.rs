use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::{
    circuit::Value,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::io::{read_config_params, read_pk, read_pk_from_path, read_vk, read_vk_from_path};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof(pub Vec<u8>);

impl Proof {
    // -----------------------------------------------------------------------
    // Primary API — for Circuit<Fr> implementations
    // -----------------------------------------------------------------------

    /// Create a proof for any `Circuit<Fr>` implementation.
    ///
    /// Uses `BaseCircuitBuilder<Fr>` to deserialize the PK (universal deserialization).
    pub fn create_for_circuit<C: Circuit<Fr>>(
        params: &ParamsKZG<Bn256>,
        pk_bytes: &[u8],
        config_params: &BaseCircuitParams,
        circuit: C,
        pub_inputs: &[&[Fr]],
    ) -> Self {
        let pk = read_pk(pk_bytes, config_params);
        let proof = Self::generate_proof(params, &pk, circuit, pub_inputs);
        Self(proof)
    }

    /// Create a proof for any `Circuit<Fr>` implementation, loading keys from file paths.
    pub fn create_for_circuit_from_paths<C: Circuit<Fr>>(
        params: &ParamsKZG<Bn256>,
        pk_path: &str,
        config_params_path: &str,
        circuit: C,
        pub_inputs: &[&[Fr]],
    ) -> Self {
        let config_params = read_config_params(config_params_path);
        let pk = read_pk_from_path(pk_path, &config_params);
        let proof = Self::generate_proof(params, &pk, circuit, pub_inputs);
        Self(proof)
    }

    // -----------------------------------------------------------------------
    // Universal verification
    // -----------------------------------------------------------------------

    /// Verify a proof using a VK deserialized from bytes.
    ///
    /// Uses `BaseCircuitBuilder<Fr>` for VK deserialization — works universally
    /// for any circuit whose `configure_with_params` delegates to
    /// `BaseCircuitBuilder::configure_with_params`.
    pub fn verify_with_vk_from_bytes(
        &self,
        vk_bytes: &[u8],
        params: &ParamsKZG<Bn256>,
        config_params: &BaseCircuitParams,
        pub_inputs: &[&[Fr]],
    ) -> bool {
        let vk = read_vk(vk_bytes, config_params);
        self.verify_with_vk(&vk, params, pub_inputs)
    }

    /// Verify a proof using a VK loaded from a file path.
    ///
    /// Loads config_params from JSON, then deserializes VK using `BaseCircuitBuilder<Fr>`.
    pub fn verify_with_vk_from_path(
        &self,
        vk_path: &str,
        params: &ParamsKZG<Bn256>,
        config_params_path: &str,
        pub_inputs: &[&[Fr]],
    ) -> bool {
        let config_params = read_config_params(config_params_path);
        let vk = read_vk_from_path(vk_path, &config_params);
        self.verify_with_vk(&vk, params, pub_inputs)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn inner(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn value(&self) -> Value<&[u8]> {
        Value::known(self.as_bytes())
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn generate_proof<C: Circuit<Fr>>(
        params: &ParamsKZG<Bn256>,
        pk: &ProvingKey<G1Affine>,
        circuit: C,
        pub_inputs: &[&[Fr]],
    ) -> Vec<u8> {
        let instances: Vec<Vec<Fr>> = pub_inputs.iter().map(|s| s.to_vec()).collect();
        let instance_refs: Vec<&[Fr]> = instances.iter().map(|v| v.as_slice()).collect();

        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
        >(
            params,
            pk,
            &[circuit],
            &[&instance_refs],
            OsRng,
            &mut transcript,
        )
        .expect("Proof generation failed");

        transcript.finalize()
    }

    /// Verify a proof using a pre-deserialized `VerifyingKey`.
    ///
    /// Use this when the VK is already loaded (e.g. from a static/lazy_static)
    /// to skip deserialization overhead on every call.
    pub fn verify_with_vk(
        &self,
        vk: &VerifyingKey<G1Affine>,
        params: &ParamsKZG<Bn256>,
        pub_inputs: &[&[Fr]],
    ) -> bool {
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(params);
        let mut transcript =
            Blake2bRead::<_, _, Challenge255<_>>::init(self.0.as_slice());
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            verifier_params,
            vk,
            strategy,
            &[pub_inputs],
            &mut transcript,
        )
        .is_ok()
    }
}
