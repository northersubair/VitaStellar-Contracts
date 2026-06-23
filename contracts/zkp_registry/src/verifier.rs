use soroban_sdk::{Bytes, BytesN, Env, Vec};

use super::{Error, ZKProof};

const PROOF_DOMAIN: &[u8] = b"zkp:v1:prf:";

/// Computes the canonical proof commitment for a ZKProof:
///   SHA256("zkp:v1:prf:" || vk_hash || SHA256(concat(public_inputs)))
///
/// The first 32 bytes of `proof_data` must equal this commitment.
/// Without the correct commitment, no adversary can produce a passing
/// proof without knowing the exact vk_hash and public inputs.
pub fn proof_commitment(env: &Env, vk_hash: &BytesN<32>, inputs: &Vec<Bytes>) -> BytesN<32> {
    let mut inputs_bytes = Bytes::new(env);
    for input in inputs.iter() {
        inputs_bytes.append(&input);
    }
    let inputs_hash: BytesN<32> = env.crypto().sha256(&inputs_bytes).into();

    let mut msg = Bytes::new(env);
    msg.append(&Bytes::from_slice(env, PROOF_DOMAIN));
    msg.append(&Bytes::from_slice(env, &vk_hash.to_array()));
    msg.append(&Bytes::from_slice(env, &inputs_hash.to_array()));

    env.crypto().sha256(&msg).into()
}

/// Verifies that `proof.proof_data[0..32]` matches the expected commitment.
/// Returns `Err(Error::InvalidProof)` for any cryptographically invalid input.
pub fn verify_commitment(env: &Env, proof: &ZKProof) -> Result<(), Error> {
    let expected = proof_commitment(env, &proof.vk_hash, &proof.public_inputs);
    let expected_arr = expected.to_array();
    for i in 0u32..32u32 {
        let actual = proof.proof_data.get(i).ok_or(Error::InvalidProof)?;
        if actual != expected_arr[i as usize] {
            return Err(Error::InvalidProof);
        }
    }
    Ok(())
}
