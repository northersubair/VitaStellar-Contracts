extern crate std;

use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, String};

fn setup(env: &Env) -> (ZKPRegistryClient<'_>, Address) {
    let contract_id = env.register_contract(None, ZKPRegistry);
    let client = ZKPRegistryClient::new(env, &contract_id);
    (client, contract_id)
}

fn make_proof(
    env: &Env,
    label: &'static [u8],
    proof_type: ZKPType,
    hash: ZKPHashFunction,
) -> ZKProof {
    ZKProof {
        proof_type,
        hash_function: hash,
        circuit_id: String::from_str(env, "circuit"),
        public_inputs: vec![env, Bytes::from_slice(env, label)],
        proof_data: Bytes::from_slice(env, b"0123456789abcdef0123456789abcdef"),
        vk_hash: BytesN::from_array(env, &[1u8; 32]),
        verification_gas: 50_000,
        created_at: env.ledger().timestamp(),
    }
}

fn make_expiration_payload(env: &Env, valid_until: u64) -> Bytes {
    let mut out = Bytes::new(env);
    out.append(&Bytes::from_slice(env, &valid_until.to_be_bytes()));
    let mut commitment_payload = Bytes::new(env);
    commitment_payload.append(&Bytes::from_slice(env, b"zkp_registry:cred_exp"));
    commitment_payload.append(&Bytes::from_slice(env, &valid_until.to_be_bytes()));
    let commitment: BytesN<32> = env.crypto().sha256(&commitment_payload).into();
    out.append(&Bytes::from_slice(env, &commitment.to_array()));
    out
}

fn init_contract(env: &Env) -> (ZKPRegistryClient<'_>, Address) {
    let (client, contract_id) = setup(env);
    let admin = Address::generate(env);
    client.initialize(&admin);
    (client, contract_id)
}

#[test]
fn test_initialize_and_register_circuit() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let (client, _id) = setup(&env);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let circuit_id = String::from_str(&env, "circuit-a");
    let vk_hash = BytesN::from_array(&env, &[2u8; 32]);
    let pk_hash = BytesN::from_array(&env, &[3u8; 32]);
    client.register_circuit(
        &admin,
        &circuit_id,
        &ZKPType::SNARK,
        &2u32,
        &3u32,
        &100u32,
        &128u32,
        &vk_hash,
        &pk_hash,
        &true,
    );

    let params = client.get_circuit_params(&circuit_id);
    assert_eq!(params.circuit_id, circuit_id);
    assert_eq!(params.circuit_type, ZKPType::SNARK);
    assert_eq!(params.num_public_inputs, 2);
}

#[test]
fn test_submit_zkp_smoke() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let (client, _) = setup(&env);
    let admin = Address::generate(&env);
    client.initialize(&admin);

    let circuit_id = String::from_str(&env, "circuit-b");
    let vk_hash = BytesN::from_array(&env, &[4u8; 32]);
    let pk_hash = BytesN::from_array(&env, &[5u8; 32]);
    client.register_circuit(
        &admin,
        &circuit_id,
        &ZKPType::SNARK,
        &1u32,
        &1u32,
        &50u32,
        &128u32,
        &vk_hash,
        &pk_hash,
        &false,
    );

    let submitter = Address::generate(&env);
    let proof_id = BytesN::from_array(&env, &[6u8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"input")];
    let proof = Bytes::from_slice(&env, b"0123456789abcdef0123456789abcdef");

    client.submit_zkp(
        &submitter,
        &proof_id,
        &ZKPType::SNARK,
        &ZKPHashFunction::Poseidon,
        &circuit_id,
        &inputs,
        &proof,
        &vk_hash,
        &50_000u64,
    );

    let result = client.get_verification_result(&proof_id);
    assert!(result.is_valid);
    assert_eq!(result.verifier, submitter);
}

#[test]
fn test_create_credential_proof_valid_future_window() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "medical_license");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 1_000_100);

    client.create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    let proof = client.get_credential_proof(&holder, &credential_type);
    assert_eq!(proof.issuer, issuer);
    assert!(proof.is_verified);
}

#[test]
fn test_create_credential_proof_about_to_expire() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "researcher");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 1_000_001);

    client.create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert!(
        client
            .get_credential_proof(&holder, &credential_type)
            .is_verified
    );
}

#[test]
fn test_create_credential_proof_exact_boundary_is_valid() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "nurse");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 1_000_000);

    client.create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert!(
        client
            .get_credential_proof(&holder, &credential_type)
            .is_verified
    );
}

#[test]
fn test_create_credential_proof_future_far_is_valid() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "surgeon");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 9_999_999);

    client.create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert!(
        client
            .get_credential_proof(&holder, &credential_type)
            .is_verified
    );
}

#[test]
fn test_create_credential_proof_expired_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "pharmacist");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = make_expiration_payload(&env, 999_999);

    let result = client.try_create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert_eq!(result, Err(Ok(Error::CredentialExpired)));
}

#[test]
fn test_create_credential_proof_tampered_commitment_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "pathologist");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let mut encrypted_expiration = make_expiration_payload(&env, 1_000_050);
    let mut tampered = [0u8; 40];
    encrypted_expiration.copy_into_slice(&mut tampered);
    tampered[39] ^= 0x01;
    encrypted_expiration = Bytes::from_slice(&env, &tampered);

    let result = client.try_create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert_eq!(result, Err(Ok(Error::CommitmentMismatch)));
}

#[test]
fn test_create_credential_proof_short_payload_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, _) = init_contract(&env);

    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let credential_type = String::from_str(&env, "therapist");
    let validity_proof = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::SHA256);
    let attribute_proof = make_proof(
        &env,
        b"attribute",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let encrypted_expiration = Bytes::from_slice(&env, b"short");

    let result = client.try_create_credential_proof(
        &holder,
        &credential_type,
        &issuer,
        &validity_proof,
        &attribute_proof,
        &encrypted_expiration,
    );

    assert_eq!(result, Err(Ok(Error::InvalidInput)));
}

// ==================== verify_recursive_proof_internal tests ====================

use super::recursive_proof::{make_aggregated_vk, recursive_commitment};

/// Registers a base ZKP so create_recursive_proof can look it up.
fn register_base_proof(
    env: &Env,
    client: &ZKPRegistryClient<'_>,
    proof_id: &BytesN<32>,
    vk: &BytesN<32>,
    pk: &BytesN<32>,
) {
    let admin = Address::generate(env);
    let circuit_id = String::from_str(env, "base_circuit");
    client.register_circuit(
        &admin,
        &circuit_id,
        &ZKPType::SNARK,
        &1,
        &1,
        &10,
        &128,
        vk,
        pk,
        &false,
    );
    let submitter = Address::generate(env);
    let inputs = vec![env, Bytes::from_slice(env, b"base_input")];
    let pd = Bytes::from_slice(env, b"0123456789abcdef0123456789abcdef");
    // Use old-style (non-verifier) path: just store the raw proof directly
    env.as_contract(&client.address, || {
        let proof_struct = ZKProof {
            proof_type: ZKPType::SNARK,
            hash_function: ZKPHashFunction::Poseidon,
            circuit_id: circuit_id.clone(),
            public_inputs: inputs.clone(),
            proof_data: pd.clone(),
            vk_hash: vk.clone(),
            verification_gas: 1_000,
            created_at: 0,
        };
        env.storage()
            .persistent()
            .set(&DataKey::ZKProof(proof_id.clone()), &proof_struct);
    });
}

fn make_recursive_proof_struct(
    env: &Env,
    base_id: &BytesN<32>,
    vk: &BytesN<32>,
    depth: u32,
) -> (RecursiveProof, Bytes) {
    let inner = ZKProof {
        proof_type: ZKPType::Recursive,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(env, "rec_circuit"),
        public_inputs: vec![env, Bytes::from_slice(env, b"rec_in")],
        proof_data: Bytes::from_slice(env, b"0123456789abcdef0123456789abcdef"),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let rp = RecursiveProof {
        base_proof_id: base_id.clone(),
        recursive_proof: inner,
        aggregated_vk: Bytes::new(env),
        composition_depth: depth,
        total_gas: 5_000,
        composed_at: 0,
    };
    let agg_vk = make_aggregated_vk(env, &rp);
    (rp, agg_vk)
}

fn init_rec(env: &Env) -> (ZKPRegistryClient<'_>, BytesN<32>, BytesN<32>) {
    let id = env.register_contract(None, ZKPRegistry);
    let client = ZKPRegistryClient::new(env, &id);
    let admin = Address::generate(env);
    client.initialize(&admin);
    let vk = BytesN::from_array(env, &[0x22u8; 32]);
    let pk = BytesN::from_array(env, &[0x33u8; 32]);
    let base_id = BytesN::from_array(env, &[0x11u8; 32]);
    register_base_proof(env, &client, &base_id, &vk, &pk);
    (client, base_id, vk)
}

#[test]
fn test_recursive_proof_depth_1_passes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, base_id, vk) = init_rec(&env);

    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    let composer = Address::generate(&env);
    client.create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &agg_vk,
        &1,
        &5_000,
    );
}

#[test]
fn test_recursive_proof_depth_3_passes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, base_id, vk) = init_rec(&env);

    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 3);
    let composer = Address::generate(&env);
    client.create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &agg_vk,
        &3,
        &5_000,
    );
}

#[test]
fn test_recursive_proof_max_depth_10_passes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, base_id, vk) = init_rec(&env);

    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 10);
    let composer = Address::generate(&env);
    client.create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &agg_vk,
        &10,
        &5_000,
    );
}

#[test]
fn test_recursive_proof_depth_0_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, base_id, vk) = init_rec(&env);

    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    let composer = Address::generate(&env);
    let r = client.try_create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &agg_vk,
        &0,
        &5_000,
    );
    assert_eq!(r, Err(Ok(Error::RecursiveDepthExceeded)));
}

#[test]
fn test_recursive_proof_depth_11_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, base_id, vk) = init_rec(&env);
    let (rp, _) = make_recursive_proof_struct(&env, &base_id, &vk, 11);
    let agg_vk = Bytes::from_slice(&env, &[0u8; 32]);
    let composer = Address::generate(&env);
    let r = client.try_create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &agg_vk,
        &11,
        &5_000,
    );
    assert_eq!(r, Err(Ok(Error::RecursiveDepthExceeded)));
}

#[test]
fn test_recursive_proof_empty_aggregated_vk_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, base_id, vk) = init_rec(&env);
    let (rp, _) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    let composer = Address::generate(&env);
    let r = client.try_create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &Bytes::new(&env),
        &1,
        &5_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_recursive_proof_short_aggregated_vk_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, base_id, vk) = init_rec(&env);
    let (rp, _) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    let composer = Address::generate(&env);
    let r = client.try_create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &Bytes::from_slice(&env, b"tooshort"),
        &1,
        &5_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_recursive_proof_wrong_base_proof_id_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, base_id, vk) = init_rec(&env);
    let wrong_base_id = BytesN::from_array(&env, &[0xffu8; 32]);
    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    let composer = Address::generate(&env);
    // agg_vk was built for base_id, but we pass wrong_base_id in both slots
    // The contract checks ZKProof(wrong_base_id) exists first, which it doesn't
    let r = client.try_create_recursive_proof(
        &composer,
        &wrong_base_id,
        &rp.recursive_proof,
        &agg_vk,
        &1,
        &5_000,
    );
    assert_eq!(r, Err(Ok(Error::ProofNotFound)));
}

#[test]
fn test_recursive_proof_wrong_vk_hash_in_commitment_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, base_id, vk) = init_rec(&env);
    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 2);
    // Swap to a different recursive_proof with a different vk_hash (still depth=2)
    let wrong_vk = BytesN::from_array(&env, &[0xeeu8; 32]);
    let bad_inner = ZKProof {
        vk_hash: wrong_vk,
        ..rp.recursive_proof.clone()
    };
    let composer = Address::generate(&env);
    let r = client.try_create_recursive_proof(&composer, &base_id, &bad_inner, &agg_vk, &2, &5_000);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_recursive_proof_wrong_depth_in_commitment_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, base_id, vk) = init_rec(&env);
    // Build valid aggregated_vk for depth=1, but submit as depth=2
    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    let composer = Address::generate(&env);
    let r = client.try_create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &agg_vk,
        &2,
        &5_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_recursive_proof_tampered_first_byte_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, base_id, vk) = init_rec(&env);
    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    let mut agg_bytes = [0u8; 32];
    agg_vk.copy_into_slice(&mut agg_bytes);
    agg_bytes[0] ^= 0x01;
    let composer = Address::generate(&env);
    let r = client.try_create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &Bytes::from_slice(&env, &agg_bytes),
        &1,
        &5_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_recursive_proof_tampered_last_byte_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, base_id, vk) = init_rec(&env);
    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    let mut agg_bytes = [0u8; 32];
    agg_vk.copy_into_slice(&mut agg_bytes);
    agg_bytes[31] ^= 0xff;
    let composer = Address::generate(&env);
    let r = client.try_create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &Bytes::from_slice(&env, &agg_bytes),
        &1,
        &5_000,
    );
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_recursive_proof_extra_vk_bytes_still_passes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, base_id, vk) = init_rec(&env);
    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    // Append extra bytes after the 32-byte commitment prefix
    let mut extended = agg_vk;
    extended.append(&Bytes::from_slice(&env, b"extra_data"));
    let composer = Address::generate(&env);
    client.create_recursive_proof(
        &composer,
        &base_id,
        &rp.recursive_proof,
        &extended,
        &1,
        &5_000,
    );
}

#[test]
fn test_recursive_commitment_different_depths_produce_different_hashes() {
    let env = Env::default();
    let base_id = BytesN::from_array(&env, &[1u8; 32]);
    let vk = BytesN::from_array(&env, &[2u8; 32]);
    let inner = ZKProof {
        proof_type: ZKPType::Recursive,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c"),
        public_inputs: vec![&env, Bytes::from_slice(&env, b"x")],
        proof_data: Bytes::from_slice(&env, b"0123456789abcdef0123456789abcdef"),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let rp1 = RecursiveProof {
        base_proof_id: base_id.clone(),
        recursive_proof: inner.clone(),
        aggregated_vk: Bytes::new(&env),
        composition_depth: 1,
        total_gas: 0,
        composed_at: 0,
    };
    let rp3 = RecursiveProof {
        base_proof_id: base_id.clone(),
        recursive_proof: inner.clone(),
        aggregated_vk: Bytes::new(&env),
        composition_depth: 3,
        total_gas: 0,
        composed_at: 0,
    };
    assert_ne!(
        recursive_commitment(&env, &rp1).to_array(),
        recursive_commitment(&env, &rp3).to_array()
    );
}

#[test]
fn test_recursive_commitment_different_base_ids_produce_different_hashes() {
    let env = Env::default();
    let base_a = BytesN::from_array(&env, &[0xaau8; 32]);
    let base_b = BytesN::from_array(&env, &[0xbbu8; 32]);
    let vk = BytesN::from_array(&env, &[2u8; 32]);
    let inner = ZKProof {
        proof_type: ZKPType::Recursive,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c"),
        public_inputs: vec![&env, Bytes::from_slice(&env, b"x")],
        proof_data: Bytes::from_slice(&env, b"0123456789abcdef0123456789abcdef"),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let rp_a = RecursiveProof {
        base_proof_id: base_a,
        recursive_proof: inner.clone(),
        aggregated_vk: Bytes::new(&env),
        composition_depth: 1,
        total_gas: 0,
        composed_at: 0,
    };
    let rp_b = RecursiveProof {
        base_proof_id: base_b,
        recursive_proof: inner.clone(),
        aggregated_vk: Bytes::new(&env),
        composition_depth: 1,
        total_gas: 0,
        composed_at: 0,
    };
    assert_ne!(
        recursive_commitment(&env, &rp_a).to_array(),
        recursive_commitment(&env, &rp_b).to_array()
    );
}

#[test]
fn test_recursive_commitment_deterministic() {
    let env = Env::default();
    let base_id = BytesN::from_array(&env, &[1u8; 32]);
    let vk = BytesN::from_array(&env, &[2u8; 32]);
    let inner = ZKProof {
        proof_type: ZKPType::Recursive,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c"),
        public_inputs: vec![&env, Bytes::from_slice(&env, b"x")],
        proof_data: Bytes::from_slice(&env, b"0123456789abcdef0123456789abcdef"),
        vk_hash: vk.clone(),
        verification_gas: 1_000,
        created_at: 0,
    };
    let rp = RecursiveProof {
        base_proof_id: base_id,
        recursive_proof: inner,
        aggregated_vk: Bytes::new(&env),
        composition_depth: 2,
        total_gas: 0,
        composed_at: 0,
    };
    assert_eq!(
        recursive_commitment(&env, &rp).to_array(),
        recursive_commitment(&env, &rp).to_array()
    );
}

#[test]
fn test_recursive_proof_prop_any_byte_flip_in_commitment_fails() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let (client, base_id, vk) = init_rec(&env);
    let (rp, agg_vk) = make_recursive_proof_struct(&env, &base_id, &vk, 1);
    let mut agg_bytes = [0u8; 32];
    agg_vk.copy_into_slice(&mut agg_bytes);

    for i in 0..32usize {
        let mut tampered = agg_bytes;
        tampered[i] ^= 0x40;
        let composer = Address::generate(&env);
        let r = client.try_create_recursive_proof(
            &composer,
            &base_id,
            &rp.recursive_proof,
            &Bytes::from_slice(&env, &tampered),
            &1,
            &5_000,
        );
        assert_eq!(
            r,
            Err(Ok(Error::InvalidProof)),
            "flip at byte {i} should fail"
        );
    }
}
