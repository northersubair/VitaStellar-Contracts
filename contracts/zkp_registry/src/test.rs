extern crate std;

use super::verifier::proof_commitment;
use super::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, String};

fn setup(env: &Env) -> (ZKPRegistryClient<'_>, Address) {
    let contract_id = env.register_contract(None, ZKPRegistry);
    let client = ZKPRegistryClient::new(env, &contract_id);
    (client, contract_id)
}

/// Build a valid 32-byte proof_data commitment for the given vk_hash and inputs.
fn make_proof_data(env: &Env, vk_hash: &BytesN<32>, inputs: &soroban_sdk::Vec<Bytes>) -> Bytes {
    let commitment = proof_commitment(env, vk_hash, inputs);
    Bytes::from_slice(env, &commitment.to_array())
}

fn make_proof(
    env: &Env,
    label: &'static [u8],
    proof_type: ZKPType,
    hash: ZKPHashFunction,
) -> ZKProof {
    let vk_hash = BytesN::from_array(env, &[1u8; 32]);
    let public_inputs = vec![env, Bytes::from_slice(env, label)];
    let proof_data = make_proof_data(env, &vk_hash, &public_inputs);
    ZKProof {
        proof_type,
        hash_function: hash,
        circuit_id: String::from_str(env, "circuit"),
        public_inputs,
        proof_data,
        vk_hash,
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

// ==================== Existing functionality tests ====================

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
    let proof_data = make_proof_data(&env, &vk_hash, &inputs);

    client.submit_zkp(
        &submitter,
        &proof_id,
        &ZKPType::SNARK,
        &ZKPHashFunction::Poseidon,
        &circuit_id,
        &inputs,
        &proof_data,
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

// ==================== verify_zkp_internal unit tests ====================

/// Helper: build a ZKProof with correct commitment (passes verification).
fn valid_zkp(env: &Env, vk_hash: [u8; 32], input: &[u8]) -> ZKProof {
    let vk = BytesN::from_array(env, &vk_hash);
    let inputs = vec![env, Bytes::from_slice(env, input)];
    let proof_data = make_proof_data(env, &vk, &inputs);
    ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(env, "c1"),
        public_inputs: inputs,
        proof_data,
        vk_hash: vk,
        verification_gas: 1_000,
        created_at: 0,
    }
}

fn env_with_contract() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);
    let id = env.register_contract(None, ZKPRegistry);
    let client = ZKPRegistryClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, id)
}

#[test]
fn test_zkp_valid_commitment_passes() {
    let (env, id) = env_with_contract();
    let client = ZKPRegistryClient::new(&env, &id);
    let admin = Address::generate(&env);
    let circuit_id = String::from_str(&env, "c1");
    let vk = BytesN::from_array(&env, &[7u8; 32]);
    let pk = BytesN::from_array(&env, &[8u8; 32]);
    client.register_circuit(
        &admin,
        &circuit_id,
        &ZKPType::SNARK,
        &1,
        &1,
        &10,
        &128,
        &vk,
        &pk,
        &false,
    );

    let inputs = vec![&env, Bytes::from_slice(&env, b"pub_input")];
    let proof_data = make_proof_data(&env, &vk, &inputs);
    let proof_id = BytesN::from_array(&env, &[9u8; 32]);
    let submitter = Address::generate(&env);

    client.submit_zkp(
        &submitter,
        &proof_id,
        &ZKPType::SNARK,
        &ZKPHashFunction::Poseidon,
        &circuit_id,
        &inputs,
        &proof_data,
        &vk,
        &10_000,
    );
    assert!(client.get_verification_result(&proof_id).is_valid);
}

#[test]
fn test_zkp_empty_proof_data_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "t1");
    let bad_proof = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c1"),
        public_inputs: vec![&env, Bytes::from_slice(&env, b"x")],
        proof_data: Bytes::new(&env),
        vk_hash: BytesN::from_array(&env, &[1u8; 32]),
        verification_gas: 1_000,
        created_at: 0,
    };
    let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    let r =
        client.try_create_credential_proof(&holder, &ctype, &issuer, &bad_proof, &good_proof, &exp);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_zkp_short_proof_data_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "t2");
    let bad_proof = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c1"),
        public_inputs: vec![&env, Bytes::from_slice(&env, b"x")],
        proof_data: Bytes::from_slice(&env, b"tooshort"),
        vk_hash: BytesN::from_array(&env, &[1u8; 32]),
        verification_gas: 1_000,
        created_at: 0,
    };
    let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    let r =
        client.try_create_credential_proof(&holder, &ctype, &issuer, &bad_proof, &good_proof, &exp);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_zkp_wrong_vk_hash_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "t3");

    let correct_vk = BytesN::from_array(&env, &[1u8; 32]);
    let wrong_vk = BytesN::from_array(&env, &[2u8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"validity")];
    // proof_data is computed with correct_vk but submitted with wrong_vk
    let proof_data = make_proof_data(&env, &correct_vk, &inputs);
    let bad_proof = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c1"),
        public_inputs: inputs,
        proof_data,
        vk_hash: wrong_vk,
        verification_gas: 1_000,
        created_at: 0,
    };
    let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    let r =
        client.try_create_credential_proof(&holder, &ctype, &issuer, &bad_proof, &good_proof, &exp);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_zkp_wrong_inputs_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "t4");

    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let original_inputs = vec![&env, Bytes::from_slice(&env, b"real_input")];
    let tampered_inputs = vec![&env, Bytes::from_slice(&env, b"forged_input")];
    // proof_data matches original_inputs, but proof carries tampered_inputs
    let proof_data = make_proof_data(&env, &vk, &original_inputs);
    let bad_proof = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c1"),
        public_inputs: tampered_inputs,
        proof_data,
        vk_hash: vk,
        verification_gas: 1_000,
        created_at: 0,
    };
    let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    let r =
        client.try_create_credential_proof(&holder, &ctype, &issuer, &bad_proof, &good_proof, &exp);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_zkp_empty_public_inputs_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "t5");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let bad_proof = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c1"),
        public_inputs: soroban_sdk::Vec::new(&env),
        proof_data: Bytes::from_slice(&env, &[0u8; 32]),
        vk_hash: vk,
        verification_gas: 1_000,
        created_at: 0,
    };
    let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    let r =
        client.try_create_credential_proof(&holder, &ctype, &issuer, &bad_proof, &good_proof, &exp);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_zkp_empty_input_element_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "t6");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let bad_proof = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c1"),
        public_inputs: vec![&env, Bytes::new(&env)], // empty input element
        proof_data: Bytes::from_slice(&env, &[0u8; 32]),
        vk_hash: vk,
        verification_gas: 1_000,
        created_at: 0,
    };
    let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    let r =
        client.try_create_credential_proof(&holder, &ctype, &issuer, &bad_proof, &good_proof, &exp);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_zkp_tampered_first_commitment_byte_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "t7");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"validity")];
    let mut proof_bytes = [0u8; 32];
    make_proof_data(&env, &vk, &inputs).copy_into_slice(&mut proof_bytes);
    proof_bytes[0] ^= 0x01; // flip first byte
    let bad_proof = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c1"),
        public_inputs: inputs,
        proof_data: Bytes::from_slice(&env, &proof_bytes),
        vk_hash: vk,
        verification_gas: 1_000,
        created_at: 0,
    };
    let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    let r =
        client.try_create_credential_proof(&holder, &ctype, &issuer, &bad_proof, &good_proof, &exp);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_zkp_tampered_last_commitment_byte_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "t8");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"validity")];
    let mut proof_bytes = [0u8; 32];
    make_proof_data(&env, &vk, &inputs).copy_into_slice(&mut proof_bytes);
    proof_bytes[31] ^= 0xff;
    let bad_proof = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c1"),
        public_inputs: inputs,
        proof_data: Bytes::from_slice(&env, &proof_bytes),
        vk_hash: vk,
        verification_gas: 1_000,
        created_at: 0,
    };
    let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    let r =
        client.try_create_credential_proof(&holder, &ctype, &issuer, &bad_proof, &good_proof, &exp);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_zkp_all_zero_commitment_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "t9");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"x")];
    let bad_proof = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "c1"),
        public_inputs: inputs,
        proof_data: Bytes::from_slice(&env, &[0u8; 32]),
        vk_hash: vk,
        verification_gas: 1_000,
        created_at: 0,
    };
    let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    let r =
        client.try_create_credential_proof(&holder, &ctype, &issuer, &bad_proof, &good_proof, &exp);
    assert_eq!(r, Err(Ok(Error::InvalidProof)));
}

#[test]
fn test_zkp_snark_type_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "snark_type");
    let p1 = make_proof(&env, b"validity", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let p2 = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::MiMC);
    let exp = make_expiration_payload(&env, 2_000_000);
    client.create_credential_proof(&holder, &ctype, &issuer, &p1, &p2, &exp);
    assert!(client.get_credential_proof(&holder, &ctype).is_verified);
}

#[test]
fn test_zkp_stark_type_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "stark_type");
    let p1 = make_proof(&env, b"validity", ZKPType::STARK, ZKPHashFunction::SHA256);
    let p2 = make_proof(&env, b"attr", ZKPType::STARK, ZKPHashFunction::Rescue);
    let exp = make_expiration_payload(&env, 2_000_000);
    client.create_credential_proof(&holder, &ctype, &issuer, &p1, &p2, &exp);
    assert!(client.get_credential_proof(&holder, &ctype).is_verified);
}

#[test]
fn test_zkp_bulletproof_type_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "bp_type");
    let p1 = make_proof(
        &env,
        b"validity",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let p2 = make_proof(
        &env,
        b"attr",
        ZKPType::Bulletproof,
        ZKPHashFunction::Poseidon,
    );
    let exp = make_expiration_payload(&env, 2_000_000);
    client.create_credential_proof(&holder, &ctype, &issuer, &p1, &p2, &exp);
    assert!(client.get_credential_proof(&holder, &ctype).is_verified);
}

#[test]
fn test_zkp_pedersen_type_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "ped_type");
    let p1 = make_proof(
        &env,
        b"validity",
        ZKPType::PedersenCommitment,
        ZKPHashFunction::MiMC,
    );
    let p2 = make_proof(
        &env,
        b"attr",
        ZKPType::PedersenCommitment,
        ZKPHashFunction::MiMC,
    );
    let exp = make_expiration_payload(&env, 2_000_000);
    client.create_credential_proof(&holder, &ctype, &issuer, &p1, &p2, &exp);
    assert!(client.get_credential_proof(&holder, &ctype).is_verified);
}

#[test]
fn test_zkp_recursive_type_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "rec_type");
    let p1 = make_proof(
        &env,
        b"validity",
        ZKPType::Recursive,
        ZKPHashFunction::Rescue,
    );
    let p2 = make_proof(&env, b"attr", ZKPType::Recursive, ZKPHashFunction::Rescue);
    let exp = make_expiration_payload(&env, 2_000_000);
    client.create_credential_proof(&holder, &ctype, &issuer, &p1, &p2, &exp);
    assert!(client.get_credential_proof(&holder, &ctype).is_verified);
}

#[test]
fn test_zkp_multiple_public_inputs_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "multi_in");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let inputs = vec![
        &env,
        Bytes::from_slice(&env, b"in0"),
        Bytes::from_slice(&env, b"in1"),
        Bytes::from_slice(&env, b"in2"),
    ];
    let proof_data = make_proof_data(&env, &vk, &inputs);
    let p1 = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "circuit"),
        public_inputs: inputs,
        proof_data,
        vk_hash: vk,
        verification_gas: 1_000,
        created_at: 0,
    };
    let p2 = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    client.create_credential_proof(&holder, &ctype, &issuer, &p1, &p2, &exp);
    assert!(client.get_credential_proof(&holder, &ctype).is_verified);
}

#[test]
fn test_zkp_extra_proof_bytes_after_commitment_valid() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let holder = Address::generate(&env);
    let issuer = Address::generate(&env);
    let ctype = String::from_str(&env, "extra_bytes");
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"validity")];
    let commitment = make_proof_data(&env, &vk, &inputs);
    // Append extra non-commitment bytes after the 32-byte prefix
    let mut proof_data = commitment;
    proof_data.append(&Bytes::from_slice(&env, b"extra_arbitrary_data_for_proof"));
    let p1 = ZKProof {
        proof_type: ZKPType::SNARK,
        hash_function: ZKPHashFunction::Poseidon,
        circuit_id: String::from_str(&env, "circuit"),
        public_inputs: inputs,
        proof_data,
        vk_hash: vk,
        verification_gas: 1_000,
        created_at: 0,
    };
    let p2 = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
    let exp = make_expiration_payload(&env, 2_000_000);
    client.create_credential_proof(&holder, &ctype, &issuer, &p1, &p2, &exp);
    assert!(client.get_credential_proof(&holder, &ctype).is_verified);
}

#[test]
fn test_zkp_different_vk_hashes_produce_different_commitments() {
    let env = Env::default();
    let vk_a = BytesN::from_array(&env, &[0xaau8; 32]);
    let vk_b = BytesN::from_array(&env, &[0xbbu8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"same_input")];
    let comm_a = proof_commitment(&env, &vk_a, &inputs);
    let comm_b = proof_commitment(&env, &vk_b, &inputs);
    assert_ne!(comm_a.to_array(), comm_b.to_array());
}

#[test]
fn test_zkp_different_inputs_produce_different_commitments() {
    let env = Env::default();
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let inputs_a = vec![&env, Bytes::from_slice(&env, b"input_a")];
    let inputs_b = vec![&env, Bytes::from_slice(&env, b"input_b")];
    let comm_a = proof_commitment(&env, &vk, &inputs_a);
    let comm_b = proof_commitment(&env, &vk, &inputs_b);
    assert_ne!(comm_a.to_array(), comm_b.to_array());
}

#[test]
fn test_zkp_same_inputs_same_vk_deterministic() {
    let env = Env::default();
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"deterministic")];
    let c1 = proof_commitment(&env, &vk, &inputs);
    let c2 = proof_commitment(&env, &vk, &inputs);
    assert_eq!(c1.to_array(), c2.to_array());
}

#[test]
fn test_zkp_property_any_single_input_byte_flip_rejected() {
    // Flip every byte in the 32-byte proof_data commitment and confirm each flip fails.
    let env = Env::default();
    env.mock_all_auths();
    let (client, _) = init_contract(&env);
    let vk = BytesN::from_array(&env, &[1u8; 32]);
    let inputs = vec![&env, Bytes::from_slice(&env, b"prop_test")];
    let mut proof_bytes = [0u8; 32];
    make_proof_data(&env, &vk, &inputs).copy_into_slice(&mut proof_bytes);

    for i in 0..32usize {
        let mut tampered = proof_bytes;
        tampered[i] ^= 0x80;
        let holder = Address::generate(&env);
        let issuer = Address::generate(&env);
        let ctype = String::from_str(&env, "prop");
        let bad_proof = ZKProof {
            proof_type: ZKPType::SNARK,
            hash_function: ZKPHashFunction::Poseidon,
            circuit_id: String::from_str(&env, "c1"),
            public_inputs: inputs.clone(),
            proof_data: Bytes::from_slice(&env, &tampered),
            vk_hash: vk.clone(),
            verification_gas: 1_000,
            created_at: 0,
        };
        let good_proof = make_proof(&env, b"attr", ZKPType::SNARK, ZKPHashFunction::Poseidon);
        let exp = make_expiration_payload(&env, 2_000_000);
        let r = client.try_create_credential_proof(
            &holder,
            &ctype,
            &issuer,
            &bad_proof,
            &good_proof,
            &exp,
        );
        assert_eq!(
            r,
            Err(Ok(Error::InvalidProof)),
            "bit flip at byte {i} should fail"
        );
    }
}
