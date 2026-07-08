use hydra_core::{
    INNER_HEADER_SIZE, OUTER_HEADER_SIZE, PROTOCOL_VERSION, SUITE_ID,
    types::{ContentKind, EnvelopeClass, OuterMode},
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes, X25519SecretKey};
use hydra_envelope::{
    OuterHeader, WireError, decode_outer_header, encode_outer_header, validate_envelope_length,
};
use ml_dsa::{MlDsa65, Signature, SigningKey, signature::Keypair};
use ml_kem::{
    FromSeed, MlKem768,
    kem::{Decapsulate, KeyExport},
};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

mod group_vectors;
mod protocol_vectors;

const ROOT_LABEL: &[u8] = b"HYDRA-MSG/test-vectors/freeze-1";

fn lp(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .expect("test input length fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
}

fn tv_draw(vector_id: &str, purpose: &str, occurrence: u32, length: usize) -> Vec<u8> {
    let mut input = Vec::new();
    lp(&mut input, ROOT_LABEL);
    lp(&mut input, vector_id.as_bytes());
    lp(&mut input, purpose.as_bytes());
    input.extend_from_slice(&occurrence.to_be_bytes());

    let mut xof = Shake256::default();
    xof.update(&input);
    let mut reader = xof.finalize_xof();
    let mut output = vec![0u8; length];
    reader.read(&mut output);
    output
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    hex::encode(RustCryptoBackend::sha3_256(bytes))
}

fn write_bytes(directory: &Path, name: &str, bytes: &[u8]) {
    fs::write(directory.join(format!("{name}.bin")), bytes).expect("write binary artifact");
    let mut encoded = hex::encode(bytes);
    encoded.push('\n');
    fs::write(directory.join(format!("{name}.hex")), encoded).expect("write hex artifact");
}

fn metadata_entry(name: &str, bytes: &[u8]) -> String {
    format!(
        "{{\"length\":{},\"name\":\"{}\",\"sha3_256\":\"{}\"}}",
        bytes.len(),
        name,
        sha3_256_hex(bytes)
    )
}

struct VectorMetadata<'a> {
    backend: &'a str,
    result: &'a str,
    expected_state: &'a str,
    cleanup: &'a str,
    entropy: &'a [(&'a str, u32, usize, &'a str)],
}

fn write_metadata(
    directory: &Path,
    vector_id: &str,
    metadata: &VectorMetadata<'_>,
    artifacts: &[(&str, &[u8])],
) {
    let entries = artifacts
        .iter()
        .map(|(name, bytes)| metadata_entry(name, bytes))
        .collect::<Vec<_>>()
        .join(",");
    let entropy_entries = metadata
        .entropy
        .iter()
        .map(|(purpose, occurrence, length, artifact)| {
            format!(
                "{{\"artifact\":\"{artifact}\",\"length\":{length},\"occurrence\":{occurrence},\"purpose\":\"{purpose}\"}}"
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(
        "{{\"artifacts\":[{entries}],\"backend\":\"{}\",\"cleanup\":\"{}\",\"entropy\":[{entropy_entries}],\"expected_state\":\"{}\",\"result\":\"{}\",\"schema\":1,\"vector_id\":\"{vector_id}\"}}\n",
        metadata.backend, metadata.cleanup, metadata.expected_state, metadata.result
    );
    fs::write(directory.join("metadata.json"), json).expect("write metadata");
}

fn generate_mlkem(root: &Path) {
    const ID: &str = "TV-PQ-MLKEM-000";
    let directory = root.join("primitive").join(ID);
    fs::create_dir_all(&directory).expect("create ML-KEM vector directory");

    let d = tv_draw(ID, "mlkem-d", 0, 32);
    let z = tv_draw(ID, "mlkem-z", 0, 32);
    let m = tv_draw(ID, "mlkem-m", 0, 32);

    let mut seed_bytes = [0u8; 64];
    seed_bytes[..32].copy_from_slice(&d);
    seed_bytes[32..].copy_from_slice(&z);
    let seed: ml_kem::Seed = seed_bytes.into();
    let (dk, ek) = MlKem768::from_seed(&seed);
    let ek_bytes = ek.to_bytes();

    let mut m_array: ml_kem::B32 = [0u8; 32].into();
    m_array.copy_from_slice(&m);
    let (ct, ss) = ek.encapsulate_deterministic(&m_array);
    let recovered = dk.decapsulate(&ct);
    assert_eq!(
        ss, recovered,
        "ML-KEM decapsulation must recover shared secret"
    );

    let mut bad_ct = ct;
    bad_ct[0] ^= 1;
    let rejected_ss = dk.decapsulate(&bad_ct);
    assert_ne!(
        ss, rejected_ss,
        "mutated ciphertext must take implicit-rejection path"
    );

    let artifacts: [(&str, &[u8]); 10] = [
        ("d", &d),
        ("z", &z),
        ("m", &m),
        ("ek", ek_bytes.as_ref()),
        ("decapsulation_seed", &seed_bytes),
        ("ciphertext", ct.as_ref()),
        ("shared_secret", ss.as_ref()),
        ("decapsulated_shared_secret", recovered.as_ref()),
        ("mutated_ciphertext", bad_ct.as_ref()),
        ("implicit_rejection_shared_secret", rejected_ss.as_ref()),
    ];
    for (name, bytes) in artifacts {
        write_bytes(&directory, name, bytes);
    }
    let metadata = VectorMetadata {
        backend: "rustcrypto-single",
        result: "valid round trip; mutated ciphertext produced distinct implicit-rejection secret",
        expected_state: "primitive operation only",
        cleanup: "test fixture retains secret outputs; production temporaries must be erased",
        entropy: &[
            ("mlkem-d", 0, 32, "d"),
            ("mlkem-z", 0, 32, "z"),
            ("mlkem-m", 0, 32, "m"),
        ],
    };
    write_metadata(&directory, ID, &metadata, &artifacts);
}

fn generate_mldsa(root: &Path) {
    const ID: &str = "TV-PQ-MLDSA-000";
    let directory = root.join("primitive").join(ID);
    fs::create_dir_all(&directory).expect("create ML-DSA vector directory");

    let xi = tv_draw(ID, "mldsa-xi", 0, 32);
    let rnd = tv_draw(ID, "mldsa-rnd", 0, 32);
    let digest = tv_draw(ID, "message", 0, 64);

    let mut xi_array: ml_dsa::Seed = [0u8; 32].into();
    xi_array.copy_from_slice(&xi);
    let signing_key = SigningKey::<MlDsa65>::from_seed(&xi_array);
    let expanded = signing_key.expanded_key();
    let verifying_key = signing_key.verifying_key();

    // Pure ML-DSA with empty context internally hashes 0x00 || 0x00 || message.
    let mut pure_message = Vec::with_capacity(66);
    pure_message.extend_from_slice(&[0, 0]);
    pure_message.extend_from_slice(&digest);

    let mut rnd_array: ml_dsa::B32 = [0u8; 32].into();
    rnd_array.copy_from_slice(&rnd);
    let signature = expanded.sign_internal(&[&pure_message], &rnd_array);
    assert!(
        verifying_key.verify_internal(&pure_message, &signature),
        "ML-DSA signature must verify"
    );

    let vk_bytes = verifying_key.encode();
    let signing_key_bytes = <SigningKey<MlDsa65> as ml_dsa::KeyExport>::to_bytes(&signing_key);
    let sig_bytes = signature.encode();
    let mut bad_sig_bytes = sig_bytes;
    bad_sig_bytes[0] ^= 1;
    let bad_verified = Signature::<MlDsa65>::decode(&bad_sig_bytes)
        .is_some_and(|candidate| verifying_key.verify_internal(&pure_message, &candidate));
    assert!(!bad_verified, "mutated ML-DSA signature must not verify");

    let bad_result = [u8::from(bad_verified)];
    let artifacts: [(&str, &[u8]); 9] = [
        ("xi", &xi),
        ("rnd", &rnd),
        ("digest", &digest),
        ("pure_mldsa_message", &pure_message),
        ("verification_key", vk_bytes.as_ref()),
        ("signing_key", signing_key_bytes.as_ref()),
        ("signature", sig_bytes.as_ref()),
        ("mutated_signature", bad_sig_bytes.as_ref()),
        ("mutated_signature_verified", &bad_result),
    ];
    for (name, bytes) in artifacts {
        write_bytes(&directory, name, bytes);
    }
    let metadata = VectorMetadata {
        backend: "rustcrypto-single",
        result: "valid signature verified; mutated signature rejected",
        expected_state: "primitive operation only",
        cleanup: "test fixture retains secret outputs; production temporaries must be erased",
        entropy: &[
            ("mldsa-xi", 0, 32, "xi"),
            ("mldsa-rnd", 0, 32, "rnd"),
            ("message", 0, 64, "digest"),
        ],
    };
    write_metadata(&directory, ID, &metadata, &artifacts);
}

fn generate_envelope_vectors(root: &Path) {
    const ID: &str = "TV-HDR-000";
    let directory = root.join("envelope").join(ID);
    fs::create_dir_all(&directory).expect("create envelope vector directory");

    let header = OuterHeader::new(
        OuterMode::Protected,
        EnvelopeClass::Full,
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ],
        0x0102_0304_0506_0708,
    );
    let encoded = encode_outer_header(&header).expect("canonical suite must encode");
    let documented = hex::decode(
        "48594431010303004859445241312d4d4b3736382d4d3635\
         000102030405060708090a0b0c0d0e0f0102030405060708\
         00000000000000000000000000000000",
    )
    .expect("documented header hex is valid");
    assert_eq!(
        encoded.as_slice(),
        documented,
        "TV-HDR-000 must match the documented bytes"
    );

    let artifacts: [(&str, &[u8]); 1] = [("outer_header", &encoded)];
    write_bytes(&directory, "outer_header", &encoded);
    let metadata = VectorMetadata {
        backend: "hydra-envelope",
        result: "canonical Full protected outer header reproduced",
        expected_state: "serialization operation only",
        cleanup: "no secret material",
        entropy: &[],
    };
    write_metadata(&directory, ID, &metadata, &artifacts);

    let mut full_envelope = vec![0_u8; EnvelopeClass::Full.envelope_size()];
    full_envelope[..OUTER_HEADER_SIZE].copy_from_slice(&encoded);

    let mut mutation = full_envelope.clone();
    mutation[0] ^= 1;
    assert_eq!(decode_outer_header(&mutation), Err(WireError::InvalidMagic));

    mutation = full_envelope.clone();
    mutation[4] = 0x02;
    assert_eq!(
        decode_outer_header(&mutation),
        Err(WireError::UnsupportedVersion(0x02))
    );

    mutation = full_envelope.clone();
    mutation[5] = 0xff;
    assert_eq!(
        decode_outer_header(&mutation),
        Err(WireError::InvalidMode(0xff))
    );

    for invalid_class in [0x00, 0xff] {
        mutation = full_envelope.clone();
        mutation[6] = invalid_class;
        assert_eq!(
            decode_outer_header(&mutation),
            Err(WireError::InvalidEnvelopeClass(invalid_class))
        );
    }

    mutation = full_envelope.clone();
    mutation[7] = 0x01;
    assert_eq!(
        decode_outer_header(&mutation),
        Err(WireError::NonZeroReserved)
    );

    mutation = full_envelope.clone();
    mutation[8] ^= 1;
    assert!(matches!(
        decode_outer_header(&mutation),
        Err(WireError::UnsupportedSuite(_))
    ));

    mutation = full_envelope;
    mutation[48] = 0x01;
    assert_eq!(
        decode_outer_header(&mutation),
        Err(WireError::NonZeroReserved)
    );

    let classes = [
        (EnvelopeClass::Lite, 4_096, 4_032, 4_016, 3_920),
        (EnvelopeClass::Standard, 32_768, 32_704, 32_688, 32_592),
        (EnvelopeClass::Full, 147_456, 147_392, 147_376, 147_280),
    ];
    for (class, envelope, body, record, content) in classes {
        assert_eq!(class.envelope_size(), envelope);
        assert_eq!(class.body_size(), body);
        assert_eq!(class.protected_record_size(), record);
        assert_eq!(class.max_content_size(), content);
        assert_eq!(validate_envelope_length(class, envelope), Ok(()));
        for actual in [envelope - 1, envelope + 1] {
            assert_eq!(
                validate_envelope_length(class, actual),
                Err(WireError::InvalidEnvelopeSize {
                    expected: envelope,
                    actual,
                })
            );
        }
    }
}

fn fixed<const N: usize>(bytes: &[u8], name: &str) -> [u8; N] {
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{name} must contain exactly {N} bytes"))
}

fn hash512(parts: &[&[u8]]) -> [u8; 64] {
    let mut input = Vec::new();
    for part in parts {
        input.extend_from_slice(part);
    }
    RustCryptoBackend::sha3_512(&input)
}

fn length_prefixed(value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    lp(&mut encoded, value);
    encoded
}

fn fingerprint(verification_key: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(b"HYDRA-MSG/v1/fingerprint");
    input.extend_from_slice(&SUITE_ID);
    input.extend_from_slice(verification_key);
    RustCryptoBackend::sha3_256(&input)
}

fn pure_mldsa_message(digest: &[u8; 64]) -> Vec<u8> {
    let mut message = Vec::with_capacity(66);
    message.extend_from_slice(&[0, 0]);
    message.extend_from_slice(digest);
    message
}

fn sign_digest(
    signing_key: &SigningKey<MlDsa65>,
    digest: &[u8; 64],
    randomness: &[u8; 32],
) -> [u8; 3309] {
    let message = pure_mldsa_message(digest);
    let randomness: ml_dsa::B32 = (*randomness).into();
    let signature = signing_key
        .expanded_key()
        .sign_internal(&[&message], &randomness);
    assert!(
        signing_key
            .verifying_key()
            .verify_internal(&message, &signature),
        "generated Pure ML-DSA signature must verify"
    );
    signature.encode().into()
}

fn expand32(key: &[u8; 32], label: &[u8], context: &[u8]) -> [u8; 32] {
    let mut info = Vec::new();
    lp(&mut info, label);
    lp(&mut info, context);
    let output = RustCryptoBackend::hkdf_expand(key, &info, 32).expect("32-byte HKDF expand");
    fixed(&output, "HKDF output")
}

fn hmac256(key: &[u8; 32], input: &[u8]) -> [u8; 32] {
    RustCryptoBackend::hmac_sha3_256(&SecretBytes::from_array(*key), input)
}

fn bootstrap_envelope(
    mode: OuterMode,
    route_tag: [u8; 16],
    control: &[u8],
    signature: &[u8; 3309],
    authenticator: &[u8; 32],
) -> Vec<u8> {
    let header = encode_outer_header(&OuterHeader::new(
        mode,
        EnvelopeClass::Standard,
        route_tag,
        0,
    ))
    .expect("fixed suite outer header");
    let mut envelope = vec![0_u8; EnvelopeClass::Standard.envelope_size()];
    envelope[..OUTER_HEADER_SIZE].copy_from_slice(&header);
    let body = &mut envelope[OUTER_HEADER_SIZE..];
    body[..4].copy_from_slice(
        &u32::try_from(control.len())
            .expect("bootstrap control length fits u32")
            .to_be_bytes(),
    );
    let control_end = 4 + control.len();
    body[4..control_end].copy_from_slice(control);
    let signature_end = control_end + signature.len();
    body[control_end..signature_end].copy_from_slice(signature);
    body[signature_end..signature_end + 32].copy_from_slice(authenticator);
    envelope
}

fn finish_plaintext(transcript_hash: &[u8; 64], session_id: &[u8; 32]) -> Vec<u8> {
    let mut content = Vec::with_capacity(96);
    content.extend_from_slice(transcript_hash);
    content.extend_from_slice(session_id);

    let mut plaintext = vec![0_u8; EnvelopeClass::Lite.protected_record_size()];
    plaintext[0] = ContentKind::HandshakeFinish as u8;
    plaintext[4..36].copy_from_slice(session_id);
    plaintext[92..INNER_HEADER_SIZE].copy_from_slice(
        &u32::try_from(content.len())
            .expect("FINISH content length fits u32")
            .to_be_bytes(),
    );
    plaintext[INNER_HEADER_SIZE..INNER_HEADER_SIZE + content.len()].copy_from_slice(&content);
    plaintext
}

fn write_vector(
    root: &Path,
    vector_id: &str,
    metadata: &VectorMetadata<'_>,
    artifacts: &[(&str, &[u8])],
) {
    let directory = root.join("handshake").join(vector_id);
    fs::create_dir_all(&directory).expect("create handshake vector directory");
    for (name, bytes) in artifacts {
        write_bytes(&directory, name, bytes);
    }
    write_metadata(&directory, vector_id, metadata, artifacts);
}

fn generate_handshake_vectors(root: &Path) {
    const INIT_ID: &str = "TV-HS-INIT-000";
    const RESP_ID: &str = "TV-HS-RESP-000";

    let init_xi = fixed::<32>(&tv_draw(INIT_ID, "mldsa-xi", 0, 32), "initiator xi");
    let init_rnd = fixed::<32>(&tv_draw(INIT_ID, "mldsa-rnd", 0, 32), "initiator rnd");
    let init_nonce = fixed::<32>(&tv_draw(INIT_ID, "nonce", 0, 32), "INIT nonce");
    let init_route = fixed::<16>(
        &tv_draw(INIT_ID, "bootstrap-route-tag", 0, 16),
        "INIT route tag",
    );
    let init_x_private = fixed::<32>(
        &tv_draw(INIT_ID, "x25519-private", 0, 32),
        "initiator X25519 private value",
    );
    let kem_d = fixed::<32>(&tv_draw(INIT_ID, "mlkem-d", 0, 32), "INIT ML-KEM d");
    let kem_z = fixed::<32>(&tv_draw(INIT_ID, "mlkem-z", 0, 32), "INIT ML-KEM z");

    let resp_xi = fixed::<32>(&tv_draw(RESP_ID, "mldsa-xi", 0, 32), "responder xi");
    let resp_rnd = fixed::<32>(&tv_draw(RESP_ID, "mldsa-rnd", 0, 32), "responder rnd");
    let resp_nonce = fixed::<32>(&tv_draw(RESP_ID, "nonce", 0, 32), "RESP nonce");
    let resp_route = fixed::<16>(
        &tv_draw(RESP_ID, "bootstrap-route-tag", 0, 16),
        "RESP route tag",
    );
    let resp_x_private = fixed::<32>(
        &tv_draw(RESP_ID, "x25519-private", 0, 32),
        "responder X25519 private value",
    );
    let kem_m = fixed::<32>(&tv_draw(RESP_ID, "mlkem-m", 0, 32), "RESP ML-KEM m");

    let init_signing = SigningKey::<MlDsa65>::from_seed(&init_xi.into());
    let init_verification = init_signing.verifying_key().encode();
    let init_fingerprint = fingerprint(init_verification.as_ref());
    let resp_signing = SigningKey::<MlDsa65>::from_seed(&resp_xi.into());
    let resp_verification = resp_signing.verifying_key().encode();
    let resp_fingerprint = fingerprint(resp_verification.as_ref());

    let init_x_secret =
        X25519SecretKey::from_bytes(&init_x_private).expect("fixed X25519 private length");
    let init_x_public = init_x_secret.public_key();
    let resp_x_secret =
        X25519SecretKey::from_bytes(&resp_x_private).expect("fixed X25519 private length");
    let resp_x_public = resp_x_secret.public_key();

    let mut kem_seed_bytes = [0_u8; 64];
    kem_seed_bytes[..32].copy_from_slice(&kem_d);
    kem_seed_bytes[32..].copy_from_slice(&kem_z);
    let kem_seed: ml_kem::Seed = kem_seed_bytes.into();
    let (kem_decapsulation, kem_encapsulation) = MlKem768::from_seed(&kem_seed);
    let kem_encapsulation_bytes = kem_encapsulation.to_bytes();

    let mut init_core = Vec::with_capacity(3249);
    init_core.push(PROTOCOL_VERSION);
    init_core.extend_from_slice(&SUITE_ID);
    init_core.extend_from_slice(&init_nonce);
    init_core.extend_from_slice(&resp_fingerprint);
    init_core.extend_from_slice(init_verification.as_ref());
    init_core.extend_from_slice(&init_x_public);
    init_core.extend_from_slice(kem_encapsulation_bytes.as_ref());
    assert_eq!(init_core.len(), 3249, "canonical INIT_CORE length");

    let init_core_lp = length_prefixed(&init_core);
    let init_sig_digest = hash512(&[b"HYDRA-MSG/v1/init-signature", &SUITE_ID, &init_core_lp]);
    let init_signature = sign_digest(&init_signing, &init_sig_digest, &init_rnd);
    let mut init_signed = init_core.clone();
    init_signed.extend_from_slice(&init_signature);
    let init_signed_lp = length_prefixed(&init_signed);
    let init_hash = hash512(&[b"HYDRA-MSG/v1/transcript", &init_signed_lp]);
    let init_envelope = bootstrap_envelope(
        OuterMode::BootstrapInit,
        init_route,
        &init_core,
        &init_signature,
        &[0_u8; 32],
    );
    assert_eq!(
        decode_outer_header(&init_envelope)
            .expect("generated INIT header must decode")
            .mode,
        OuterMode::BootstrapInit
    );

    let mut kem_entropy: ml_kem::B32 = kem_m.into();
    let (kem_ciphertext, kem_shared) = kem_encapsulation.encapsulate_deterministic(&kem_entropy);
    let kem_recovered = kem_decapsulation.decapsulate(&kem_ciphertext);
    assert_eq!(
        kem_shared, kem_recovered,
        "handshake ML-KEM shared secret must agree"
    );
    kem_entropy.fill(0);

    let responder_x = resp_x_secret
        .diffie_hellman(&init_x_public)
        .expect("nonzero responder X25519 output");
    let initiator_x = init_x_secret
        .diffie_hellman(&resp_x_public)
        .expect("nonzero initiator X25519 output");
    assert_eq!(
        responder_x.expose_secret(),
        initiator_x.expose_secret(),
        "handshake X25519 shared secret must agree"
    );

    let mut resp_core = Vec::with_capacity(3217);
    resp_core.push(PROTOCOL_VERSION);
    resp_core.extend_from_slice(&SUITE_ID);
    resp_core.extend_from_slice(&init_hash);
    resp_core.extend_from_slice(&resp_nonce);
    resp_core.extend_from_slice(&init_fingerprint);
    resp_core.extend_from_slice(resp_verification.as_ref());
    resp_core.extend_from_slice(&resp_x_public);
    resp_core.extend_from_slice(kem_ciphertext.as_ref());
    assert_eq!(resp_core.len(), 3217, "canonical RESP_CORE length");

    let resp_core_lp = length_prefixed(&resp_core);
    let resp_sig_digest = hash512(&[
        b"HYDRA-MSG/v1/resp-signature",
        &SUITE_ID,
        &init_hash,
        &resp_core_lp,
    ]);
    let resp_signature = sign_digest(&resp_signing, &resp_sig_digest, &resp_rnd);
    let mut resp_signed = resp_core.clone();
    resp_signed.extend_from_slice(&resp_signature);
    let resp_signed_lp = length_prefixed(&resp_signed);
    let transcript_hash = hash512(&[b"HYDRA-MSG/v1/transcript", &init_signed_lp, &resp_signed_lp]);

    let mut hybrid_ikm = Vec::new();
    lp(&mut hybrid_ikm, responder_x.expose_secret());
    lp(&mut hybrid_ikm, kem_shared.as_ref());
    let hybrid_prk_secret = RustCryptoBackend::hkdf_extract(&transcript_hash, &hybrid_ikm);
    let hybrid_prk = *hybrid_prk_secret.expose_secret();
    let handshake_secret = expand32(&hybrid_prk, b"HYDRA-MSG/v1/root-key", &transcript_hash);
    let session_id = expand32(
        &handshake_secret,
        b"HYDRA-MSG/v1/session-id",
        &transcript_hash,
    );
    let confirm_key = expand32(
        &handshake_secret,
        b"HYDRA-MSG/v1/confirm-key",
        &transcript_hash,
    );
    let finish_key = expand32(
        &handshake_secret,
        b"HYDRA-MSG/v1/finish-key",
        &transcript_hash,
    );
    let chain_i2r = expand32(
        &handshake_secret,
        b"HYDRA-MSG/v1/init-chain/i2r",
        &transcript_hash,
    );
    let chain_r2i = expand32(
        &handshake_secret,
        b"HYDRA-MSG/v1/init-chain/r2i",
        &transcript_hash,
    );
    let refresh_root = expand32(
        &handshake_secret,
        b"HYDRA-MSG/v1/refresh-root",
        &transcript_hash,
    );

    let mut confirm_input = Vec::new();
    confirm_input.extend_from_slice(b"HYDRA-MSG/v1/resp-confirm");
    confirm_input.extend_from_slice(&transcript_hash);
    confirm_input.extend_from_slice(&session_id);
    let resp_confirm = hmac256(&confirm_key, &confirm_input);
    RustCryptoBackend::verify_hmac_sha3_256(
        &SecretBytes::from_array(confirm_key),
        &confirm_input,
        &resp_confirm,
    )
    .expect("generated RESP confirmation must verify");

    let resp_envelope = bootstrap_envelope(
        OuterMode::BootstrapResp,
        resp_route,
        &resp_core,
        &resp_signature,
        &resp_confirm,
    );
    assert_eq!(
        decode_outer_header(&resp_envelope)
            .expect("generated RESP header must decode")
            .mode,
        OuterMode::BootstrapResp
    );

    let mut initiator_hybrid_ikm = Vec::new();
    lp(&mut initiator_hybrid_ikm, initiator_x.expose_secret());
    lp(&mut initiator_hybrid_ikm, kem_recovered.as_ref());
    let initiator_prk = RustCryptoBackend::hkdf_extract(&transcript_hash, &initiator_hybrid_ikm);
    assert_eq!(
        initiator_prk.expose_secret(),
        &hybrid_prk,
        "both handshake roles must derive the same hybrid PRK"
    );

    let finish_record = finish_plaintext(&transcript_hash, &session_id);
    let mut finish_route_input = Vec::new();
    finish_route_input.extend_from_slice(b"HYDRA-MSG/v1/route-tag");
    finish_route_input.extend_from_slice(&session_id);
    finish_route_input.extend_from_slice(&transcript_hash);
    let finish_route_full = hmac256(&finish_key, &finish_route_input);
    let finish_route = fixed::<16>(&finish_route_full[..16], "FINISH route tag");
    let finish_header = encode_outer_header(&OuterHeader::new(
        OuterMode::Protected,
        EnvelopeClass::Lite,
        finish_route,
        0,
    ))
    .expect("fixed FINISH header");
    let finish_body = RustCryptoBackend::aead_seal(
        &SecretBytes::from_array(finish_key),
        &[0_u8; 12],
        &finish_header,
        &finish_record,
    )
    .expect("FINISH encryption");
    assert_eq!(
        finish_body.len(),
        EnvelopeClass::Lite.body_size(),
        "FINISH body fills the Lite class"
    );
    let mut finish_envelope = Vec::with_capacity(EnvelopeClass::Lite.envelope_size());
    finish_envelope.extend_from_slice(&finish_header);
    finish_envelope.extend_from_slice(&finish_body);
    let opened_finish = RustCryptoBackend::aead_open(
        &SecretBytes::from_array(finish_key),
        &[0_u8; 12],
        &finish_header,
        &finish_body,
    )
    .expect("FINISH authentication");
    assert_eq!(&*opened_finish, &finish_record);
    assert_eq!(
        decode_outer_header(&finish_envelope)
            .expect("generated FINISH header must decode")
            .envelope_class,
        EnvelopeClass::Lite
    );

    let init_artifacts: Vec<(&str, &[u8])> = vec![
        ("mldsa_xi", &init_xi),
        ("mldsa_rnd", &init_rnd),
        ("nonce", &init_nonce),
        ("bootstrap_route_tag", &init_route),
        ("x25519_private", &init_x_private),
        ("mlkem_d", &kem_d),
        ("mlkem_z", &kem_z),
        ("identity_verification_key", init_verification.as_ref()),
        ("identity_fingerprint", &init_fingerprint),
        ("responder_fingerprint", &resp_fingerprint),
        ("x25519_public", &init_x_public),
        ("mlkem_encapsulation_key", kem_encapsulation_bytes.as_ref()),
        ("core", &init_core),
        ("signature_digest", &init_sig_digest),
        ("signature", &init_signature),
        ("init_hash", &init_hash),
        ("envelope", &init_envelope),
    ];
    let init_metadata = VectorMetadata {
        backend: "hydra-crypto plus RustCrypto deterministic PQ fixture; single backend",
        result: "INIT signature and complete Standard envelope verified",
        expected_state: "initiator New->InitSent; responder New->InitVerified",
        cleanup: "retain immutable INIT and bounded provisional handshake state",
        entropy: &[
            ("mldsa-xi", 0, 32, "mldsa_xi"),
            ("mldsa-rnd", 0, 32, "mldsa_rnd"),
            ("nonce", 0, 32, "nonce"),
            ("bootstrap-route-tag", 0, 16, "bootstrap_route_tag"),
            ("x25519-private", 0, 32, "x25519_private"),
            ("mlkem-d", 0, 32, "mlkem_d"),
            ("mlkem-z", 0, 32, "mlkem_z"),
        ],
    };
    write_vector(root, INIT_ID, &init_metadata, &init_artifacts);

    let resp_artifacts: Vec<(&str, &[u8])> = vec![
        ("mldsa_xi", &resp_xi),
        ("mldsa_rnd", &resp_rnd),
        ("nonce", &resp_nonce),
        ("bootstrap_route_tag", &resp_route),
        ("x25519_private", &resp_x_private),
        ("mlkem_m", &kem_m),
        ("identity_verification_key", resp_verification.as_ref()),
        ("identity_fingerprint", &resp_fingerprint),
        ("initiator_fingerprint", &init_fingerprint),
        ("x25519_public", &resp_x_public),
        ("mlkem_ciphertext", kem_ciphertext.as_ref()),
        ("core", &resp_core),
        ("signature_digest", &resp_sig_digest),
        ("signature", &resp_signature),
        ("transcript_hash", &transcript_hash),
        ("resp_confirm", &resp_confirm),
        ("envelope", &resp_envelope),
    ];
    let resp_metadata = VectorMetadata {
        backend: "hydra-crypto plus RustCrypto deterministic PQ fixture; single backend",
        result: "RESP signature, transcript, confirmation, and complete Standard envelope verified",
        expected_state: "initiator InitSent->RespVerified; responder InitVerified->RespSent",
        cleanup: "retain immutable RESP and provisional secrets until FINISH; erase rejected provisional state",
        entropy: &[
            ("mldsa-xi", 0, 32, "mldsa_xi"),
            ("mldsa-rnd", 0, 32, "mldsa_rnd"),
            ("nonce", 0, 32, "nonce"),
            ("bootstrap-route-tag", 0, 16, "bootstrap_route_tag"),
            ("x25519-private", 0, 32, "x25519_private"),
            ("mlkem-m", 0, 32, "mlkem_m"),
        ],
    };
    write_vector(root, RESP_ID, &resp_metadata, &resp_artifacts);

    let kdf_artifacts: Vec<(&str, &[u8])> = vec![
        ("initiator_x25519_public", &init_x_public),
        ("responder_x25519_public", &resp_x_public),
        ("x25519_shared_secret", responder_x.expose_secret()),
        ("mlkem_shared_secret", kem_shared.as_ref()),
        ("mlkem_decapsulated_secret", kem_recovered.as_ref()),
        ("hybrid_ikm", &hybrid_ikm),
        ("hybrid_prk", &hybrid_prk),
        ("handshake_secret", &handshake_secret),
        ("session_id", &session_id),
        ("confirm_key", &confirm_key),
        ("finish_key", &finish_key),
        ("chain_i2r", &chain_i2r),
        ("chain_r2i", &chain_r2i),
        ("refresh_root", &refresh_root),
    ];
    let kdf_metadata = VectorMetadata {
        backend: "hydra-crypto plus RustCrypto deterministic PQ fixture; single backend",
        result: "both roles derived identical X25519, ML-KEM, hybrid, and session secrets",
        expected_state: "provisional until RESP confirmation and FINISH authentication",
        cleanup: "after FINISH erase X25519, ML-KEM, hybrid PRK, handshake, confirmation, and FINISH secrets; retain chains and refresh root",
        entropy: &[],
    };
    write_vector(root, "TV-HS-KDF-000", &kdf_metadata, &kdf_artifacts);

    let conf_artifacts: Vec<(&str, &[u8])> = vec![
        ("resp_confirm", &resp_confirm),
        ("finish_route_tag", &finish_route),
        ("finish_outer_header", &finish_header),
        ("finish_plaintext_record", &finish_record),
        ("finish_ciphertext_and_tag", &finish_body),
        ("finish_envelope", &finish_envelope),
        ("opened_finish_record", &opened_finish),
    ];
    let conf_metadata = VectorMetadata {
        backend: "hydra-crypto; single RustCrypto backend",
        result: "RESP confirmation verified and complete Lite FINISH envelope authenticated",
        expected_state: "initiator RespVerified->FinishSent->Established; responder RespSent->FinishVerified->Established",
        cleanup: "erase provisional handshake, confirmation, and FINISH secrets after processing; retain current chains and refresh root",
        entropy: &[],
    };
    write_vector(root, "TV-HS-CONF-000", &conf_metadata, &conf_artifacts);
}

fn write_provenance(root: &Path) {
    let directory = root.join("provenance");
    fs::create_dir_all(&directory).expect("create provenance directory");
    let tool_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml = fs::read(tool_root.join("Cargo.toml")).expect("read tool Cargo.toml");
    let cargo_lock = fs::read(tool_root.join("Cargo.lock")).expect("read tool Cargo.lock");
    let main_rs = fs::read(tool_root.join("src").join("main.rs")).expect("read tool source");
    let protocol_vectors_rs =
        fs::read(tool_root.join("src").join("protocol_vectors.rs")).expect("read protocol source");
    let group_vectors_rs =
        fs::read(tool_root.join("src").join("group_vectors.rs")).expect("read group source");
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .expect("run rustc --version");
    assert!(rustc.status.success(), "rustc --version must succeed");
    let text = format!(
        "claim=local deterministic primitive, envelope, handshake, session, refresh, identity, and group candidate vectors; no PQ interoperability claim\nbackend=HYDRA reference implementation; hydra-session; hydra-group; hydra-crypto RustCrypto candidate adapter; RustCrypto ml-kem 0.3.2 deterministic fixture; RustCrypto ml-dsa 0.1.1 deterministic fixture\nrustc={}\ntool=hydra-vector-gen 0.1.0\ntool_cargo_toml_sha3_256={}\ntool_cargo_lock_sha3_256={}\ntool_main_rs_sha3_256={}\ntool_protocol_vectors_rs_sha3_256={}\ntool_group_vectors_rs_sha3_256={}\n",
        String::from_utf8(rustc.stdout)
            .expect("rustc output is UTF-8")
            .trim(),
        sha3_256_hex(&cargo_toml),
        sha3_256_hex(&cargo_lock),
        sha3_256_hex(&main_rs),
        sha3_256_hex(&protocol_vectors_rs),
        sha3_256_hex(&group_vectors_rs)
    );
    fs::write(directory.join("backend.txt"), text).expect("write provenance");
}

fn clean_generated_output(root: &Path) {
    for category in [
        "envelope",
        "handshake",
        "identity",
        "group",
        "negative",
        "primitive",
        "protocol",
        "provenance",
        "ratchet",
        "refresh",
    ] {
        let path = root.join(category);
        if path.exists() {
            remove_generated_directory(&path);
        }
    }
    let manifest = root.join("manifest.sha3-256");
    if manifest.exists() {
        remove_generated_file(&manifest);
    }
}

fn remove_generated_directory(path: &Path) {
    const ATTEMPTS: usize = 40;
    for attempt in 0..ATTEMPTS {
        match fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) if attempt + 1 < ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => panic!(
                "remove prior generated category {}: {error}",
                path.display()
            ),
        }
    }
}

fn remove_generated_file(path: &Path) {
    const ATTEMPTS: usize = 40;
    for attempt in 0..ATTEMPTS {
        match fs::remove_file(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) if attempt + 1 < ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => panic!("remove prior generated file {}: {error}", path.display()),
        }
    }
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read output directory") {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            collect_files(root, &path, files);
        } else if path
            .file_name()
            .is_some_and(|name| name != "manifest.sha3-256")
        {
            files.push(
                path.strip_prefix(root)
                    .expect("path under root")
                    .to_path_buf(),
            );
        }
    }
}

fn write_manifest(root: &Path) {
    let mut files = Vec::new();
    collect_files(root, root, &mut files);
    files.sort_by_key(|path| path.to_string_lossy().replace('\\', "/"));

    let mut manifest = String::new();
    for relative in files {
        let bytes = fs::read(root.join(&relative)).expect("read artifact for manifest");
        let portable = relative.to_string_lossy().replace('\\', "/");
        manifest.push_str(&format!("{}  {}\n", sha3_256_hex(&bytes), portable));
    }
    fs::write(root.join("manifest.sha3-256"), manifest).expect("write manifest");
}

fn verify_manifest(root: &Path) -> Result<(), String> {
    let manifest_path = root.join("manifest.sha3-256");
    let manifest = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("read {}: {error}", manifest_path.display()))?;
    let mut listed_paths = Vec::new();
    let mut previous: Option<String> = None;

    for (line_index, line) in manifest.lines().enumerate() {
        let (expected_hash, portable) = line
            .split_once("  ")
            .ok_or_else(|| format!("manifest line {} has invalid separator", line_index + 1))?;
        if expected_hash.len() != 64
            || !expected_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(format!(
                "manifest line {} has noncanonical SHA3-256",
                line_index + 1
            ));
        }
        if portable.contains('\\')
            || Path::new(portable)
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!(
                "manifest line {} has nonportable path",
                line_index + 1
            ));
        }
        if previous
            .as_ref()
            .is_some_and(|value| value.as_str() >= portable)
        {
            return Err(format!(
                "manifest paths are not strictly sorted at line {}",
                line_index + 1
            ));
        }
        previous = Some(portable.to_owned());

        let bytes = fs::read(root.join(portable))
            .map_err(|error| format!("read manifest artifact {portable}: {error}"))?;
        let actual_hash = sha3_256_hex(&bytes);
        if actual_hash != expected_hash {
            return Err(format!("hash mismatch for {portable}"));
        }

        if let Some(stem) = portable.strip_suffix(".hex") {
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| format!("hex artifact is not UTF-8: {portable}"))?;
            let encoded = text
                .strip_suffix('\n')
                .ok_or_else(|| format!("hex artifact lacks final LF: {portable}"))?;
            if encoded.contains('\n')
                || !encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(format!("hex artifact is not canonical: {portable}"));
            }
            let decoded =
                hex::decode(encoded).map_err(|_| format!("invalid hex artifact: {portable}"))?;
            let binary_path = format!("{stem}.bin");
            let binary = fs::read(root.join(&binary_path))
                .map_err(|error| format!("read binary mirror {binary_path}: {error}"))?;
            if decoded != binary {
                return Err(format!("hex/binary mismatch for {stem}"));
            }
        }
        listed_paths.push(PathBuf::from(portable));
    }

    let mut actual_paths = Vec::new();
    collect_files(root, root, &mut actual_paths);
    actual_paths.sort_by_key(|path| path.to_string_lossy().replace('\\', "/"));
    if listed_paths != actual_paths {
        return Err("manifest file inventory does not match output tree".to_owned());
    }
    Ok(())
}

fn main() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tool is under repository/qa/tools");
    let output = repository.join("vectors").join("candidate");

    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments == ["--verify"] {
        verify_manifest(&output).expect("verify existing manifest");
        println!("{}", output.display());
        return;
    }
    assert!(arguments.is_empty(), "usage: hydra-vector-gen [--verify]");

    fs::create_dir_all(&output).expect("create candidate output root");
    clean_generated_output(&output);

    generate_mlkem(&output);
    generate_mldsa(&output);
    generate_envelope_vectors(&output);
    generate_handshake_vectors(&output);
    protocol_vectors::generate(&output);
    group_vectors::generate(&output);
    write_provenance(&output);
    write_manifest(&output);
    verify_manifest(&output).expect("verify generated manifest");

    println!("{}", output.display());
}

#[cfg(test)]
mod tests {
    use super::{sha3_256_hex, tv_draw, verify_manifest, write_manifest};
    use std::fs;

    #[test]
    fn deterministic_draw_matches_frozen_schedule() {
        assert_eq!(
            hex::encode(tv_draw("TV-PQ-MLKEM-000", "mlkem-d", 0, 32)),
            "dfdfcc52ae5b8773995789b128fe20f8865bd24966210dc664480745a45fac52"
        );
    }

    #[test]
    fn deterministic_draw_separates_purpose_and_occurrence() {
        let base = tv_draw("TV-PQ-MLKEM-000", "mlkem-d", 0, 32);
        assert_ne!(base, tv_draw("TV-PQ-MLKEM-000", "mlkem-z", 0, 32));
        assert_ne!(base, tv_draw("TV-PQ-MLKEM-000", "mlkem-d", 1, 32));
    }

    #[test]
    fn manifest_verifier_checks_generated_inventory_and_hashes() {
        let root =
            std::env::temp_dir().join(format!("hydra-vector-gen-manifest-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale test directory");
        }
        fs::create_dir_all(root.join("sample")).expect("create test directory");
        fs::write(root.join("sample").join("value.bin"), [0x01, 0x23]).expect("write test binary");
        fs::write(root.join("sample").join("value.hex"), b"0123\n").expect("write test hex");
        write_manifest(&root);
        verify_manifest(&root).expect("generated manifest must verify");

        fs::write(root.join("sample").join("value.bin"), [0x01, 0x24]).expect("mutate test binary");
        assert!(verify_manifest(&root).is_err());

        let manifest = fs::read(root.join("manifest.sha3-256")).expect("read test manifest");
        assert_eq!(sha3_256_hex(&manifest).len(), 64);
        fs::remove_dir_all(root).expect("remove test directory");
    }
}
