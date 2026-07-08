use super::{
    VectorMetadata, expand32, fingerprint, fixed, hash512, length_prefixed, lp, sign_digest,
    tv_draw, write_bytes, write_metadata,
};
use hydra_core::{
    FULL_MAX_CONTENT_SIZE, LITE_MAX_CONTENT_SIZE, MAX_SKIP, ML_DSA_65_SIG_SIZE, ML_DSA_65_VK_SIZE,
    STANDARD_MAX_CONTENT_SIZE, SUITE_ID,
    types::{ContentKind, EnvelopeClass, OuterMode},
};
use hydra_crypto::{CryptoBackend, RustCryptoBackend, SecretBytes, X25519SecretKey};
use hydra_envelope::{OuterHeader, ProtectedRecord, encode_outer_header, encode_protected_record};
use hydra_session::{
    RefreshIdDecision, RefreshRole, SessionError, SessionRole, SessionState, derive_initial_secrets,
};
use ml_dsa::{MlDsa65, Signature, SigningKey, signature::Keypair};
use ml_kem::{
    FromSeed, MlKem768,
    kem::{Decapsulate, KeyExport},
};
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    thread,
};

struct PairFixture {
    initiator: SessionState,
    responder: SessionState,
    transcript_hash: [u8; 64],
    handshake_secret: [u8; 32],
}

fn pair(vector_id: &str) -> PairFixture {
    pair_with_fingerprints(vector_id, [0x11; 32], [0x22; 32])
}

fn pair_with_fingerprints(
    vector_id: &str,
    initiator_fingerprint: [u8; 32],
    responder_fingerprint: [u8; 32],
) -> PairFixture {
    let transcript_hash = fixed::<64>(
        &tv_draw(vector_id, "message", 0, 64),
        "session transcript hash",
    );
    let handshake_secret = fixed::<32>(
        &tv_draw(vector_id, "message", 1, 32),
        "session handshake secret",
    );
    let initiator_secrets =
        derive_initial_secrets(&SecretBytes::from_array(handshake_secret), &transcript_hash)
            .expect("derive initiator session fixture");
    let responder_secrets =
        derive_initial_secrets(&SecretBytes::from_array(handshake_secret), &transcript_hash)
            .expect("derive responder session fixture");
    PairFixture {
        initiator: SessionState::established(
            SessionRole::Initiator,
            transcript_hash,
            initiator_fingerprint,
            responder_fingerprint,
            initiator_secrets,
        ),
        responder: SessionState::established(
            SessionRole::Responder,
            transcript_hash,
            responder_fingerprint,
            initiator_fingerprint,
            responder_secrets,
        ),
        transcript_hash,
        handshake_secret,
    }
}

fn session_entropy() -> &'static [(&'static str, u32, usize, &'static str)] {
    &[
        ("message", 0, 64, "transcript_hash"),
        ("message", 1, 32, "handshake_secret"),
    ]
}

fn write_owned(
    root: &Path,
    category: &str,
    vector_id: &str,
    metadata: &VectorMetadata<'_>,
    artifacts: &[(String, Vec<u8>)],
) {
    let directory = root.join(category).join(vector_id);
    fs::create_dir_all(&directory).expect("create protocol vector directory");
    let references = artifacts
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect::<Vec<_>>();
    for (name, bytes) in &references {
        write_bytes(&directory, name, bytes);
    }
    write_metadata(&directory, vector_id, metadata, &references);
}

fn base_artifacts(fixture: &PairFixture) -> Vec<(String, Vec<u8>)> {
    vec![
        (
            "transcript_hash".to_owned(),
            fixture.transcript_hash.to_vec(),
        ),
        (
            "handshake_secret".to_owned(),
            fixture.handshake_secret.to_vec(),
        ),
    ]
}

fn metadata<'a>(
    result: &'a str,
    expected_state: &'a str,
    cleanup: &'a str,
    entropy: &'a [(&'a str, u32, usize, &'a str)],
) -> VectorMetadata<'a> {
    VectorMetadata {
        backend: "hydra-session with hydra-crypto RustCrypto candidate adapter; single backend",
        result,
        expected_state,
        cleanup,
        entropy,
    }
}

fn generate_exact_ratchet_and_envelope(root: &Path) {
    let chain_key: [u8; 32] = fixed(
        &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
        "chain key",
    );
    let session_id: [u8; 32] = fixed(
        &hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap(),
        "session ID",
    );
    let index = 7_u64;
    let mut context = Vec::new();
    context.extend_from_slice(&session_id);
    context.extend_from_slice(&index.to_be_bytes());
    let message_key = expand32(&chain_key, b"HYDRA-MSG/v1/message-key", &context);
    let next_chain_key = expand32(&chain_key, b"HYDRA-MSG/v1/chain-advance", &context);
    let aead_key = expand32(&message_key, b"HYDRA-MSG/v1/aead-key", &context);
    let mut route_input = Vec::new();
    route_input.extend_from_slice(b"HYDRA-MSG/v1/route-tag");
    route_input.extend_from_slice(&session_id);
    route_input.extend_from_slice(&index.to_be_bytes());
    let route_full =
        RustCryptoBackend::hmac_sha3_256(&SecretBytes::from_array(message_key), &route_input);
    let route_tag: [u8; 16] = route_full[..16].try_into().unwrap();
    assert_eq!(
        hex::encode(message_key),
        "57c52aff9054b2dca7612159bf8ec32f46fba04eb3e6cc7eb41552b7472c3f28"
    );
    assert_eq!(
        hex::encode(next_chain_key),
        "c4b16856388d565959d42e247673e50248277624782da3160bef6a01d8bbda75"
    );
    assert_eq!(
        hex::encode(aead_key),
        "a66e347d5219b73bdd4adcf23b5df3c97e0b901ce59f7367e2f03eefa0620a86"
    );
    assert_eq!(hex::encode(route_tag), "d7b4c2bd7fc3df2f141bda721c8b141f");
    let ratchet_artifacts = vec![
        ("chain_key".to_owned(), chain_key.to_vec()),
        ("session_id".to_owned(), session_id.to_vec()),
        ("message_index".to_owned(), index.to_be_bytes().to_vec()),
        ("message_key".to_owned(), message_key.to_vec()),
        ("next_chain_key".to_owned(), next_chain_key.to_vec()),
        ("aead_key".to_owned(), aead_key.to_vec()),
        ("aead_nonce".to_owned(), vec![0; 12]),
        ("route_tag".to_owned(), route_tag.to_vec()),
    ];
    write_owned(
        root,
        "ratchet",
        "TV-RATCHET-000",
        &metadata(
            "documented ratchet derivation reproduced exactly",
            "derivation only; no persistent state",
            "fixture secrets retained only as vector artifacts",
            &[],
        ),
        &ratchet_artifacts,
    );

    let record = encode_protected_record(
        EnvelopeClass::Full,
        &ProtectedRecord {
            content_kind: ContentKind::Data,
            session_or_group_id: session_id,
            sender_id: [0; 32],
            epoch: 0,
            state_version: 0,
            message_index: index,
            content: b"abc".to_vec(),
        },
    )
    .unwrap();
    let header = encode_outer_header(&OuterHeader::new(
        OuterMode::Protected,
        EnvelopeClass::Full,
        route_tag,
        index,
    ))
    .unwrap();
    let body = RustCryptoBackend::aead_seal(
        &SecretBytes::from_array(aead_key),
        &[0; 12],
        &header,
        &record,
    )
    .unwrap();
    let mut envelope = Vec::new();
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&body);
    assert_eq!(
        hex::encode(RustCryptoBackend::sha3_256(&record)),
        "be0e3b94445ab92d181dc929c42fc38019dbf9ffac7438d6255618c8c54cf2ce"
    );
    assert_eq!(
        hex::encode(RustCryptoBackend::sha3_256(&body)),
        "bf2266e5ecaf73e40433aee9b932c2a9b162534cfce92e72e9d8a330d5c26950"
    );
    assert_eq!(
        hex::encode(RustCryptoBackend::sha3_256(&envelope)),
        "fad5e401eea9f5b4bc1564f201d71ef6b402da5cbf0a6037c96f1e4c3f78b580"
    );
    let envelope_artifacts = vec![
        ("protected_record".to_owned(), record),
        ("outer_header".to_owned(), header.to_vec()),
        ("body".to_owned(), body),
        ("envelope".to_owned(), envelope),
    ];
    write_owned(
        root,
        "protocol",
        "TV-ENV-000",
        &metadata(
            "documented Full protected abc envelope reproduced exactly",
            "serialization fixture only",
            "one-use fixture keys retained only as vector artifacts",
            &[],
        ),
        &envelope_artifacts,
    );
}

fn generate_data(root: &Path) {
    const ID: &str = "TV-DATA-000";
    let mut fixture = pair(ID);
    let sender_before = fixture.initiator.test_state_hash();
    let receiver_before = fixture.responder.test_state_hash();
    let outbound = fixture
        .initiator
        .send_data(b"hello protocol")
        .expect("seal DATA");
    let received = fixture
        .responder
        .receive(&outbound.envelope)
        .expect("open DATA");
    assert_eq!(received.content, b"hello protocol");
    let mut artifacts = base_artifacts(&fixture);
    artifacts.extend([
        ("content".to_owned(), b"hello protocol".to_vec()),
        ("envelope".to_owned(), outbound.envelope),
        ("sender_state_before".to_owned(), sender_before.to_vec()),
        (
            "sender_state_after".to_owned(),
            fixture.initiator.test_state_hash().to_vec(),
        ),
        ("receiver_state_before".to_owned(), receiver_before.to_vec()),
        (
            "receiver_state_after".to_owned(),
            fixture.responder.test_state_hash().to_vec(),
        ),
    ]);

    let class_cases = [
        (LITE_MAX_CONTENT_SIZE, EnvelopeClass::Lite),
        (STANDARD_MAX_CONTENT_SIZE, EnvelopeClass::Standard),
        (FULL_MAX_CONTENT_SIZE, EnvelopeClass::Full),
    ];
    let mut boundary_results = Vec::new();
    for (maximum, expected) in class_cases {
        for length in [maximum - 1, maximum] {
            let mut boundary = pair(ID).initiator;
            let sent = boundary
                .send_data(&vec![0xa5; length])
                .expect("inclusive class boundary");
            let class = hydra_envelope::decode_outer_header(&sent.envelope)
                .expect("boundary header")
                .envelope_class;
            assert_eq!(class, expected);
            boundary_results.push(class as u8);
        }
    }
    let mut lite_plus_one = pair(ID).initiator;
    boundary_results.push(
        hydra_envelope::decode_outer_header(
            &lite_plus_one
                .send_data(&vec![0; LITE_MAX_CONTENT_SIZE + 1])
                .expect("Lite overflow promotes")
                .envelope,
        )
        .expect("promoted header")
        .envelope_class as u8,
    );
    let mut standard_plus_one = pair(ID).initiator;
    boundary_results.push(
        hydra_envelope::decode_outer_header(
            &standard_plus_one
                .send_data(&vec![0; STANDARD_MAX_CONTENT_SIZE + 1])
                .expect("Standard overflow promotes")
                .envelope,
        )
        .expect("promoted header")
        .envelope_class as u8,
    );
    let mut full_plus_one = pair(ID).initiator;
    let full_before = full_plus_one.test_state_hash();
    assert_eq!(
        full_plus_one.send_data(&vec![0; FULL_MAX_CONTENT_SIZE + 1]),
        Err(SessionError::InvalidPayload)
    );
    assert_eq!(full_plus_one.test_state_hash(), full_before);
    boundary_results.push(0xff);
    artifacts.push(("class_boundary_results".to_owned(), boundary_results));

    write_owned(
        root,
        "protocol",
        ID,
        &metadata(
            "protected DATA sealed, authenticated, parsed, and delivered",
            "sender and receiver advance exactly once",
            "one-use message and AEAD keys erased after commit",
            session_entropy(),
        ),
        &artifacts,
    );
}

fn malformed_plaintext(
    class: EnvelopeClass,
    session_id: [u8; 32],
    index: u64,
    mutation: &str,
) -> Vec<u8> {
    let forcing_length = match class {
        EnvelopeClass::Lite => 1,
        EnvelopeClass::Standard => LITE_MAX_CONTENT_SIZE + 1,
        EnvelopeClass::Full => STANDARD_MAX_CONTENT_SIZE + 1,
    };
    let mut record = ProtectedRecord {
        content_kind: ContentKind::Data,
        session_or_group_id: session_id,
        sender_id: [0; 32],
        epoch: 0,
        state_version: 0,
        message_index: index,
        content: vec![0x42; forcing_length],
    };
    if mutation == "class_policy" {
        record.content = vec![0x42; 1];
        if class == EnvelopeClass::Lite {
            record.content_kind = ContentKind::RefreshInit;
        }
    }
    let mut plaintext =
        encode_protected_record(class, &record).expect("base protected test record");
    match mutation {
        "flags" => plaintext[1] = 1,
        "reserved" => plaintext[2] = 1,
        "kind" => plaintext[0] = 0xff,
        "content_len" => {
            plaintext[92..96].copy_from_slice(
                &u32::try_from(class.max_content_size() + 1)
                    .expect("class bound fits u32")
                    .to_be_bytes(),
            );
        }
        "padding" => *plaintext.last_mut().expect("record is nonempty") = 1,
        "index" => plaintext[84..92].copy_from_slice(&(index + 1).to_be_bytes()),
        "session_id" => plaintext[4] ^= 1,
        "class_policy" => {}
        _ => panic!("unknown malformed mutation"),
    }
    plaintext
}

fn generate_malformed(root: &Path) {
    const ID: &str = "TV-PROTECTED-BAD-000";
    let mut artifacts = Vec::new();
    for class in [
        EnvelopeClass::Lite,
        EnvelopeClass::Standard,
        EnvelopeClass::Full,
    ] {
        for mutation in [
            "flags",
            "reserved",
            "kind",
            "content_len",
            "padding",
            "index",
            "session_id",
            "class_policy",
        ] {
            let mut fixture = pair(ID);
            let before = fixture.responder.test_state_hash();
            let plaintext =
                malformed_plaintext(class, *fixture.initiator.session_id(), 0, mutation);
            let outbound = fixture
                .initiator
                .seal_test_plaintext(class, &plaintext)
                .expect("seal authenticated malformed record");
            assert_eq!(
                fixture.responder.receive(&outbound.envelope),
                Err(SessionError::AuthenticationFailed)
            );
            let after = fixture.responder.test_state_hash();
            assert_eq!(before, after);
            let prefix = format!("{}_{mutation}", class as u8);
            artifacts.push((format!("{prefix}_plaintext"), plaintext));
            artifacts.push((format!("{prefix}_envelope"), outbound.envelope));
            artifacts.push((format!("{prefix}_state_before"), before.to_vec()));
            artifacts.push((format!("{prefix}_state_after"), after.to_vec()));
        }
    }
    write_owned(
        root,
        "negative",
        ID,
        &metadata(
            "all authenticated inner mutations rejected with identical parent state hashes",
            "receiver remains at parent state",
            "all provisional keys erased; no skipped or replay commit",
            &[],
        ),
        &artifacts,
    );
}

fn write_ratchet_vector(
    root: &Path,
    id: &str,
    result: &str,
    expected_state: &str,
    fixture: &PairFixture,
    mut artifacts: Vec<(String, Vec<u8>)>,
) {
    let mut complete = base_artifacts(fixture);
    complete.append(&mut artifacts);
    write_owned(
        root,
        "ratchet",
        id,
        &metadata(
            result,
            expected_state,
            "unused provisional keys erased; committed skipped keys remain one-use",
            session_entropy(),
        ),
        &complete,
    );
}

fn generate_ratchet(root: &Path) {
    {
        const ID: &str = "TV-RATCHET-001";
        let mut f = pair(ID);
        let before = f.responder.test_state_hash();
        let outbound = f.initiator.send_data(b"ordered").unwrap();
        let received = f.responder.receive(&outbound.envelope).unwrap();
        write_ratchet_vector(
            root,
            ID,
            "ordered receive accepted",
            "receive index advances from 0 to 1 exactly once",
            &f,
            vec![
                ("envelope".to_owned(), outbound.envelope),
                ("received".to_owned(), received.content),
                ("state_before".to_owned(), before.to_vec()),
                (
                    "state_after".to_owned(),
                    f.responder.test_state_hash().to_vec(),
                ),
            ],
        );
    }
    {
        const ID: &str = "TV-RATCHET-002";
        let mut f = pair(ID);
        let mut outbound = f.initiator.send_data(b"authenticate").unwrap();
        outbound.envelope[100] ^= 1;
        let before = f.responder.test_state_hash();
        assert_eq!(
            f.responder.receive(&outbound.envelope),
            Err(SessionError::AuthenticationFailed)
        );
        let after = f.responder.test_state_hash();
        assert_eq!(before, after);
        write_ratchet_vector(
            root,
            ID,
            "mutated ciphertext rejected",
            "parent receive state unchanged",
            &f,
            vec![
                ("mutated_envelope".to_owned(), outbound.envelope),
                ("state_before".to_owned(), before.to_vec()),
                ("state_after".to_owned(), after.to_vec()),
            ],
        );
    }
    {
        const ID: &str = "TV-RATCHET-003";
        let mut f = pair(ID);
        let mut first = None;
        let mut boundary = None;
        for index in 0..=MAX_SKIP {
            let outbound = f.initiator.send_data(b"gap-256").unwrap();
            if index == 0 {
                first = Some(outbound);
            } else if index == MAX_SKIP {
                boundary = Some(outbound);
            }
        }
        let boundary = boundary.unwrap();
        f.responder.receive(&boundary.envelope).unwrap();
        let after_boundary = f.responder.test_state_hash();
        let first = first.unwrap();
        f.responder.receive(&first.envelope).unwrap();
        let after_delayed = f.responder.test_state_hash();
        let before_replay = f.responder.test_state_hash();
        assert_eq!(
            f.responder.receive(&first.envelope),
            Err(SessionError::ReplayDetected)
        );
        assert_eq!(f.responder.test_state_hash(), before_replay);
        write_ratchet_vector(
            root,
            ID,
            "gap 256 and delayed oldest key accepted once; replay rejected",
            "next receive index 257 with delayed index 0 consumed once",
            &f,
            vec![
                ("boundary_envelope".to_owned(), boundary.envelope),
                ("delayed_zero_envelope".to_owned(), first.envelope),
                ("state_after_boundary".to_owned(), after_boundary.to_vec()),
                ("state_after_delayed".to_owned(), after_delayed.to_vec()),
                ("state_after_replay".to_owned(), before_replay.to_vec()),
            ],
        );
    }
    {
        const ID: &str = "TV-RATCHET-004";
        let mut f = pair(ID);
        let mut future = None;
        for index in 0..=MAX_SKIP + 1 {
            let outbound = f.initiator.send_data(b"gap-257").unwrap();
            if index == MAX_SKIP + 1 {
                future = Some(outbound);
            }
        }
        let future = future.unwrap();
        let before = f.responder.test_state_hash();
        assert_eq!(
            f.responder.receive(&future.envelope),
            Err(SessionError::MessageTooFarAhead)
        );
        let after = f.responder.test_state_hash();
        assert_eq!(before, after);
        write_ratchet_vector(
            root,
            ID,
            "gap 257 rejected before derivation",
            "parent receive state unchanged",
            &f,
            vec![
                ("future_envelope".to_owned(), future.envelope),
                ("state_before".to_owned(), before.to_vec()),
                ("state_after".to_owned(), after.to_vec()),
            ],
        );
    }
    {
        const ID: &str = "TV-RATCHET-006";
        let mut f = pair(ID);
        let first = f.initiator.send_data(b"skipped").unwrap();
        let second = f.initiator.send_data(b"ahead").unwrap();
        f.responder.receive(&second.envelope).unwrap();
        let mut damaged = first.envelope.clone();
        damaged[100] ^= 1;
        let before = f.responder.test_state_hash();
        assert_eq!(
            f.responder.receive(&damaged),
            Err(SessionError::AuthenticationFailed)
        );
        let after_failure = f.responder.test_state_hash();
        assert_eq!(after_failure, before);
        f.responder.receive(&first.envelope).unwrap();
        write_ratchet_vector(
            root,
            ID,
            "failed skipped-key AEAD preserves key; original succeeds once",
            "skipped key removed only after successful authentication",
            &f,
            vec![
                ("damaged_envelope".to_owned(), damaged),
                ("valid_envelope".to_owned(), first.envelope),
                ("state_before_failure".to_owned(), before.to_vec()),
                ("state_after_failure".to_owned(), after_failure.to_vec()),
                (
                    "state_after_success".to_owned(),
                    f.responder.test_state_hash().to_vec(),
                ),
            ],
        );
    }
    {
        const ID: &str = "TV-RATCHET-005";
        let mut f = pair(ID);
        let first = f.initiator.send_data(b"skipped-once").unwrap();
        let second = f.initiator.send_data(b"ahead").unwrap();
        f.responder.receive(&second.envelope).unwrap();
        let before = f.responder.test_state_hash();
        f.responder.receive(&first.envelope).unwrap();
        let after = f.responder.test_state_hash();
        assert_eq!(
            f.responder.receive(&first.envelope),
            Err(SessionError::ReplayDetected)
        );
        let after_replay = f.responder.test_state_hash();
        assert_eq!(after_replay, after);
        write_ratchet_vector(
            root,
            ID,
            "skipped key succeeds once and replay is rejected",
            "skipped key removed and replay state committed exactly once",
            &f,
            vec![
                ("skipped_envelope".to_owned(), first.envelope),
                ("ahead_envelope".to_owned(), second.envelope),
                ("state_before".to_owned(), before.to_vec()),
                ("state_after".to_owned(), after.to_vec()),
                ("state_after_replay".to_owned(), after_replay.to_vec()),
            ],
        );
    }
    {
        const ID: &str = "TV-RATCHET-007";
        let mut f = pair(ID);
        let outbound = f.initiator.send_data(b"duplicate").unwrap();
        f.responder.receive(&outbound.envelope).unwrap();
        let before_replay = f.responder.test_state_hash();
        assert_eq!(
            f.responder.receive(&outbound.envelope),
            Err(SessionError::ReplayDetected)
        );
        assert_eq!(f.responder.test_state_hash(), before_replay);
        write_ratchet_vector(
            root,
            ID,
            "duplicate ciphertext rejected",
            "receiver state unchanged after replay",
            &f,
            vec![
                ("envelope".to_owned(), outbound.envelope),
                ("state_before_replay".to_owned(), before_replay.to_vec()),
                ("state_after_replay".to_owned(), before_replay.to_vec()),
            ],
        );
    }
    {
        const ID: &str = "TV-RATCHET-008";
        let mut f = pair(ID);
        f.initiator.set_test_send_index(u64::MAX - 1);
        let last = f.initiator.send_data(b"last").unwrap();
        let before_reject = f.initiator.test_state_hash();
        assert_eq!(
            f.initiator.send_data(b"overflow"),
            Err(SessionError::CounterExhausted)
        );
        let after_reject = f.initiator.test_state_hash();
        assert_eq!(after_reject, before_reject);
        write_ratchet_vector(
            root,
            ID,
            "index u64::MAX-1 succeeds; u64::MAX send is rejected",
            "send chain remains exhausted without key reuse",
            &f,
            vec![
                ("last_envelope".to_owned(), last.envelope),
                ("exhausted_state".to_owned(), before_reject.to_vec()),
                ("state_after_reject".to_owned(), after_reject.to_vec()),
            ],
        );
    }
    {
        const ID: &str = "TV-RATCHET-009";
        let mut f = pair(ID);
        let before = f.initiator.test_state_hash();
        let emitted = f.initiator.send_data(b"ambiguous").unwrap();
        let immutable_retry = emitted.envelope.clone();
        assert_eq!(emitted.envelope, immutable_retry);
        write_ratchet_vector(
            root,
            ID,
            "ambiguous delivery consumes index and permits only identical retry bytes",
            "send index advances exactly once",
            &f,
            vec![
                ("envelope".to_owned(), emitted.envelope),
                ("identical_retry".to_owned(), immutable_retry),
                ("state_before".to_owned(), before.to_vec()),
                (
                    "state_after".to_owned(),
                    f.initiator.test_state_hash().to_vec(),
                ),
            ],
        );
    }
    {
        const ID: &str = "TV-RATCHET-010";
        let f = pair(ID);
        let transcript = f.transcript_hash;
        let secret = f.handshake_secret;
        let state_before = f.initiator.test_state_hash();
        let shared = Arc::new(Mutex::new(f.initiator));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let shared = Arc::clone(&shared);
            handles.push(thread::spawn(move || {
                shared.lock().unwrap().send_data(b"concurrent").unwrap()
            }));
        }
        let mut outputs = handles
            .into_iter()
            .map(|handle| handle.join().expect("send thread"))
            .collect::<Vec<_>>();
        outputs.sort_by_key(|output| output.index);
        assert_eq!([outputs[0].index, outputs[1].index], [0, 1]);
        let final_hash = shared.lock().unwrap().test_state_hash();
        let fixture = PairFixture {
            initiator: pair(ID).initiator,
            responder: f.responder,
            transcript_hash: transcript,
            handshake_secret: secret,
        };
        write_ratchet_vector(
            root,
            ID,
            "serialized concurrent callers receive distinct indices",
            "send index advances from 0 to 2",
            &fixture,
            vec![
                ("envelope_0".to_owned(), outputs.remove(0).envelope),
                ("envelope_1".to_owned(), outputs.remove(0).envelope),
                ("state_before".to_owned(), state_before.to_vec()),
                ("state_after".to_owned(), final_hash.to_vec()),
            ],
        );
    }
}

fn generate_close(root: &Path) {
    const ID: &str = "TV-CLOSE-000";
    let mut f = pair(ID);
    let sender_before = f.initiator.test_state_hash();
    let close = f.initiator.send_close(u16::MAX).unwrap();
    let receiver_before = f.responder.test_state_hash();
    let received = f.responder.receive(&close.envelope).unwrap();
    assert_eq!(received.content, u16::MAX.to_be_bytes());
    let mut artifacts = base_artifacts(&f);
    artifacts.extend([
        ("envelope".to_owned(), close.envelope),
        ("reason_code".to_owned(), u16::MAX.to_be_bytes().to_vec()),
        ("sender_state_before".to_owned(), sender_before.to_vec()),
        (
            "sender_state_after".to_owned(),
            f.initiator.test_state_hash().to_vec(),
        ),
        ("receiver_state_before".to_owned(), receiver_before.to_vec()),
        (
            "receiver_state_after".to_owned(),
            f.responder.test_state_hash().to_vec(),
        ),
    ]);
    write_owned(
        root,
        "protocol",
        ID,
        &metadata(
            "authenticated CLOSE delivered and receiver erased",
            "sender Closing; receiver Closed",
            "receiver session secrets erased",
            session_entropy(),
        ),
        &artifacts,
    );
}

fn verify_signature(
    verification_key: &ml_dsa::VerifyingKey<MlDsa65>,
    digest: &[u8; 64],
    signature: &[u8],
) -> bool {
    let Ok(signature) = <&[u8; ML_DSA_65_SIG_SIZE]>::try_from(signature) else {
        return false;
    };
    let Some(signature) = Signature::<MlDsa65>::decode(signature.into()) else {
        return false;
    };
    let mut message = Vec::with_capacity(66);
    message.extend_from_slice(&[0, 0]);
    message.extend_from_slice(digest);
    verification_key.verify_internal(&message, &signature)
}

fn refresh_init_digest(core: &[u8]) -> [u8; 64] {
    hash512(&[
        b"HYDRA-MSG/v1/refresh-init-signature",
        &SUITE_ID,
        &length_prefixed(core),
    ])
}

const REFRESH_INIT_CORE_SIZE: usize = 32 + 64 + 32 + 32 + 32 + 32 + 1184 + 8 + 8;

fn refresh_resp_digest(
    pretranscript: &[u8; 64],
    new_session_id: &[u8; 32],
    confirmation: &[u8; 32],
    core: &[u8],
) -> [u8; 64] {
    hash512(&[
        b"HYDRA-MSG/v1/refresh-resp-signature",
        &SUITE_ID,
        pretranscript,
        new_session_id,
        confirmation,
        &length_prefixed(core),
    ])
}

fn refresh_mix(
    session_id: &[u8; 32],
    pretranscript: &[u8; 64],
    x_secret: &[u8; 32],
    kem_secret: &[u8],
) -> [u8; 32] {
    let mut ikm = Vec::new();
    lp(&mut ikm, x_secret);
    lp(&mut ikm, kem_secret);
    let prk = RustCryptoBackend::hkdf_extract(pretranscript, &ikm);
    let mut context = Vec::new();
    context.extend_from_slice(session_id);
    context.extend_from_slice(pretranscript);
    expand32(prk.expose_secret(), b"HYDRA-MSG/v1/refresh", &context)
}

fn generate_refresh(root: &Path) {
    const ID: &str = "TV-REFRESH-000";
    let initiator_xi = fixed::<32>(&tv_draw(ID, "mldsa-xi", 0, 32), "refresh initiator xi");
    let responder_xi = fixed::<32>(&tv_draw(ID, "mldsa-xi", 1, 32), "refresh responder xi");
    let initiator_rnd = fixed::<32>(&tv_draw(ID, "mldsa-rnd", 0, 32), "refresh INIT rnd");
    let responder_rnd = fixed::<32>(&tv_draw(ID, "mldsa-rnd", 1, 32), "refresh RESP rnd");
    let initiator_signing = SigningKey::<MlDsa65>::from_seed(&initiator_xi.into());
    let responder_signing = SigningKey::<MlDsa65>::from_seed(&responder_xi.into());
    let initiator_verification = initiator_signing.verifying_key();
    let responder_verification = responder_signing.verifying_key();
    let initiator_fingerprint = fingerprint(initiator_verification.encode().as_ref());
    let responder_fingerprint = fingerprint(responder_verification.encode().as_ref());
    let mut fixture = pair_with_fingerprints(ID, initiator_fingerprint, responder_fingerprint);
    let old_session_id = *fixture.initiator.session_id();

    let refresh_id = fixed::<32>(&tv_draw(ID, "nonce", 0, 32), "refresh ID");
    fixture.initiator.begin_refresh(refresh_id).unwrap();
    let init_x_private = fixed::<32>(&tv_draw(ID, "x25519-private", 0, 32), "refresh INIT X25519");
    let init_x_secret = X25519SecretKey::from_bytes(&init_x_private).unwrap();
    let init_x_public = init_x_secret.public_key();
    let kem_d = fixed::<32>(&tv_draw(ID, "mlkem-d", 0, 32), "refresh ML-KEM d");
    let kem_z = fixed::<32>(&tv_draw(ID, "mlkem-z", 0, 32), "refresh ML-KEM z");
    let mut kem_seed_bytes = [0_u8; 64];
    kem_seed_bytes[..32].copy_from_slice(&kem_d);
    kem_seed_bytes[32..].copy_from_slice(&kem_z);
    let kem_seed: ml_kem::Seed = kem_seed_bytes.into();
    let (kem_decapsulation, kem_encapsulation) = MlKem768::from_seed(&kem_seed);
    let kem_encapsulation_bytes = kem_encapsulation.to_bytes();

    let mut init_core = Vec::new();
    init_core.extend_from_slice(&old_session_id);
    init_core.extend_from_slice(fixture.initiator.transcript_hash());
    init_core.extend_from_slice(&refresh_id);
    init_core.extend_from_slice(&initiator_fingerprint);
    init_core.extend_from_slice(&responder_fingerprint);
    init_core.extend_from_slice(&init_x_public);
    init_core.extend_from_slice(kem_encapsulation_bytes.as_ref());
    init_core.extend_from_slice(&(fixture.initiator.next_send_index() + 1).to_be_bytes());
    init_core.extend_from_slice(&fixture.initiator.next_receive_index().to_be_bytes());
    assert_eq!(init_core.len(), REFRESH_INIT_CORE_SIZE);
    let init_digest = refresh_init_digest(&init_core);
    let init_signature = sign_digest(&initiator_signing, &init_digest, &initiator_rnd);
    let mut init_content = init_core.clone();
    init_content.extend_from_slice(&init_signature);
    let init_envelope = fixture
        .initiator
        .send_refresh_control(ContentKind::RefreshInit, &init_content)
        .unwrap();
    let responder_before_init = fixture.responder.test_state_hash();
    fixture
        .responder
        .receive_validated(&init_envelope.envelope, |record| {
            if !exact_size(
                record.content.len(),
                REFRESH_INIT_CORE_SIZE + ML_DSA_65_SIG_SIZE,
            ) {
                return Err(SessionError::AuthenticationFailed);
            }
            let (core, signature) = record.content.split_at(REFRESH_INIT_CORE_SIZE);
            if core != init_core
                || !verify_signature(
                    &initiator_verification,
                    &refresh_init_digest(core),
                    signature,
                )
            {
                return Err(SessionError::AuthenticationFailed);
            }
            Ok(())
        })
        .unwrap();
    fixture.responder.begin_refresh(refresh_id).unwrap();

    let resp_x_private = fixed::<32>(&tv_draw(ID, "x25519-private", 1, 32), "refresh RESP X25519");
    let resp_x_secret = X25519SecretKey::from_bytes(&resp_x_private).unwrap();
    let resp_x_public = resp_x_secret.public_key();
    let kem_m = fixed::<32>(&tv_draw(ID, "mlkem-m", 0, 32), "refresh ML-KEM m");
    let kem_entropy: ml_kem::B32 = kem_m.into();
    let (kem_ciphertext, kem_shared) = kem_encapsulation.encapsulate_deterministic(&kem_entropy);
    let kem_recovered = kem_decapsulation.decapsulate(&kem_ciphertext);
    assert_eq!(kem_shared, kem_recovered);
    let responder_x = resp_x_secret.diffie_hellman(&init_x_public).unwrap();
    let initiator_x = init_x_secret.diffie_hellman(&resp_x_public).unwrap();
    assert_eq!(responder_x.expose_secret(), initiator_x.expose_secret());

    let mut init_signed = init_core.clone();
    init_signed.extend_from_slice(&init_signature);
    let refresh_init_hash = hash512(&[b"HYDRA-MSG/v1/refresh", &length_prefixed(&init_signed)]);
    let mut resp_core = Vec::new();
    resp_core.extend_from_slice(&refresh_init_hash);
    resp_core.extend_from_slice(&resp_x_public);
    resp_core.extend_from_slice(kem_ciphertext.as_ref());
    resp_core.extend_from_slice(&(fixture.responder.next_send_index() + 1).to_be_bytes());
    resp_core.extend_from_slice(&fixture.responder.next_receive_index().to_be_bytes());
    assert_eq!(resp_core.len(), 1200);
    let pretranscript = hash512(&[
        b"HYDRA-MSG/v1/refresh",
        &length_prefixed(&init_signed),
        &length_prefixed(&resp_core),
    ]);
    let mix = refresh_mix(
        &old_session_id,
        &pretranscript,
        responder_x.expose_secret(),
        kem_shared.as_ref(),
    );

    let initial_refresh_root = expand32(
        &fixture.handshake_secret,
        b"HYDRA-MSG/v1/refresh-root",
        &fixture.transcript_hash,
    );
    let candidate_secret = RustCryptoBackend::hkdf_extract(&initial_refresh_root, &mix);
    let new_session_id = expand32(
        candidate_secret.expose_secret(),
        b"HYDRA-MSG/v1/session-id",
        &pretranscript,
    );
    let confirm_key = SecretBytes::from_array(expand32(
        candidate_secret.expose_secret(),
        b"HYDRA-MSG/v1/confirm-key",
        &pretranscript,
    ));
    let mut confirm_input = Vec::new();
    confirm_input.extend_from_slice(b"HYDRA-MSG/v1/resp-confirm");
    confirm_input.extend_from_slice(&pretranscript);
    confirm_input.extend_from_slice(&new_session_id);
    let confirmation = RustCryptoBackend::hmac_sha3_256(&confirm_key, &confirm_input);
    let resp_digest =
        refresh_resp_digest(&pretranscript, &new_session_id, &confirmation, &resp_core);
    let resp_signature = sign_digest(&responder_signing, &resp_digest, &responder_rnd);
    let mut resp_content = resp_core.clone();
    resp_content.extend_from_slice(&new_session_id);
    resp_content.extend_from_slice(&confirmation);
    resp_content.extend_from_slice(&resp_signature);
    let mut resp_signed = resp_core.clone();
    resp_signed.extend_from_slice(&new_session_id);
    resp_signed.extend_from_slice(&confirmation);
    resp_signed.extend_from_slice(&resp_signature);
    let refresh_transcript = hash512(&[
        b"HYDRA-MSG/v1/refresh",
        &length_prefixed(&init_signed),
        &length_prefixed(&resp_signed),
    ]);

    let responder_candidate = fixture
        .responder
        .derive_refresh_candidate(
            RefreshRole::Responder,
            &mix,
            pretranscript,
            refresh_transcript,
        )
        .unwrap();
    assert_eq!(responder_candidate.new_session_id(), &new_session_id);
    assert_eq!(responder_candidate.response_confirmation(), confirmation);
    let resp_envelope = fixture
        .responder
        .send_refresh_control(ContentKind::RefreshResp, &resp_content)
        .unwrap();
    fixture
        .initiator
        .receive_validated(&resp_envelope.envelope, |record| {
            let expected_length = 1200 + 32 + 32 + ML_DSA_65_SIG_SIZE;
            if !exact_size(record.content.len(), expected_length) {
                return Err(SessionError::AuthenticationFailed);
            }
            let core = &record.content[..1200];
            let received_session = &record.content[1200..1232];
            let received_confirm = &record.content[1232..1264];
            let signature = &record.content[1264..];
            if core != resp_core
                || received_session != new_session_id
                || received_confirm != confirmation
                || !verify_signature(
                    &responder_verification,
                    &refresh_resp_digest(&pretranscript, &new_session_id, &confirmation, core),
                    signature,
                )
            {
                return Err(SessionError::AuthenticationFailed);
            }
            Ok(())
        })
        .unwrap();
    let initiator_candidate = fixture
        .initiator
        .derive_refresh_candidate(
            RefreshRole::Initiator,
            &mix,
            pretranscript,
            refresh_transcript,
        )
        .unwrap();
    let initiator_confirmed = initiator_candidate.confirm_response(&confirmation).unwrap();
    let responder_confirmed = responder_candidate.confirm_response(&confirmation).unwrap();
    let (finish_envelope, initiator_verified) = initiator_confirmed.seal_finish().unwrap();
    let responder_verified = responder_confirmed.open_finish(&finish_envelope).unwrap();
    fixture
        .initiator
        .install_refresh(initiator_verified)
        .unwrap();
    fixture
        .responder
        .install_refresh(responder_verified)
        .unwrap();
    assert_eq!(fixture.initiator.session_id(), &new_session_id);
    assert_eq!(fixture.responder.session_id(), &new_session_id);

    let mut artifacts = base_artifacts(&fixture);
    artifacts.extend([
        ("initiator_identity_xi".to_owned(), initiator_xi.to_vec()),
        ("responder_identity_xi".to_owned(), responder_xi.to_vec()),
        ("initiator_signature_rnd".to_owned(), initiator_rnd.to_vec()),
        ("responder_signature_rnd".to_owned(), responder_rnd.to_vec()),
        ("refresh_id".to_owned(), refresh_id.to_vec()),
        (
            "initiator_x25519_private".to_owned(),
            init_x_private.to_vec(),
        ),
        (
            "responder_x25519_private".to_owned(),
            resp_x_private.to_vec(),
        ),
        ("mlkem_d".to_owned(), kem_d.to_vec()),
        ("mlkem_z".to_owned(), kem_z.to_vec()),
        ("mlkem_m".to_owned(), kem_m.to_vec()),
        ("refresh_init_core".to_owned(), init_core),
        ("refresh_init_digest".to_owned(), init_digest.to_vec()),
        ("refresh_init_signature".to_owned(), init_signature.to_vec()),
        ("refresh_init_envelope".to_owned(), init_envelope.envelope),
        ("refresh_resp_core".to_owned(), resp_core),
        ("refresh_pretranscript".to_owned(), pretranscript.to_vec()),
        ("refresh_mix".to_owned(), mix.to_vec()),
        ("new_session_id".to_owned(), new_session_id.to_vec()),
        ("refresh_resp_confirm".to_owned(), confirmation.to_vec()),
        ("refresh_resp_digest".to_owned(), resp_digest.to_vec()),
        ("refresh_resp_signature".to_owned(), resp_signature.to_vec()),
        ("refresh_resp_envelope".to_owned(), resp_envelope.envelope),
        ("refresh_transcript".to_owned(), refresh_transcript.to_vec()),
        ("refresh_finish_envelope".to_owned(), finish_envelope),
        (
            "responder_state_before_init".to_owned(),
            responder_before_init.to_vec(),
        ),
        (
            "initiator_state_after_install".to_owned(),
            fixture.initiator.test_state_hash().to_vec(),
        ),
        (
            "responder_state_after_install".to_owned(),
            fixture.responder.test_state_hash().to_vec(),
        ),
    ]);
    let entropy = [
        ("message", 0, 64, "transcript_hash"),
        ("message", 1, 32, "handshake_secret"),
        ("mldsa-xi", 0, 32, "initiator_identity_xi"),
        ("mldsa-xi", 1, 32, "responder_identity_xi"),
        ("mldsa-rnd", 0, 32, "initiator_signature_rnd"),
        ("mldsa-rnd", 1, 32, "responder_signature_rnd"),
        ("nonce", 0, 32, "refresh_id"),
        ("x25519-private", 0, 32, "initiator_x25519_private"),
        ("x25519-private", 1, 32, "responder_x25519_private"),
        ("mlkem-d", 0, 32, "mlkem_d"),
        ("mlkem-z", 0, 32, "mlkem_z"),
        ("mlkem-m", 0, 32, "mlkem_m"),
    ];
    write_owned(
        root,
        "refresh",
        ID,
        &metadata(
            "signed hybrid refresh INIT/RESP and authenticated FINISH installed",
            "both roles atomically install the same new session at index zero",
            "old roots, chains, replay, skipped, hybrid, confirmation, and finish secrets erased",
            &entropy,
        ),
        &artifacts,
    );

    generate_refresh_bad_signature(root);
    generate_refresh_conflict(root);
}

fn generate_refresh_bad_signature(root: &Path) {
    const ID: &str = "TV-REFRESH-001";
    let xi = fixed::<32>(&tv_draw(ID, "mldsa-xi", 0, 32), "bad refresh xi");
    let rnd = fixed::<32>(&tv_draw(ID, "mldsa-rnd", 0, 32), "bad refresh rnd");
    let signing = SigningKey::<MlDsa65>::from_seed(&xi.into());
    let verification = signing.verifying_key();
    let init_fingerprint = fingerprint(verification.encode().as_ref());
    let mut f = pair_with_fingerprints(ID, init_fingerprint, [0x22; 32]);
    let refresh_id = fixed::<32>(&tv_draw(ID, "nonce", 0, 32), "bad refresh ID");
    f.initiator.begin_refresh(refresh_id).unwrap();
    let mut core = vec![0_u8; REFRESH_INIT_CORE_SIZE];
    core[..32].copy_from_slice(f.initiator.session_id());
    core[32..96].copy_from_slice(f.initiator.transcript_hash());
    core[96..128].copy_from_slice(&refresh_id);
    core[128..160].copy_from_slice(&init_fingerprint);
    core[160..192].copy_from_slice(f.initiator.remote_identity_fingerprint());
    core[1408..1416].copy_from_slice(&1_u64.to_be_bytes());
    let digest = refresh_init_digest(&core);
    let mut signature = sign_digest(&signing, &digest, &rnd);
    signature[0] ^= 1;
    let mut content = core.clone();
    content.extend_from_slice(&signature);
    let envelope = f
        .initiator
        .send_refresh_control(ContentKind::RefreshInit, &content)
        .unwrap();
    let before = f.responder.test_state_hash();
    assert_eq!(
        f.responder.receive_validated(&envelope.envelope, |record| {
            if !exact_size(
                record.content.len(),
                REFRESH_INIT_CORE_SIZE + ML_DSA_65_SIG_SIZE,
            ) {
                return Err(SessionError::AuthenticationFailed);
            }
            let (received_core, received_signature) =
                record.content.split_at(REFRESH_INIT_CORE_SIZE);
            if verify_signature(
                &verification,
                &refresh_init_digest(received_core),
                received_signature,
            ) {
                Ok(())
            } else {
                Err(SessionError::AuthenticationFailed)
            }
        }),
        Err(SessionError::AuthenticationFailed)
    );
    let after = f.responder.test_state_hash();
    assert_eq!(before, after);

    let mut response_fixture =
        pair_with_fingerprints(ID, [0x11; 32], fingerprint(verification.encode().as_ref()));
    response_fixture
        .initiator
        .begin_refresh(refresh_id)
        .unwrap();
    response_fixture
        .responder
        .begin_refresh(refresh_id)
        .unwrap();
    let response_core = vec![0_u8; 1200];
    let response_pretranscript = [0x77; 64];
    let response_session_id = [0x88; 32];
    let response_confirmation = [0x99; 32];
    let response_digest = refresh_resp_digest(
        &response_pretranscript,
        &response_session_id,
        &response_confirmation,
        &response_core,
    );
    let mut response_signature = sign_digest(&signing, &response_digest, &rnd);
    response_signature[0] ^= 1;
    let mut response_content = response_core.clone();
    response_content.extend_from_slice(&response_session_id);
    response_content.extend_from_slice(&response_confirmation);
    response_content.extend_from_slice(&response_signature);
    let response_envelope = response_fixture
        .responder
        .send_refresh_control(ContentKind::RefreshResp, &response_content)
        .unwrap();
    let response_before = response_fixture.initiator.test_state_hash();
    assert_eq!(
        response_fixture
            .initiator
            .receive_validated(&response_envelope.envelope, |record| {
                let expected_length = 1200 + 32 + 32 + ML_DSA_65_SIG_SIZE;
                if !exact_size(record.content.len(), expected_length) {
                    return Err(SessionError::AuthenticationFailed);
                }
                if verify_signature(
                    &verification,
                    &refresh_resp_digest(
                        &response_pretranscript,
                        &response_session_id,
                        &response_confirmation,
                        &record.content[..1200],
                    ),
                    &record.content[1264..],
                ) {
                    Ok(())
                } else {
                    Err(SessionError::AuthenticationFailed)
                }
            }),
        Err(SessionError::AuthenticationFailed)
    );
    let response_after = response_fixture.initiator.test_state_hash();
    assert_eq!(response_before, response_after);

    let mut artifacts = base_artifacts(&f);
    artifacts.extend([
        ("identity_xi".to_owned(), xi.to_vec()),
        ("signature_rnd".to_owned(), rnd.to_vec()),
        ("refresh_id".to_owned(), refresh_id.to_vec()),
        ("refresh_init_core".to_owned(), core),
        ("mutated_signature".to_owned(), signature.to_vec()),
        ("envelope".to_owned(), envelope.envelope),
        ("state_before".to_owned(), before.to_vec()),
        ("state_after".to_owned(), after.to_vec()),
        ("refresh_resp_core".to_owned(), response_core),
        (
            "mutated_resp_signature".to_owned(),
            response_signature.to_vec(),
        ),
        (
            "refresh_resp_envelope".to_owned(),
            response_envelope.envelope,
        ),
        (
            "resp_receiver_state_before".to_owned(),
            response_before.to_vec(),
        ),
        (
            "resp_receiver_state_after".to_owned(),
            response_after.to_vec(),
        ),
    ]);
    let entropy = [
        ("message", 0, 64, "transcript_hash"),
        ("message", 1, 32, "handshake_secret"),
        ("mldsa-xi", 0, 32, "identity_xi"),
        ("mldsa-rnd", 0, 32, "signature_rnd"),
        ("nonce", 0, 32, "refresh_id"),
    ];
    write_owned(
        root,
        "refresh",
        ID,
        &metadata(
            "invalid refresh INIT and RESP identity signatures rejected before parent commit",
            "both receiver parent states unchanged",
            "provisional receive and signature material erased",
            &entropy,
        ),
        &artifacts,
    );
}

fn generate_refresh_conflict(root: &Path) {
    const ID: &str = "TV-REFRESH-002";
    let mut f = pair(ID);
    let before = f.initiator.test_state_hash();
    assert_eq!(
        f.initiator.begin_refresh([9; 32]),
        Ok(RefreshIdDecision::Accepted)
    );
    let after_local = f.initiator.test_state_hash();
    assert_eq!(
        f.initiator.begin_refresh([8; 32]),
        Ok(RefreshIdDecision::ReplacedLocal)
    );
    let after_lower = f.initiator.test_state_hash();
    assert_eq!(
        f.initiator.begin_refresh([10; 32]),
        Err(SessionError::RefreshConflict)
    );
    assert_eq!(f.initiator.test_state_hash(), after_lower);
    let mut artifacts = base_artifacts(&f);
    artifacts.extend([
        ("state_before".to_owned(), before.to_vec()),
        ("state_after_local".to_owned(), after_local.to_vec()),
        ("state_after_lower".to_owned(), after_lower.to_vec()),
        ("state_after_higher_reject".to_owned(), after_lower.to_vec()),
    ]);
    write_owned(
        root,
        "refresh",
        ID,
        &metadata(
            "lower concurrent refresh ID replaces local candidate; higher ID rejected",
            "Refreshing with lexicographically lowest ID",
            "losing candidate material erased by owner",
            session_entropy(),
        ),
        &artifacts,
    );
}

const ROTATION_CORE_SIZE: usize = 32 + ML_DSA_65_VK_SIZE + 8 + 8 + 32;
const REVOCATION_CORE_SIZE: usize = 32 + 32 + 32 + 8 + 8 + 2;

const fn exact_size(actual: usize, expected: usize) -> bool {
    actual == expected
}

fn rotation_digest(core: &[u8]) -> [u8; 64] {
    hash512(&[
        b"HYDRA-MSG/v1/identity-rotation",
        &SUITE_ID,
        &length_prefixed(core),
    ])
}

fn validate_rotation(
    record: &ProtectedRecord,
    old_verification: &ml_dsa::VerifyingKey<MlDsa65>,
    new_verification: &ml_dsa::VerifyingKey<MlDsa65>,
    minimum_rotation_index: u64,
) -> Result<u64, SessionError> {
    let expected = 4 + ROTATION_CORE_SIZE + 2 * ML_DSA_65_SIG_SIZE;
    if record.content_kind != ContentKind::IdentityRotation
        || !exact_size(record.content.len(), expected)
    {
        return Err(SessionError::AuthenticationFailed);
    }
    let core_length = u32::from_be_bytes(
        record.content[..4]
            .try_into()
            .map_err(|_| SessionError::AuthenticationFailed)?,
    ) as usize;
    if !exact_size(core_length, ROTATION_CORE_SIZE) {
        return Err(SessionError::AuthenticationFailed);
    }
    let core = &record.content[4..4 + ROTATION_CORE_SIZE];
    let rotation_index = u64::from_be_bytes(
        core[32 + ML_DSA_65_VK_SIZE..40 + ML_DSA_65_VK_SIZE]
            .try_into()
            .map_err(|_| SessionError::AuthenticationFailed)?,
    );
    let encoded_new_verification = new_verification.encode();
    if !strictly_increases(rotation_index, minimum_rotation_index)
        || core[..32] != fingerprint(old_verification.encode().as_ref())
        || core[32..32 + ML_DSA_65_VK_SIZE] != encoded_new_verification[..]
    {
        return Err(SessionError::AuthenticationFailed);
    }
    let digest = rotation_digest(core);
    let signatures = &record.content[4 + ROTATION_CORE_SIZE..];
    if !verify_signature(old_verification, &digest, &signatures[..ML_DSA_65_SIG_SIZE])
        || !verify_signature(new_verification, &digest, &signatures[ML_DSA_65_SIG_SIZE..])
    {
        return Err(SessionError::AuthenticationFailed);
    }
    Ok(rotation_index)
}

const fn strictly_increases(candidate: u64, current: u64) -> bool {
    candidate > current
}

struct RotationFixture {
    sessions: PairFixture,
    content: Vec<u8>,
    digest: [u8; 64],
    old_signature: [u8; ML_DSA_65_SIG_SIZE],
    new_signature: [u8; ML_DSA_65_SIG_SIZE],
    old_xi: [u8; 32],
    new_xi: [u8; 32],
    old_signing: SigningKey<MlDsa65>,
    new_signing: SigningKey<MlDsa65>,
}

fn rotation_fixture(vector_id: &str, rotation_index: u64) -> RotationFixture {
    let old_xi = fixed::<32>(&tv_draw(vector_id, "mldsa-xi", 0, 32), "old identity xi");
    let new_xi = fixed::<32>(&tv_draw(vector_id, "mldsa-xi", 1, 32), "new identity xi");
    let old_rnd = fixed::<32>(&tv_draw(vector_id, "mldsa-rnd", 0, 32), "old signature rnd");
    let new_rnd = fixed::<32>(&tv_draw(vector_id, "mldsa-rnd", 1, 32), "new signature rnd");
    let old_signing = SigningKey::<MlDsa65>::from_seed(&old_xi.into());
    let new_signing = SigningKey::<MlDsa65>::from_seed(&new_xi.into());
    let old_fingerprint = fingerprint(old_signing.verifying_key().encode().as_ref());
    let sessions = pair_with_fingerprints(vector_id, old_fingerprint, [0x22; 32]);
    let nonce = fixed::<32>(&tv_draw(vector_id, "nonce", 0, 32), "rotation nonce");
    let mut core = Vec::new();
    core.extend_from_slice(&old_fingerprint);
    core.extend_from_slice(new_signing.verifying_key().encode().as_ref());
    core.extend_from_slice(&rotation_index.to_be_bytes());
    core.extend_from_slice(&0_u64.to_be_bytes());
    core.extend_from_slice(&nonce);
    assert_eq!(core.len(), ROTATION_CORE_SIZE);
    let digest = rotation_digest(&core);
    let old_signature = sign_digest(&old_signing, &digest, &old_rnd);
    let new_signature = sign_digest(&new_signing, &digest, &new_rnd);
    let mut content = length_prefixed(&core);
    content.extend_from_slice(&old_signature);
    content.extend_from_slice(&new_signature);
    RotationFixture {
        sessions,
        content,
        digest,
        old_signature,
        new_signature,
        old_xi,
        new_xi,
        old_signing,
        new_signing,
    }
}

fn generate_rotation_accepted(root: &Path, id: &str) {
    let RotationFixture {
        sessions: mut fixture,
        content,
        digest,
        old_signature,
        new_signature,
        old_xi,
        new_xi,
        old_signing,
        new_signing,
    } = rotation_fixture(id, 1);
    let old_rnd = fixed::<32>(&tv_draw(id, "mldsa-rnd", 0, 32), "old signature rnd");
    let new_rnd = fixed::<32>(&tv_draw(id, "mldsa-rnd", 1, 32), "new signature rnd");
    let nonce = fixed::<32>(&tv_draw(id, "nonce", 0, 32), "rotation nonce");
    let receiver_before = fixture.responder.test_state_hash();
    let envelope = fixture
        .initiator
        .send_signed_control(ContentKind::IdentityRotation, &content)
        .unwrap();
    let received = fixture
        .responder
        .receive_validated(&envelope.envelope, |record| {
            validate_rotation(
                record,
                &old_signing.verifying_key(),
                &new_signing.verifying_key(),
                0,
            )
            .map(|_| ())
        })
        .unwrap();
    assert_eq!(received.content_kind, ContentKind::IdentityRotation);
    let receiver_after_accept = fixture.responder.test_state_hash();
    fixture.initiator.full_wipe();
    fixture.responder.full_wipe();
    let core = content[4..4 + ROTATION_CORE_SIZE].to_vec();
    let mut artifacts = base_artifacts(&fixture);
    artifacts.extend([
        ("old_identity_xi".to_owned(), old_xi.to_vec()),
        ("new_identity_xi".to_owned(), new_xi.to_vec()),
        ("old_signature_rnd".to_owned(), old_rnd.to_vec()),
        ("new_signature_rnd".to_owned(), new_rnd.to_vec()),
        ("nonce".to_owned(), nonce.to_vec()),
        ("rotation_core".to_owned(), core),
        ("rotation_digest".to_owned(), digest.to_vec()),
        ("old_signature".to_owned(), old_signature.to_vec()),
        ("new_signature".to_owned(), new_signature.to_vec()),
        ("content".to_owned(), content),
        ("envelope".to_owned(), envelope.envelope),
        ("receiver_state_before".to_owned(), receiver_before.to_vec()),
        (
            "receiver_state_after_accept".to_owned(),
            receiver_after_accept.to_vec(),
        ),
        (
            "receiver_state_after_close".to_owned(),
            fixture.responder.test_state_hash().to_vec(),
        ),
    ]);
    let entropy = [
        ("message", 0, 64, "transcript_hash"),
        ("message", 1, 32, "handshake_secret"),
        ("mldsa-xi", 0, 32, "old_identity_xi"),
        ("mldsa-xi", 1, 32, "new_identity_xi"),
        ("mldsa-rnd", 0, 32, "old_signature_rnd"),
        ("mldsa-rnd", 1, 32, "new_signature_rnd"),
        ("nonce", 0, 32, "nonce"),
    ];
    write_owned(
        root,
        "identity",
        id,
        &metadata(
            "old and new identity signatures verified over one rotation digest",
            "rotation accepted and affected sessions closed",
            "old session traffic state erased; new handshake required",
            &entropy,
        ),
        &artifacts,
    );
}

fn generate_rotation_missing_signature(root: &Path) {
    const ID: &str = "TV-ID-ROT-001";
    let RotationFixture {
        sessions: mut fixture,
        mut content,
        digest,
        old_signature,
        new_signature: _,
        old_xi,
        new_xi,
        old_signing,
        new_signing,
    } = rotation_fixture(ID, 1);
    content.truncate(4 + ROTATION_CORE_SIZE + ML_DSA_65_SIG_SIZE);
    let envelope = fixture
        .initiator
        .send_signed_control(ContentKind::IdentityRotation, &content)
        .unwrap();
    let before = fixture.responder.test_state_hash();
    assert_eq!(
        fixture
            .responder
            .receive_validated(&envelope.envelope, |record| {
                validate_rotation(
                    record,
                    &old_signing.verifying_key(),
                    &new_signing.verifying_key(),
                    0,
                )
                .map(|_| ())
            }),
        Err(SessionError::AuthenticationFailed)
    );
    let after = fixture.responder.test_state_hash();
    assert_eq!(before, after);
    let mut artifacts = base_artifacts(&fixture);
    artifacts.extend([
        ("old_identity_xi".to_owned(), old_xi.to_vec()),
        ("new_identity_xi".to_owned(), new_xi.to_vec()),
        ("rotation_digest".to_owned(), digest.to_vec()),
        ("old_signature".to_owned(), old_signature.to_vec()),
        ("truncated_content".to_owned(), content),
        ("envelope".to_owned(), envelope.envelope),
        ("state_before".to_owned(), before.to_vec()),
        ("state_after".to_owned(), after.to_vec()),
    ]);
    write_owned(
        root,
        "identity",
        ID,
        &metadata(
            "rotation missing new-key signature rejected",
            "receiver parent state unchanged",
            "provisional receive state erased",
            session_entropy(),
        ),
        &artifacts,
    );
}

fn generate_rotation_rollback(root: &Path) {
    const ID: &str = "TV-ID-ROT-002";
    let RotationFixture {
        sessions: mut fixture,
        content,
        digest,
        old_signature,
        new_signature,
        old_xi,
        new_xi,
        old_signing,
        new_signing,
    } = rotation_fixture(ID, 5);
    let envelope = fixture
        .initiator
        .send_signed_control(ContentKind::IdentityRotation, &content)
        .unwrap();
    let before = fixture.responder.test_state_hash();
    assert_eq!(
        fixture
            .responder
            .receive_validated(&envelope.envelope, |record| {
                validate_rotation(
                    record,
                    &old_signing.verifying_key(),
                    &new_signing.verifying_key(),
                    5,
                )
                .map(|_| ())
            }),
        Err(SessionError::AuthenticationFailed)
    );
    let after = fixture.responder.test_state_hash();
    assert_eq!(before, after);
    let mut artifacts = base_artifacts(&fixture);
    artifacts.extend([
        ("old_identity_xi".to_owned(), old_xi.to_vec()),
        ("new_identity_xi".to_owned(), new_xi.to_vec()),
        ("rotation_digest".to_owned(), digest.to_vec()),
        ("old_signature".to_owned(), old_signature.to_vec()),
        ("new_signature".to_owned(), new_signature.to_vec()),
        ("envelope".to_owned(), envelope.envelope),
        ("state_before".to_owned(), before.to_vec()),
        ("state_after".to_owned(), after.to_vec()),
    ]);
    write_owned(
        root,
        "identity",
        ID,
        &metadata(
            "non-increasing rotation index rejected",
            "receiver parent state unchanged",
            "provisional receive state erased",
            session_entropy(),
        ),
        &artifacts,
    );
}

fn revocation_digest(core: &[u8]) -> [u8; 64] {
    hash512(&[
        b"HYDRA-MSG/v1/device-revocation",
        &SUITE_ID,
        &length_prefixed(core),
    ])
}

fn validate_revocation_count(count: u8) -> Result<(), SessionError> {
    if (1..=16).contains(&count) {
        Ok(())
    } else {
        Err(SessionError::AuthenticationFailed)
    }
}

fn validate_revocation(
    record: &ProtectedRecord,
    required_authorizers: &[ml_dsa::VerifyingKey<MlDsa65>],
    minimum_roster_version: u64,
) -> Result<(), SessionError> {
    if record.content_kind != ContentKind::DeviceRevocation
        || record.content.len() < 4 + REVOCATION_CORE_SIZE + 1
    {
        return Err(SessionError::AuthenticationFailed);
    }
    let core_length = u32::from_be_bytes(
        record.content[..4]
            .try_into()
            .map_err(|_| SessionError::AuthenticationFailed)?,
    ) as usize;
    if !exact_size(core_length, REVOCATION_CORE_SIZE) {
        return Err(SessionError::AuthenticationFailed);
    }
    let core = &record.content[4..4 + REVOCATION_CORE_SIZE];
    let roster_version = u64::from_be_bytes(
        core[96..104]
            .try_into()
            .map_err(|_| SessionError::AuthenticationFailed)?,
    );
    let core_revoker: [u8; 32] = core[64..96]
        .try_into()
        .map_err(|_| SessionError::AuthenticationFailed)?;
    if !strictly_increases(roster_version, minimum_roster_version)
        || !required_authorizers
            .iter()
            .any(|key| fingerprint(key.encode().as_ref()) == core_revoker)
    {
        return Err(SessionError::AuthenticationFailed);
    }
    let count = record.content[4 + REVOCATION_CORE_SIZE];
    validate_revocation_count(count)?;
    if usize::from(count) != required_authorizers.len() {
        return Err(SessionError::AuthenticationFailed);
    }
    let entries = &record.content[5 + REVOCATION_CORE_SIZE..];
    let entry_size = 32 + ML_DSA_65_SIG_SIZE;
    if entries.len() != usize::from(count) * entry_size {
        return Err(SessionError::AuthenticationFailed);
    }
    let digest = revocation_digest(core);
    let mut previous: Option<[u8; 32]> = None;
    for entry in entries.chunks_exact(entry_size) {
        let signer_fingerprint: [u8; 32] = entry[..32]
            .try_into()
            .map_err(|_| SessionError::AuthenticationFailed)?;
        let Some(verification) = required_authorizers
            .iter()
            .find(|key| fingerprint(key.encode().as_ref()) == signer_fingerprint)
        else {
            return Err(SessionError::AuthenticationFailed);
        };
        if previous.is_some_and(|value| value >= signer_fingerprint)
            || !verify_signature(verification, &digest, &entry[32..])
        {
            return Err(SessionError::AuthenticationFailed);
        }
        previous = Some(signer_fingerprint);
    }
    Ok(())
}

fn generate_revocation(root: &Path) {
    const ID: &str = "TV-ID-REV-000";
    let xi = fixed::<32>(&tv_draw(ID, "mldsa-xi", 0, 32), "revoker xi");
    let rnd = fixed::<32>(&tv_draw(ID, "mldsa-rnd", 0, 32), "revoker rnd");
    let signing = SigningKey::<MlDsa65>::from_seed(&xi.into());
    let verification = signing.verifying_key();
    let revoker_fingerprint = fingerprint(verification.encode().as_ref());
    let mut fixture = pair(ID);
    let mut core = Vec::new();
    core.extend_from_slice(&[0x31; 32]);
    core.extend_from_slice(&[0x32; 32]);
    core.extend_from_slice(&revoker_fingerprint);
    core.extend_from_slice(&1_u64.to_be_bytes());
    core.extend_from_slice(&0_u64.to_be_bytes());
    core.extend_from_slice(&7_u16.to_be_bytes());
    assert_eq!(core.len(), REVOCATION_CORE_SIZE);
    let digest = revocation_digest(&core);
    let signature = sign_digest(&signing, &digest, &rnd);
    let mut content = length_prefixed(&core);
    content.push(1);
    content.extend_from_slice(&revoker_fingerprint);
    content.extend_from_slice(&signature);
    let envelope = fixture
        .initiator
        .send_signed_control(ContentKind::DeviceRevocation, &content)
        .unwrap();
    let before = fixture.responder.test_state_hash();
    fixture
        .responder
        .receive_validated(&envelope.envelope, |record| {
            validate_revocation(record, std::slice::from_ref(&verification), 0)
        })
        .unwrap();
    let after_accept = fixture.responder.test_state_hash();
    fixture.responder.full_wipe();
    for count in [1, 2, 15, 16] {
        assert_eq!(validate_revocation_count(count), Ok(()));
    }
    for count in [0, 17] {
        assert_eq!(
            validate_revocation_count(count),
            Err(SessionError::AuthenticationFailed)
        );
    }
    let mut artifacts = base_artifacts(&fixture);
    artifacts.extend([
        ("revoker_xi".to_owned(), xi.to_vec()),
        ("signature_rnd".to_owned(), rnd.to_vec()),
        ("revocation_core".to_owned(), core),
        ("revocation_digest".to_owned(), digest.to_vec()),
        ("signature".to_owned(), signature.to_vec()),
        ("content".to_owned(), content),
        ("envelope".to_owned(), envelope.envelope),
        ("state_before".to_owned(), before.to_vec()),
        ("state_after_accept".to_owned(), after_accept.to_vec()),
        (
            "state_after_close".to_owned(),
            fixture.responder.test_state_hash().to_vec(),
        ),
        (
            "signature_count_boundaries".to_owned(),
            vec![0, 1, 2, 15, 16, 17],
        ),
    ]);
    let entropy = [
        ("message", 0, 64, "transcript_hash"),
        ("message", 1, 32, "handshake_secret"),
        ("mldsa-xi", 0, 32, "revoker_xi"),
        ("mldsa-rnd", 0, 32, "signature_rnd"),
    ];
    write_owned(
        root,
        "identity",
        ID,
        &metadata(
            "authorized single-signature device revocation accepted",
            "roster policy advances and affected session closes",
            "affected session traffic state erased",
            &entropy,
        ),
        &artifacts,
    );
}

fn generate_identity(root: &Path) {
    generate_rotation_accepted(root, "TV-ID-ROT-000");
    generate_rotation_missing_signature(root);
    generate_rotation_rollback(root);
    generate_rotation_accepted(root, "TV-ID-ROT-003");
    generate_revocation(root);
}

pub fn generate(root: &Path) {
    generate_exact_ratchet_and_envelope(root);
    generate_data(root);
    generate_malformed(root);
    generate_ratchet(root);
    generate_close(root);
    generate_refresh(root);
    generate_identity(root);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revocation_with_signers(
        count: usize,
    ) -> (ProtectedRecord, Vec<ml_dsa::VerifyingKey<MlDsa65>>) {
        let mut signers = (0..count)
            .map(|index| {
                let seed: ml_dsa::Seed = [u8::try_from(index + 1).unwrap(); 32].into();
                SigningKey::<MlDsa65>::from_seed(&seed)
            })
            .collect::<Vec<_>>();
        signers.sort_by_key(|key| fingerprint(key.verifying_key().encode().as_ref()));
        let authorized = signers
            .iter()
            .map(SigningKey::verifying_key)
            .collect::<Vec<_>>();
        let mut core = Vec::new();
        core.extend_from_slice(&[0x31; 32]);
        core.extend_from_slice(&[0x32; 32]);
        core.extend_from_slice(&fingerprint(authorized[0].encode().as_ref()));
        core.extend_from_slice(&1_u64.to_be_bytes());
        core.extend_from_slice(&0_u64.to_be_bytes());
        core.extend_from_slice(&0_u16.to_be_bytes());
        let digest = revocation_digest(&core);
        let mut content = length_prefixed(&core);
        content.push(u8::try_from(count).unwrap());
        for (index, signer) in signers.iter().enumerate() {
            let verification = signer.verifying_key();
            content.extend_from_slice(&fingerprint(verification.encode().as_ref()));
            content.extend_from_slice(&sign_digest(
                signer,
                &digest,
                &[u8::try_from(index + 1).unwrap(); 32],
            ));
        }
        (
            ProtectedRecord {
                content_kind: ContentKind::DeviceRevocation,
                session_or_group_id: [0; 32],
                sender_id: [0; 32],
                epoch: 0,
                state_version: 0,
                message_index: 0,
                content,
            },
            authorized,
        )
    }

    #[test]
    fn every_m6_fixed_size_checks_n_minus_one_n_and_n_plus_one() {
        for expected in [
            REFRESH_INIT_CORE_SIZE,
            1200,
            ROTATION_CORE_SIZE,
            REVOCATION_CORE_SIZE,
            ML_DSA_65_SIG_SIZE,
        ] {
            assert!(!exact_size(expected - 1, expected));
            assert!(exact_size(expected, expected));
            assert!(!exact_size(expected + 1, expected));
        }
    }

    #[test]
    fn monotonic_indices_reject_n_minus_one_and_n_but_accept_n_plus_one() {
        let current = 5;
        assert!(!strictly_increases(current - 1, current));
        assert!(!strictly_increases(current, current));
        assert!(strictly_increases(current + 1, current));
    }

    #[test]
    fn revocation_signature_count_boundaries_and_storage_match() {
        for count in [1, 2, 15, 16] {
            assert_eq!(validate_revocation_count(count), Ok(()));
        }
        for count in [0, 17] {
            assert_eq!(
                validate_revocation_count(count),
                Err(SessionError::AuthenticationFailed)
            );
        }
        for count in [1, 15, 16] {
            let (record, authorized) = revocation_with_signers(count);
            assert_eq!(validate_revocation(&record, &authorized, 0), Ok(()));
        }
    }

    #[test]
    fn revocation_rejects_duplicate_signers_and_nonincreasing_roster() {
        let (mut record, authorized) = revocation_with_signers(2);
        let entry_size = 32 + ML_DSA_65_SIG_SIZE;
        let entries_start = 5 + REVOCATION_CORE_SIZE;
        let first = record.content[entries_start..entries_start + entry_size].to_vec();
        record.content[entries_start + entry_size..entries_start + 2 * entry_size]
            .copy_from_slice(&first);
        assert_eq!(
            validate_revocation(&record, &authorized, 0),
            Err(SessionError::AuthenticationFailed)
        );

        let (record, authorized) = revocation_with_signers(1);
        assert_eq!(
            validate_revocation(&record, &authorized, 1),
            Err(SessionError::AuthenticationFailed)
        );
    }
}
