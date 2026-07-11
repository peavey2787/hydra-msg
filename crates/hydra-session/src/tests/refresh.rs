use super::*;

#[test]
fn confirmed_refresh_finish_atomically_cuts_over_both_roles() {
    let (mut initiator, mut responder) = pair();
    let old_zero = initiator.send_data(b"old-zero").unwrap();
    let old_one = initiator.send_data(b"old-one").unwrap();
    responder.receive(&old_one.envelope).unwrap();
    assert_eq!(responder.skipped_key_count(), 1);

    let refresh_id = [0x10; 32];
    initiator.begin_refresh(refresh_id).unwrap();
    responder.begin_refresh(refresh_id).unwrap();
    let old_session_id = *initiator.session_id();
    let mix = [0x55; 32];
    let pretranscript = [0x66; 64];
    let transcript = [0x77; 64];
    let initiator_candidate = initiator
        .derive_refresh_candidate(RefreshRole::Initiator, &mix, pretranscript, transcript)
        .unwrap();
    let responder_candidate = responder
        .derive_refresh_candidate(RefreshRole::Responder, &mix, pretranscript, transcript)
        .unwrap();
    let confirmation = responder_candidate.response_confirmation();
    let initiator_confirmed = initiator_candidate.confirm_response(&confirmation).unwrap();
    let responder_confirmed = responder_candidate.confirm_response(&confirmation).unwrap();
    let (finish, initiator_verified) = initiator_confirmed.seal_finish().unwrap();
    let responder_verified = responder_confirmed.open_finish(&finish).unwrap();

    initiator.install_refresh(initiator_verified).unwrap();
    responder.install_refresh(responder_verified).unwrap();
    assert_ne!(initiator.session_id(), &old_session_id);
    assert_eq!(initiator.session_id(), responder.session_id());
    assert_eq!(
        (initiator.next_send_index(), responder.next_receive_index()),
        (0, 0)
    );
    assert_eq!(responder.skipped_key_count(), 0);
    assert_eq!(
        responder.receive(&old_zero.envelope),
        Err(SessionError::AuthenticationFailed)
    );
    assert_eq!(responder.next_receive_index(), 0);

    let fresh = initiator.send_data(b"new").unwrap();
    assert_eq!(responder.receive(&fresh.envelope).unwrap().content, b"new");
}

#[test]
fn invalid_refresh_finish_does_not_install_or_erase_parent() {
    let (mut initiator, mut responder) = pair();
    initiator.begin_refresh([1; 32]).unwrap();
    responder.begin_refresh([1; 32]).unwrap();
    let old_id = *responder.session_id();
    let pretranscript = [2; 64];
    let candidate_i = initiator
        .derive_refresh_candidate(RefreshRole::Initiator, &[3; 32], pretranscript, [4; 64])
        .unwrap();
    let candidate_r = responder
        .derive_refresh_candidate(RefreshRole::Responder, &[3; 32], pretranscript, [4; 64])
        .unwrap();
    let tag = candidate_r.response_confirmation();
    let (mut finish, _) = candidate_i
        .confirm_response(&tag)
        .unwrap()
        .seal_finish()
        .unwrap();
    finish[100] ^= 1;
    assert!(candidate_r
        .confirm_response(&tag)
        .unwrap()
        .open_finish(&finish)
        .is_err());
    assert_eq!(responder.session_id(), &old_id);
    assert_eq!(responder.phase(), SessionPhase::Refreshing);
    responder.abort_refresh().unwrap();
    assert_eq!(responder.phase(), SessionPhase::Established);
}

#[test]
fn lower_concurrent_refresh_id_wins() {
    let (mut initiator, _) = pair();
    assert_eq!(
        initiator.begin_refresh([9; 32]),
        Ok(RefreshIdDecision::Accepted)
    );
    assert_eq!(
        initiator.begin_refresh([8; 32]),
        Ok(RefreshIdDecision::ReplacedLocal)
    );
    assert_eq!(
        initiator.begin_refresh([10; 32]),
        Err(SessionError::RefreshConflict)
    );
}

#[test]
fn refresh_pauses_application_send_but_uses_parent_chain_for_control() {
    let (mut initiator, mut responder) = pair();
    initiator.begin_refresh([5; 32]).unwrap();
    assert_eq!(
        initiator.send_data(b"paused"),
        Err(SessionError::InvalidState)
    );
    let control = initiator
        .send_refresh_control(ContentKind::RefreshInit, b"signed refresh core")
        .unwrap();
    assert_eq!(control.index, 0);
    let before = responder.test_state_hash();
    assert_eq!(
        responder.receive(&control.envelope),
        Err(SessionError::AuthenticationFailed)
    );
    assert_eq!(responder.test_state_hash(), before);
    let received = responder
        .receive_validated(&control.envelope, |record| {
            if record.content_kind == ContentKind::RefreshInit {
                Ok(())
            } else {
                Err(SessionError::AuthenticationFailed)
            }
        })
        .unwrap();
    assert_eq!(received.content_kind, ContentKind::RefreshInit);
    assert_eq!(responder.next_receive_index(), 1);
}
