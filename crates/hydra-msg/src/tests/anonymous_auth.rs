use super::*;
use crate::limits::MAX_ANONYMOUS_AUTH_SPENT;
use std::fs;

fn fresh(path: &str) -> Hydra {
    let _ = fs::remove_dir_all(path);
    Hydra::open(path, "state-pw").unwrap()
}

#[test]
fn anonymous_auth_tokens_are_one_time_and_unlinkable_across_issues() {
    let mut hydra = fresh("target/hydra-msg-test-anonymous-auth-unlinkable");
    let policy = HydraAnonymousAuthPolicy::new("private-lobby-alpha", "join").with_expiry(1000);

    let token_a = hydra.issue_anonymous_auth_token(policy.clone()).unwrap();
    let token_b = hydra.issue_anonymous_auth_token(policy.clone()).unwrap();
    assert_ne!(token_a.as_bytes(), token_b.as_bytes());

    let nullifier_a = hydra.anonymous_auth_nullifier(&token_a).unwrap();
    let nullifier_b = hydra.anonymous_auth_nullifier(&token_b).unwrap();
    assert_ne!(nullifier_a, nullifier_b);

    let token_text = String::from_utf8(token_a.clone().into_bytes()).unwrap();
    assert!(token_text.contains("HYDRA-MSG-AUTH-TOKEN"));
    assert!(!token_text.contains("contact"));
    assert!(!token_text.contains("identity"));

    let grant = hydra
        .accept_anonymous_auth_token(token_a, "private-lobby-alpha", "join", 999)
        .unwrap();
    assert_eq!(grant.policy().scope(), "private-lobby-alpha");
    assert_eq!(grant.policy().action(), "join");
    assert_eq!(grant.nullifier(), nullifier_a);

    assert!(hydra
        .accept_anonymous_auth_token(token_b, "private-lobby-alpha", "join", 999)
        .is_ok());
}

#[test]
fn anonymous_auth_rejects_replay_wrong_scope_tampering_and_expiry() {
    let mut hydra = fresh("target/hydra-msg-test-anonymous-auth-rejects");
    let policy = HydraAnonymousAuthPolicy::new("mailbox-42", "send").with_expiry(10);
    let token = hydra.issue_anonymous_auth_token(policy).unwrap();

    assert!(hydra
        .accept_anonymous_auth_token(&token, "mailbox-42", "join", 5)
        .is_err());
    assert!(hydra
        .accept_anonymous_auth_token(&token, "mailbox-42", "send", 11)
        .is_err());

    let mut tampered = token.clone().into_bytes();
    let last = tampered.len() - 2;
    tampered[last] ^= 1;
    assert!(hydra
        .accept_anonymous_auth_token(tampered, "mailbox-42", "send", 5)
        .is_err());

    hydra
        .accept_anonymous_auth_token(&token, "mailbox-42", "send", 5)
        .unwrap();
    assert!(hydra
        .accept_anonymous_auth_token(&token, "mailbox-42", "send", 5)
        .is_err());
}

#[test]
fn anonymous_auth_spent_nullifiers_persist_and_revocation_blocks_use() {
    let path = "target/hydra-msg-test-anonymous-auth-persist";
    let mut hydra = fresh(path);
    let policy = HydraAnonymousAuthPolicy::new("relay-window", "post");
    let token = hydra.issue_anonymous_auth_token(policy).unwrap();
    let nullifier = hydra.anonymous_auth_nullifier(&token).unwrap();
    hydra
        .revoke_anonymous_auth_token(&token, "relay-window", "post")
        .unwrap();
    assert_eq!(hydra.anonymous_auth_spent, vec![nullifier]);
    drop(hydra);

    let mut reopened = Hydra::open(path, "state-pw").unwrap();
    assert!(reopened.anonymous_auth_spent.contains(&nullifier));
    assert!(reopened
        .accept_anonymous_auth_token(&token, "relay-window", "post", 0)
        .is_err());
}

#[test]
fn anonymous_auth_token_from_other_issuer_is_not_valid() {
    let mut issuer_a = fresh("target/hydra-msg-test-anonymous-auth-issuer-a");
    let mut issuer_b = fresh("target/hydra-msg-test-anonymous-auth-issuer-b");
    let token = issuer_a
        .issue_anonymous_auth_token(HydraAnonymousAuthPolicy::new("paid-access", "read"))
        .unwrap();

    assert!(issuer_b
        .accept_anonymous_auth_token(token, "paid-access", "read", 0)
        .is_err());
}

#[test]
fn anonymous_auth_nullifier_stability_reuse_cap_and_revocation_isolation() {
    let mut hydra = fresh("target/hydra-msg-test-anonymous-auth-expanded");
    let token_a = hydra
        .issue_anonymous_auth_token(HydraAnonymousAuthPolicy::new("scope-a", "join"))
        .unwrap();
    let token_b = hydra
        .issue_anonymous_auth_token(HydraAnonymousAuthPolicy::new("scope-a", "join"))
        .unwrap();

    assert_eq!(
        hydra.anonymous_auth_nullifier(&token_a).unwrap(),
        hydra.anonymous_auth_nullifier(&token_a).unwrap()
    );
    assert_ne!(
        hydra.anonymous_auth_nullifier(&token_a).unwrap(),
        hydra.anonymous_auth_nullifier(&token_b).unwrap()
    );

    hydra
        .revoke_anonymous_auth_token(&token_a, "scope-a", "join")
        .unwrap();
    assert!(hydra
        .accept_anonymous_auth_token(&token_a, "scope-a", "join", 0)
        .is_err());
    assert!(hydra
        .accept_anonymous_auth_token(&token_b, "scope-a", "join", 0)
        .is_ok());

    let mut capped = fresh("target/hydra-msg-test-anonymous-auth-cap");
    let capped_token = capped
        .issue_anonymous_auth_token(HydraAnonymousAuthPolicy::new("cap", "spend"))
        .unwrap();
    for index in 0..MAX_ANONYMOUS_AUTH_SPENT {
        let mut bytes = [0_u8; hydra_core::HASH_SIZE];
        bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let nullifier = HydraAnonymousAuthNullifier::from_bytes(bytes);
        capped.anonymous_auth_spent.push(nullifier);
        capped.anonymous_auth_spent_index.insert(nullifier);
    }
    let before = capped.anonymous_auth_spent.len();
    assert!(capped
        .accept_anonymous_auth_token(&capped_token, "cap", "spend", 0)
        .is_err());
    assert_eq!(capped.anonymous_auth_spent.len(), before);
}

#[test]
fn anonymous_auth_malformed_valid_looking_tokens_and_status_surfaces_do_not_leak_nullifiers() {
    let mut hydra = fresh("target/hydra-msg-test-anonymous-auth-malformed-expanded");
    let token = hydra
        .issue_anonymous_auth_token(
            HydraAnonymousAuthPolicy::new("mailbox", "post").with_expiry(50),
        )
        .unwrap();
    assert!(hydra
        .accept_anonymous_auth_token(&token, "wrong-mailbox", "post", 1)
        .is_err());
    assert!(hydra
        .accept_anonymous_auth_token(&token, "mailbox", "wrong-action", 1)
        .is_err());
    assert!(hydra
        .accept_anonymous_auth_token(&token, "mailbox", "post", 51)
        .is_err());

    let mailbox_hex = crate::codec::hex_encode(b"mailbox");
    let mailbox2_hex = crate::codec::hex_encode(b"mailbox2");
    let malformed = String::from_utf8(token.clone().into_bytes())
        .unwrap()
        .replace(
            &format!("scope\t{mailbox_hex}"),
            &format!("scope\t{mailbox2_hex}"),
        );
    assert!(hydra
        .accept_anonymous_auth_token(malformed.as_bytes(), "mailbox2", "post", 1)
        .is_err());

    let nullifier = hydra.anonymous_auth_nullifier(&token).unwrap();
    hydra
        .accept_anonymous_auth_token(&token, "mailbox", "post", 1)
        .unwrap();
    let normal_status = format!("{:?}", hydra.storage_status());
    assert!(!normal_status.contains(&nullifier.hex()));
    assert!(!normal_status.contains("anonymous_auth"));
}
