#![no_main]

mod common;

use hydra_msg::HydraAnonymousAuthPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let base = common::temp_case_dir("anonymous-auth", data);
    let Some(mut hydra) = common::fresh(base) else {
        return;
    };
    let _ = hydra.anonymous_auth_nullifier(data);
    let _ = hydra.accept_anonymous_auth_token(data, "scope", "action", 0);
    let _ = hydra.revoke_anonymous_auth_token(data, "scope", "action");

    let policy = HydraAnonymousAuthPolicy::new("scope", "action").with_expiry(1);
    if let Ok(token) = hydra.issue_anonymous_auth_token(policy) {
        let mut mutated = token.into_bytes();
        if !mutated.is_empty() && !data.is_empty() {
            let index = data.len() % mutated.len();
            mutated[index] ^= data[0];
        }
        let _ = hydra.anonymous_auth_nullifier(&mutated);
        let _ = hydra.accept_anonymous_auth_token(&mutated, "scope", "action", 0);
        let _ = hydra.revoke_anonymous_auth_token(&mutated, "scope", "action");
    }
});
