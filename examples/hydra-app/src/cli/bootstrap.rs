use crate::services;

pub(super) fn run_bootstrap(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("create") => {
            let password = args.get(1).ok_or_else(|| {
                "usage: hydra-app bootstrap create <identity-password> [ttl-seconds] [recipient-fingerprint-hex]".to_owned()
            })?;
            let ttl_seconds = args
                .get(2)
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|error| format!("ttl must be seconds: {error}"))
                })
                .transpose()?
                .unwrap_or(hydra_app_core::DEFAULT_INVITE_TTL_SECONDS);
            let recipient = args.get(3).map(String::as_str);
            let invite =
                services::create_bootstrap_invite(password.as_bytes(), ttl_seconds, recipient)?;
            println!("join code: {}", invite.to_join_code());
            println!("safety number: {}", invite.safety_number);
            println!("inviter fingerprint: {}", invite.identity_fingerprint_hex);
            Ok(())
        }
        Some("review") => {
            let join_code = args
                .get(1)
                .ok_or_else(|| "usage: hydra-app bootstrap review <join-code>".to_owned())?;
            let invite = services::review_bootstrap_join_code(join_code)?;
            println!("bootstrap invite review");
            println!("label: {}", invite.inviter_label);
            println!("fingerprint: {}", invite.identity_fingerprint_hex);
            println!("device: {}", invite.device_fingerprint_hex);
            println!("safety number: {}", invite.safety_number);
            println!("expires at ms: {}", invite.expires_at_ms);
            Ok(())
        }
        _ => Err("usage: hydra-app bootstrap <create|review> ...".to_owned()),
    }
}
