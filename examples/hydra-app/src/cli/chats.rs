use crate::services;

pub(super) fn run_chats(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None | Some("list") => {
            let snapshot = services::chat_snapshot()?;
            println!("[Chats] {}", snapshot.status);
            if snapshot.conversations.is_empty() {
                println!("no chats yet");
                println!("start one with: hydra-app chats direct <trusted-contact-alias>");
                return Ok(());
            }
            for conversation in snapshot.conversations {
                println!(
                    "{}  kind={}  messages={}  last={}",
                    conversation.id_hex,
                    conversation.kind_label,
                    conversation.message_count,
                    conversation.last_message_preview,
                );
            }
            Ok(())
        }
        Some("direct") => {
            let alias = args.get(1).ok_or_else(|| {
                "usage: hydra-app chats direct <trusted-contact-alias>".to_owned()
            })?;
            let conversation_id = services::create_direct_chat(alias)?;
            println!("direct chat ready: {conversation_id}");
            Ok(())
        }
        Some("group") => {
            let kind = args.get(1).ok_or_else(|| {
                "usage: hydra-app chats group <lite|interactive|broadcast>".to_owned()
            })?;
            let conversation_id = services::create_group_chat_from_label(kind)?;
            println!("group chat shell ready: {conversation_id}");
            Ok(())
        }
        Some("send") => {
            let conversation_id = args.get(1).ok_or_else(|| {
                "usage: hydra-app chats send <conversation-id-hex> <identity-password> <message>".to_owned()
            })?;
            let password = args.get(2).ok_or_else(|| {
                "usage: hydra-app chats send <conversation-id-hex> <identity-password> <message>".to_owned()
            })?;
            let message = args.get(3).ok_or_else(|| {
                "usage: hydra-app chats send <conversation-id-hex> <identity-password> <message>".to_owned()
            })?;
            let material = services::active_identity_public_material(password.as_bytes())?;
            let index = services::send_chat_message(
                conversation_id,
                &material.identity_fingerprint_hex,
                message,
            )?;
            println!("message stored in encrypted local chat database: index {index}");
            Ok(())
        }
        Some("receive-review") => {
            let conversation_id = args.get(1).ok_or_else(|| {
                "usage: hydra-app chats receive-review <conversation-id-hex> <message> [sender-id-hex]".to_owned()
            })?;
            let message = args.get(2).ok_or_else(|| {
                "usage: hydra-app chats receive-review <conversation-id-hex> <message> [sender-id-hex]".to_owned()
            })?;
            let sender_id = args.get(3).map(String::as_str);
            let index =
                services::receive_reviewed_chat_message(conversation_id, sender_id, message)?;
            println!("reviewed inbound message stored locally: index {index}");
            Ok(())
        }
        Some(other) => Err(format!("unknown chats command '{other}'")),
    }
}
