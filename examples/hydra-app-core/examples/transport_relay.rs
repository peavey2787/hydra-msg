use hydra_app_core::{InMemoryTransport, MailboxId, TransportApi, TransportUploadRequest};
use hydra_core::LITE_ENVELOPE_SIZE;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sender = MailboxId([1; 32]);
    let recipient = MailboxId([2; 32]);
    let envelope = vec![0xa5; LITE_ENVELOPE_SIZE];
    let mut relay = InMemoryTransport::new();

    let receipt = relay.upload_envelope(TransportUploadRequest::new(
        sender,
        recipient,
        1_000,
        Some(60_000),
        envelope,
    ))?;
    let queued = relay.download_envelopes(recipient, 2_000, 8)?;
    println!(
        "queued={} message_id_prefix={:02x?}",
        queued.len(),
        &receipt.message_id.0[..4]
    );
    Ok(())
}
