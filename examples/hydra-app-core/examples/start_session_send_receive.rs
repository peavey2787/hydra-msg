use hydra_app_core::{AppIdentity, AppSession, AppSessionRole, SessionHandshakeExport};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = AppIdentity::generate()?;
    let bob = AppIdentity::generate()?;
    let transcript = [0x33; 64];
    let handshake_secret = [0x44; 32];

    let mut alice_session = AppSession::start(
        AppSessionRole::Initiator,
        &alice,
        bob.public_identity(),
        SessionHandshakeExport::from_test_bytes(handshake_secret, transcript),
    )?;
    let mut bob_session = AppSession::start(
        AppSessionRole::Responder,
        &bob,
        alice.public_identity(),
        SessionHandshakeExport::from_test_bytes(handshake_secret, transcript),
    )?;

    let wire = alice_session.send(b"hello 1:1")?;
    let received = bob_session.receive(wire.as_envelope())?;
    println!("received: {}", String::from_utf8_lossy(received.content()));
    Ok(())
}
