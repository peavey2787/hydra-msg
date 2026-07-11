#![forbid(unsafe_code)]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

use hydra_msg::{
    ContactId, Hydra, HydraAttachment, HydraBenchmarkReport, HydraMessage, HydraMsgError,
    HydraResult, IdentityId,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run() -> HydraResult<()> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }

    let command = args.remove(0);
    match command.as_str() {
        "generate-id" => generate_id(&args),
        "contact-card" => contact_card(&args),
        "handshake-demo" => handshake_demo(&args),
        "send-demo" => send_demo(&args),
        "attachment-demo" => attachment_demo(&args),
        "bench" => bench(&args),
        "doctor" => doctor(&args),
        _ => {
            print_help();
            Err(HydraMsgError::InvalidInput("unknown hydra-msg-cli command"))
        }
    }
}

fn print_help() {
    println!(
        r#"HYDRA-MSG developer CLI

Usage:
  hydra-msg-cli generate-id <data-dir> <state-password> <identity-password>
  hydra-msg-cli contact-card <data-dir> <state-password> <identity-id-hex> <identity-password>
  hydra-msg-cli handshake-demo [data-dir]
  hydra-msg-cli send-demo [data-dir] [message]
  hydra-msg-cli attachment-demo [data-dir]
  hydra-msg-cli bench [data-dir] [state-password]
  hydra-msg-cli doctor [data-dir] [state-password]

Examples:
  cargo run -p hydra-msg-cli -- generate-id ./hydra-msg-data state-password identity-password
  cargo run -p hydra-msg-cli -- contact-card ./hydra-msg-data state-password <id-hex> identity-password
  cargo run -p hydra-msg-cli -- handshake-demo ./hydra-msg-cli-demo
  cargo run -p hydra-msg-cli -- send-demo ./hydra-msg-cli-demo "hello"
  cargo run -p hydra-msg-cli -- attachment-demo ./hydra-msg-cli-demo
  cargo run -p hydra-msg-cli -- bench ./hydra-msg-data state-password
  cargo run -p hydra-msg-cli -- doctor ./hydra-msg-data state-password

This CLI is only a developer tool over the simple hydra-msg facade.
It is not protocol authority and it does not add a public advanced API.
"#
    );
}

fn generate_id(args: &[String]) -> HydraResult<()> {
    let data_dir = required_arg(args, 0, "data-dir")?;
    let state_password = required_arg(args, 1, "state-password")?;
    let identity_password = required_arg(args, 2, "identity-password")?;
    let mut hydra = Hydra::open(data_dir, state_password)?;
    let id = hydra.generate_id(identity_password)?;
    hydra.set_active_id(id, identity_password)?;
    println!("id={}", id.hex());
    println!("data_dir={}", hydra.data_dir().display());
    Ok(())
}

fn contact_card(args: &[String]) -> HydraResult<()> {
    let data_dir = required_arg(args, 0, "data-dir")?;
    let state_password = required_arg(args, 1, "state-password")?;
    let identity_hex = required_arg(args, 2, "identity-id-hex")?;
    let identity_password = required_arg(args, 3, "identity-password")?;
    let id = IdentityId::from_hex(identity_hex)?;
    let mut hydra = Hydra::open(data_dir, state_password)?;
    hydra.set_active_id(id, identity_password)?;
    let card = hydra.create_contact_card()?;
    println!("{}", String::from_utf8_lossy(&card));
    Ok(())
}

fn handshake_demo(args: &[String]) -> HydraResult<()> {
    let base = optional_dir(args, "hydra-msg-cli-demo");
    let (alice, bob, bob_id) = setup_two_party_demo(&base)?;
    println!("alice_data_dir={}", alice.data_dir().display());
    println!("bob_data_dir={}", bob.data_dir().display());
    println!("bob_contact_id={}", bob_id.hex());
    println!("alice_session_status={:?}", alice.session_status(bob_id)?);
    Ok(())
}

fn send_demo(args: &[String]) -> HydraResult<()> {
    let base = optional_dir(args, "hydra-msg-cli-demo");
    let message = args
        .get(1)
        .map_or("hello from hydra-msg-cli", String::as_str);
    let (mut alice, mut bob, bob_id) = setup_two_party_demo(&base)?;
    let packets = alice.send(bob_id, HydraMessage::text(message))?;
    let mut received = None;
    for packet in packets {
        received = bob.receive(packet)?.or(received);
    }
    let received = received.ok_or(HydraMsgError::InvalidEncoding("message did not complete"))?;
    println!("sent={message}");
    println!("received={}", received.text()?);
    println!("attachment_count={}", received.attachments().len());
    Ok(())
}

fn attachment_demo(args: &[String]) -> HydraResult<()> {
    let base = optional_dir(args, "hydra-msg-cli-demo");
    let (mut alice, mut bob, bob_id) = setup_two_party_demo(&base)?;
    let raw_attachment = HydraAttachment::from_bytes(b"anonymous bytes".to_vec())?
        .with_filename("from-bytes.bin")?;
    let message = HydraMessage::text("message with attachments")
        .attach_bytes("named-bytes.txt", b"named bytes".to_vec())?;
    let mut message = message;
    message.attachments.push(raw_attachment);
    let packets = alice.send(bob_id, message)?;
    let mut received = None;
    for packet in packets {
        received = bob.receive(packet)?.or(received);
    }
    let received = received.ok_or(HydraMsgError::InvalidEncoding("message did not complete"))?;
    println!("text={}", received.text()?);
    for attachment in received.attachments() {
        println!(
            "attachment filename={} bytes={} source={:?}",
            attachment.filename(),
            attachment.bytes().len(),
            attachment.source()
        );
    }
    Ok(())
}

fn bench(args: &[String]) -> HydraResult<()> {
    let data_dir = args.first().map_or("hydra-msg-data", String::as_str);
    let state_password = args
        .get(1)
        .map_or("developer-state-password", String::as_str);
    let hydra = Hydra::open(data_dir, state_password)?;
    let report = hydra.benchmark()?;
    print_benchmark(&report);
    Ok(())
}

fn doctor(args: &[String]) -> HydraResult<()> {
    let data_dir = args.first().map_or("hydra-msg-data", String::as_str);
    let state_password = args
        .get(1)
        .map_or("developer-state-password", String::as_str);
    let hydra = Hydra::open(data_dir, state_password)?;
    let status = hydra.storage_debug_status();
    println!("data_dir={}", status.data_dir.display());
    println!("identities={}", status.identity_count);
    println!("contacts={}", status.contact_count);
    println!("sessions={}", status.session_count);
    println!("messages={}", status.message_count);
    println!("lobbies={}", status.lobby_count);
    Ok(())
}

fn setup_two_party_demo(base: &Path) -> HydraResult<(Hydra, Hydra, ContactId)> {
    let _ = fs::remove_dir_all(base);
    fs::create_dir_all(base)?;

    let alice_dir = base.join("alice");
    let bob_dir = base.join("bob");
    let mut alice = Hydra::open(&alice_dir, "alice-state-password")?;
    let mut bob = Hydra::open(&bob_dir, "bob-state-password")?;

    let alice_id = alice.generate_id("alice-password")?;
    alice.set_active_id(alice_id, "alice-password")?;
    let bob_id = bob.generate_id("bob-password")?;
    bob.set_active_id(bob_id, "bob-password")?;

    let alice_card = alice.create_contact_card()?;
    let bob_card = bob.create_contact_card()?;
    let alice_contact = bob.add_contact(alice_card)?;
    let bob_contact = alice.add_contact(bob_card)?;
    bob.verify_contact(alice_contact.id(), alice_contact.safety_code())?;
    alice.verify_contact(bob_contact.id(), bob_contact.safety_code())?;

    let offer = alice.init_handshake(bob_contact.id())?;
    let answer = bob.reply_handshake(offer)?;
    alice.finish_handshake(answer)?;

    Ok((alice, bob, bob_contact.id()))
}

fn optional_dir(args: &[String], default_dir: &str) -> PathBuf {
    PathBuf::from(args.first().map_or(default_dir, String::as_str))
}

fn required_arg<'a>(args: &'a [String], index: usize, name: &'static str) -> HydraResult<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or(HydraMsgError::InvalidInput(name))
}

fn print_benchmark(report: &HydraBenchmarkReport) {
    println!("suite={}", report.suite);
    println!("iterations={}", report.iterations);
    println!("handshake_avg_ms={:.4}", report.handshake_avg_ms);
    println!("send_receive_avg_ms={:.4}", report.send_receive_avg_ms);
}
