use crate::{gui, text::hex_encode};
use hydra_app_core::{ContactId, HydraApp, HydraLobbyPolicy, HydraMessage, IdentityId, LobbyId};
use std::{
    env,
    error::Error,
    fmt, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

type CliResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct CliError(String);

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CliError {}

struct GlobalOptions {
    data_dir: PathBuf,
    state_password: String,
    args: Vec<String>,
}

pub fn run() -> CliResult<()> {
    let raw = env::args().skip(1).collect::<Vec<_>>();
    if raw.is_empty() || matches!(raw[0].as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    let options = parse_global_options(raw)?;
    dispatch(options)
}

fn parse_global_options(raw: Vec<String>) -> CliResult<GlobalOptions> {
    let mut data_dir = PathBuf::from("hydra-gui-data");
    let mut state_password = env::var("HYDRA_GUI_STATE_PASSWORD").ok();
    let mut args = Vec::new();
    let mut index = 0;
    while index < raw.len() {
        match raw[index].as_str() {
            "--data-dir" => {
                data_dir = PathBuf::from(required(&raw, index + 1, "--data-dir value")?);
                index += 2;
            }
            "--state-password" => {
                state_password =
                    Some(required(&raw, index + 1, "--state-password value")?.to_owned());
                index += 2;
            }
            _ => {
                args.extend_from_slice(&raw[index..]);
                break;
            }
        }
    }
    if args.is_empty() {
        return Err(Box::new(CliError("missing command".to_owned())));
    }
    let state_password = state_password.ok_or_else(|| {
        Box::new(CliError(
            "provide --state-password or HYDRA_GUI_STATE_PASSWORD".to_owned(),
        )) as Box<dyn Error>
    })?;
    Ok(GlobalOptions {
        data_dir,
        state_password,
        args,
    })
}

fn dispatch(options: GlobalOptions) -> CliResult<()> {
    let command = required(&options.args, 0, "command")?;
    if command == "gui" {
        let address = options
            .args
            .get(1)
            .map(String::as_str)
            .unwrap_or("127.0.0.1:8787")
            .parse::<SocketAddr>()?;
        return gui::serve(options.data_dir, options.state_password, address);
    }

    let mut app = HydraApp::open(&options.data_dir, &options.state_password)?;
    let args = &options.args[1..];
    match command {
        "identity" => identity(&mut app, args),
        "contacts" => contacts(&mut app, args),
        "handshake" => handshake(&mut app, args),
        "messages" => messages(&mut app, args),
        "lobbies" => lobbies(&mut app, args),
        "backup" => backup(&mut app, args),
        "storage" => storage(&app, args),
        _ => Err(Box::new(CliError(format!("unknown command: {command}")))),
    }
}

fn identity(app: &mut HydraApp, args: &[String]) -> CliResult<()> {
    match required(args, 0, "identity action")? {
        "generate" => {
            let label = required(args, 1, "label")?;
            let password = required(args, 2, "identity password")?;
            let id = app.generate_identity(label, password)?;
            println!("{}", id.hex());
        }
        "list" => {
            for identity in app.list_identities() {
                println!(
                    "{}\t{}\tunlocked={}",
                    identity.id().hex(),
                    identity.label(),
                    identity.unlocked()
                );
            }
        }
        "switch" => {
            let id = IdentityId::from_hex(required(args, 1, "identity id")?)?;
            app.switch_identity(id, required(args, 2, "identity password")?)?;
        }
        "unlock" => {
            let id = IdentityId::from_hex(required(args, 1, "identity id")?)?;
            app.unlock_identity(id, required(args, 2, "identity password")?)?;
        }
        "lock" => {
            let target = required(args, 1, "identity id or active")?;
            if target == "active" {
                app.lock_active_identity()?;
            } else {
                app.lock_identity(IdentityId::from_hex(target)?)?;
            }
        }
        "export" => {
            let id = IdentityId::from_hex(required(args, 1, "identity id")?)?;
            let bytes = app.export_identity(id, required(args, 2, "identity password")?)?;
            fs::write(required(args, 3, "output path")?, bytes)?;
        }
        "import" => {
            let bytes = fs::read(required(args, 1, "identity file")?)?;
            let id = app.import_identity(
                bytes,
                required(args, 2, "identity password")?,
                required(args, 3, "label")?,
            )?;
            println!("{}", id.hex());
        }
        "change-password" => {
            let id = IdentityId::from_hex(required(args, 1, "identity id")?)?;
            app.change_identity_password(
                id,
                required(args, 2, "old password")?,
                required(args, 3, "new password")?,
            )?;
        }
        "delete" => {
            let id = IdentityId::from_hex(required(args, 1, "identity id")?)?;
            app.delete_identity(id, required(args, 2, "identity password")?)?;
        }
        action => {
            return Err(Box::new(CliError(format!(
                "unknown identity action: {action}"
            ))))
        }
    }
    Ok(())
}

fn contacts(app: &mut HydraApp, args: &[String]) -> CliResult<()> {
    match required(args, 0, "contacts action")? {
        "my-card" => {
            let label = required(args, 1, "label or -")?;
            let output = required(args, 2, "output path")?;
            let bytes = if label == "-" {
                app.create_contact_card()?
            } else {
                app.create_labeled_contact_card(label)?
            };
            fs::write(output, bytes)?;
        }
        "preview" => {
            let contact = app.preview_contact_card(fs::read(required(args, 1, "card path")?)?)?;
            print_contact(&contact);
        }
        "add" => {
            let contact = app.add_contact(fs::read(required(args, 1, "card path")?)?)?;
            print_contact(&contact);
        }
        "verify" => {
            let id = ContactId::from_hex(required(args, 1, "contact id")?)?;
            app.verify_contact(id, required(args, 2, "safety code")?)?;
        }
        "export" => fs::write(required(args, 1, "output path")?, app.export_contacts()?)?,
        "import" => app.import_contacts(fs::read(required(args, 1, "contacts file")?)?)?,
        action => {
            return Err(Box::new(CliError(format!(
                "unknown contacts action: {action}"
            ))))
        }
    }
    Ok(())
}

fn handshake(app: &mut HydraApp, args: &[String]) -> CliResult<()> {
    match required(args, 0, "handshake action")? {
        "offer" => {
            let id = ContactId::from_hex(required(args, 1, "contact id")?)?;
            fs::write(required(args, 2, "offer path")?, app.handshake_offer(id)?)?;
        }
        "answer" => {
            let offer = fs::read(required(args, 1, "offer path")?)?;
            fs::write(
                required(args, 2, "answer path")?,
                app.handshake_answer(offer)?,
            )?;
        }
        "finish" => app.finish_handshake(fs::read(required(args, 1, "answer path")?)?)?,
        action => {
            return Err(Box::new(CliError(format!(
                "unknown handshake action: {action}"
            ))))
        }
    }
    Ok(())
}

fn messages(app: &mut HydraApp, args: &[String]) -> CliResult<()> {
    match required(args, 0, "messages action")? {
        "send" => {
            let id = ContactId::from_hex(required(args, 1, "contact id")?)?;
            let text = required(args, 2, "message text")?;
            let prefix = PathBuf::from(required(args, 3, "output prefix")?);
            write_packets(&prefix, app.send_message(id, HydraMessage::text(text))?)?;
        }
        "receive" => {
            let packet = fs::read(required(args, 1, "packet path")?)?;
            match app.receive_message(packet)? {
                Some(message) => println!("{}", message.text()?),
                None => println!("fragment accepted; message incomplete"),
            }
        }
        action => {
            return Err(Box::new(CliError(format!(
                "unknown messages action: {action}"
            ))))
        }
    }
    Ok(())
}

fn lobbies(app: &mut HydraApp, args: &[String]) -> CliResult<()> {
    match required(args, 0, "lobbies action")? {
        "create" => {
            let label = required(args, 1, "lobby label")?;
            let max_members = required(args, 2, "max members")?.parse::<usize>()?;
            let lobby = app.create_lobby(HydraLobbyPolicy::new(label, max_members))?;
            println!("{}", lobby.id().hex());
        }
        "add-member" => {
            let lobby = LobbyId::from_hex(required(args, 1, "lobby id")?)?;
            let contact = ContactId::from_hex(required(args, 2, "contact id")?)?;
            app.add_lobby_member(lobby, contact)?;
        }
        "invite" => {
            let lobby = LobbyId::from_hex(required(args, 1, "lobby id")?)?;
            fs::write(
                required(args, 2, "invite path")?,
                app.create_lobby_invite(lobby)?,
            )?;
        }
        "join" => {
            let lobby = app.join_lobby(fs::read(required(args, 1, "invite path")?)?)?;
            println!("{}", lobby.id().hex());
        }
        "send" => {
            let lobby = LobbyId::from_hex(required(args, 1, "lobby id")?)?;
            let text = required(args, 2, "message text")?;
            let output_dir = PathBuf::from(required(args, 3, "output directory")?);
            fs::create_dir_all(&output_dir)?;
            for (index, packet) in app
                .send_lobby_message(lobby, HydraMessage::text(text))?
                .into_iter()
                .enumerate()
            {
                let name = format!(
                    "{}-{}-{index:04}.hydra",
                    packet.recipient.hex(),
                    hex_encode(&packet.routing_hint.bytes())
                );
                fs::write(output_dir.join(name), packet.bytes)?;
            }
        }
        "receive" => {
            let packet = fs::read(required(args, 1, "packet path")?)?;
            match app.receive_lobby_message(packet)? {
                Some(message) => println!("{}", message.text()?),
                None => println!("fragment accepted; message incomplete"),
            }
        }
        "leave" => {
            app.leave_lobby(LobbyId::from_hex(required(args, 1, "lobby id")?)?)?;
        }
        action => {
            return Err(Box::new(CliError(format!(
                "unknown lobbies action: {action}"
            ))))
        }
    }
    Ok(())
}

fn backup(app: &mut HydraApp, args: &[String]) -> CliResult<()> {
    match required(args, 0, "backup action")? {
        "export" => fs::write(
            required(args, 2, "output path")?,
            app.export_backup(required(args, 1, "backup password")?)?,
        )?,
        "verify" => app.verify_backup(
            fs::read(required(args, 1, "backup path")?)?,
            required(args, 2, "backup password")?,
        )?,
        "import" => app.import_backup(
            fs::read(required(args, 1, "backup path")?)?,
            required(args, 2, "backup password")?,
        )?,
        "change-state-password" => app.change_state_password(
            required(args, 1, "old state password")?,
            required(args, 2, "new state password")?,
        )?,
        "status" => print_storage_status(app),
        action => {
            return Err(Box::new(CliError(format!(
                "unknown backup action: {action}"
            ))))
        }
    }
    Ok(())
}

fn storage(app: &HydraApp, args: &[String]) -> CliResult<()> {
    match required(args, 0, "storage action")? {
        "status" => print_storage_status(app),
        "debug-status" => {
            let status = app.storage_debug_status();
            println!("data_dir={}", status.data_dir.display());
            println!("encrypted_state={}", status.encrypted_state);
            println!("identity_count={}", status.identity_count);
            println!("contact_count={}", status.contact_count);
            println!("session_count={}", status.session_count);
            println!("message_count={}", status.message_count);
            println!("lobby_count={}", status.lobby_count);
            println!("state_generation={}", status.state_generation);
        }
        action => {
            return Err(Box::new(CliError(format!(
                "unknown storage action: {action}"
            ))))
        }
    }
    Ok(())
}

fn print_storage_status(app: &HydraApp) {
    let status = app.storage_status();
    println!("data_dir={}", status.data_dir.display());
    println!("encrypted_state={}", status.encrypted_state);
}

fn print_contact(contact: &hydra_app_core::HydraContact) {
    println!("id={}", contact.id().hex());
    println!("label={}", contact.label());
    println!("verified={}", contact.verified());
    println!("blocked={}", contact.blocked());
    println!("safety_code={}", contact.safety_code());
}

fn write_packets(prefix: &Path, packets: Vec<Vec<u8>>) -> CliResult<()> {
    let parent = prefix.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let stem = prefix
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| CliError("output prefix must have a valid file name".to_owned()))?;
    for (index, packet) in packets.into_iter().enumerate() {
        fs::write(parent.join(format!("{stem}-{index:04}.hydra")), packet)?;
    }
    Ok(())
}

fn required<'a>(args: &'a [String], index: usize, name: &str) -> CliResult<&'a str> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| Box::new(CliError(format!("missing {name}"))) as Box<dyn Error>)
}

fn print_help() {
    println!(
        r#"HYDRA production reference app

Global options:
  --data-dir <path>
  --state-password <password>  (or HYDRA_GUI_STATE_PASSWORD)

Commands:
  identity generate <label> <password>
  identity list
  identity switch <id> <password>
  identity unlock <id> <password>
  identity lock <id|active>
  identity export <id> <password> <output>
  identity import <input> <password> <label>
  identity change-password <id> <old> <new>
  identity delete <id> <password>

  contacts my-card <label|-> <output>
  contacts preview <card>
  contacts add <card>
  contacts verify <contact-id> <safety-code>
  contacts export <output>
  contacts import <input>

  handshake offer <contact-id> <output>
  handshake answer <offer> <output>
  handshake finish <answer>

  messages send <contact-id> <text> <output-prefix>
  messages receive <packet>

  lobbies create <label> <max-members>
  lobbies add-member <lobby-id> <contact-id>
  lobbies invite <lobby-id> <output>
  lobbies join <invite>
  lobbies send <lobby-id> <text> <output-directory>
  lobbies receive <packet>
  lobbies leave <lobby-id>

  backup export <password> <output>
  backup verify <input> <password>
  backup import <input> <password>
  backup change-state-password <old> <new>
  backup status

  storage status
  storage debug-status
  gui [127.0.0.1:8787]

All handshake, message, and lobby files are opaque HYDRA SDK bytes. The app does
not parse or recreate protocol packets."#
    );
}
