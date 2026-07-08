use std::env;

use crate::{gui, services};

mod bootstrap;
mod chats;
mod config;
mod contacts;
mod identity;
mod recovery;

pub fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        None => {
            print_help();
            Ok(())
        }
        Some("config") => config::run_config(&args[1..]),
        Some("identity") => identity::run_identity(&args[1..]),
        Some("contacts") => contacts::run_contacts(&args[1..]),
        Some("bootstrap") => bootstrap::run_bootstrap(&args[1..]),
        Some("chats") => chats::run_chats(&args[1..]),
        Some("backup") => recovery::run_backup(&args[1..]),
        Some("recovery") => recovery::run_recovery(&args[1..]),
        Some("gui") => gui::run(&args[1..]),
        Some("help" | "--help" | "-h") => {
            print_help();
            Ok(())
        }
        Some(other) => Err(format!("unknown command '{other}'. Run `hydra-app help`.")),
    }
}

fn print_help() {
    println!("{}", services::help_text());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_text_is_available() {
        print_help();
        assert!(services::help_text().contains("hydra-app identity generate"));
        assert!(services::help_text().contains("hydra-app gui"));
    }
}
