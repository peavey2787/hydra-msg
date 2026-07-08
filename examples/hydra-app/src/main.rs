mod cli;
mod config;
mod contacts;
mod gui;
mod secrets;
mod services;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
