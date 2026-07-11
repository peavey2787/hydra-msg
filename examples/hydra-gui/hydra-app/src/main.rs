#![forbid(unsafe_code)]
#![deny(dead_code, deprecated, unused)]

mod cli;
mod gui;
mod text;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
