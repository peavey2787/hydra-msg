use crate::{config::AppConfig, services};

pub(super) fn run_config(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        None | Some("show") => {
            let config = AppConfig::load_or_default()?;
            println!("{config}");
            Ok(())
        }
        Some("set") => {
            let key = args
                .get(1)
                .ok_or_else(|| "usage: hydra-app config set <key> <value>".to_owned())?;
            let value = args
                .get(2)
                .ok_or_else(|| "usage: hydra-app config set <key> <value>".to_owned())?;
            services::set_config_value(key, value)?;
            println!("updated config key '{key}'");
            Ok(())
        }
        Some(other) => Err(format!("unknown config command '{other}'")),
    }
}
