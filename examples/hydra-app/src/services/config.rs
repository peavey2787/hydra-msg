use crate::config::AppConfig;

pub fn set_config_value(key: &str, value: &str) -> Result<AppConfig, String> {
    let mut config = AppConfig::load_or_default()?;
    config.set(key, value)?;
    config.save()?;
    Ok(config)
}
