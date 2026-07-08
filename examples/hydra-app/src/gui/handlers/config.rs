use crate::config::{is_advanced_config_key, AppConfig};

use super::support::optional_bool;
use crate::gui::{
    encoding::json_escape,
    forms::{parse_form, required_form_value},
    state::GuiAppState,
};

pub(crate) fn api_config_set(body: &[u8], app_state: &GuiAppState) -> Result<String, String> {
    let form = parse_form(body)?;
    let key = required_form_value(&form, "key")?;
    let value = required_form_value(&form, "value")?;
    if is_advanced_config_key(key) {
        let advanced_confirm = optional_bool(form.get("advanced_confirm").map(String::as_str))?;
        if !advanced_confirm {
            return Err("advanced settings require explicit confirmation".to_owned());
        }
    }
    let mut config = AppConfig::load_or_default()?;
    config.set(key, value)?;
    if key == "data_dir" {
        app_state.lock_identity_session()?.lock_all();
    }
    config.save()?;
    Ok(format!(
        "{{\"ok\":true,\"message\":\"updated {}\"}}",
        json_escape(key),
    ))
}
