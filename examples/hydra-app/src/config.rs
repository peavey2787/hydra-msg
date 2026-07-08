use std::{
    env, fmt, fs,
    path::{Path, PathBuf},
};

const DEFAULT_DATA_DIR: &str = "./hydra-msg-data";
const CONFIG_FILE: &str = "app-config.txt";
const MIN_REKEY_MESSAGES: u64 = 1;
const MAX_REKEY_MESSAGES: u64 = 1_000_000;
const MAX_ROTATE_IDENTITY_AFTER_REKEY_COUNT: u64 = 1_000_000;
const MIN_GROUP_MEMBERS: u16 = 2;
const MAX_GROUP_MEMBERS: u16 = 512;
const MAX_ACCESS_LIST_ENTRIES: usize = 256;
const MAX_ACCESS_LIST_ENTRY_LEN: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConfig {
    pub data_dir: PathBuf,
    pub rekey: RekeyConfig,
    pub chat: ChatPolicyConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RekeyConfig {
    pub direct_every_messages: u64,
    pub group_lite_every_messages: u64,
    pub group_interactive_every_messages: u64,
    pub group_broadcast_every_messages: u64,
    pub group_on_membership_change: bool,
    pub rotate_identity_after_rekey_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncomingMessagePolicy {
    ContactsOnly,
    AllowUnknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatListMode {
    None,
    Whitelist,
    Blacklist,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatPolicyConfig {
    pub incoming_message_policy: IncomingMessagePolicy,
    pub default_group_max_members: u16,
    pub default_chat_list_mode: ChatListMode,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
}

impl IncomingMessagePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContactsOnly => "contacts-only",
            Self::AllowUnknown => "allow-unknown",
        }
    }

    pub fn parse(key: &str, value: &str) -> Result<Self, String> {
        match value.trim() {
            "contacts-only" | "contacts" | "trusted-only" => Ok(Self::ContactsOnly),
            "allow-unknown" | "unknown" | "anyone" => Ok(Self::AllowUnknown),
            _ => Err(format!("{key} must be contacts-only or allow-unknown")),
        }
    }
}

impl ChatListMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Whitelist => "whitelist",
            Self::Blacklist => "blacklist",
        }
    }

    pub fn parse(key: &str, value: &str) -> Result<Self, String> {
        match value.trim() {
            "none" | "off" => Ok(Self::None),
            "whitelist" | "allow-list" => Ok(Self::Whitelist),
            "blacklist" | "block-list" => Ok(Self::Blacklist),
            _ => Err(format!("{key} must be none, whitelist, or blacklist")),
        }
    }
}

impl Default for ChatPolicyConfig {
    fn default() -> Self {
        Self {
            incoming_message_policy: IncomingMessagePolicy::ContactsOnly,
            default_group_max_members: 32,
            default_chat_list_mode: ChatListMode::None,
            whitelist: Vec::new(),
            blacklist: Vec::new(),
        }
    }
}

impl Default for RekeyConfig {
    fn default() -> Self {
        Self {
            direct_every_messages: 256,
            group_lite_every_messages: 128,
            group_interactive_every_messages: 64,
            group_broadcast_every_messages: 32,
            group_on_membership_change: true,
            rotate_identity_after_rekey_count: 0,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            rekey: RekeyConfig::default(),
            chat: ChatPolicyConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load_or_default() -> Result<Self, String> {
        let mut config = Self::default();
        let path = config_path(&config.data_dir);
        if !path.exists() {
            return Ok(config);
        }
        let text = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read config {}: {error}", path.display()))?;
        for (line_index, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("invalid config line {}", line_index + 1))?;
            config.set(key.trim(), value.trim())?;
        }
        Ok(config)
    }

    pub fn save(&self) -> Result<(), String> {
        fs::create_dir_all(&self.data_dir).map_err(|error| {
            format!(
                "cannot create data dir {}: {error}",
                self.data_dir.display()
            )
        })?;
        fs::write(config_path(&self.data_dir), self.to_file_text())
            .map_err(|error| format!("cannot save config: {error}"))
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "data_dir" => self.data_dir = parse_data_dir(key, value)?,
            "direct_rekey_every_messages" => {
                self.rekey.direct_every_messages = parse_rekey_messages(key, value)?;
            }
            "group_lite_rekey_every_messages" => {
                self.rekey.group_lite_every_messages = parse_rekey_messages(key, value)?;
            }
            "group_interactive_rekey_every_messages" => {
                self.rekey.group_interactive_every_messages = parse_rekey_messages(key, value)?;
            }
            "group_broadcast_rekey_every_messages" => {
                self.rekey.group_broadcast_every_messages = parse_rekey_messages(key, value)?;
            }
            "group_rekey_on_membership_change" => {
                self.rekey.group_on_membership_change = parse_bool(key, value)?;
            }
            "rotate_identity_after_rekey_count" => {
                self.rekey.rotate_identity_after_rekey_count =
                    parse_rotate_identity_after_rekey_count(key, value)?;
            }
            "incoming_message_policy" => {
                self.chat.incoming_message_policy = IncomingMessagePolicy::parse(key, value)?;
            }
            "default_group_max_members" => {
                self.chat.default_group_max_members = parse_group_members(key, value)?;
            }
            "default_chat_list_mode" => {
                self.chat.default_chat_list_mode = ChatListMode::parse(key, value)?;
            }
            "chat_whitelist" => {
                self.chat.whitelist = parse_access_list(key, value)?;
            }
            "chat_blacklist" => {
                self.chat.blacklist = parse_access_list(key, value)?;
            }
            _ => return Err(format!("unknown config key '{key}'")),
        }
        Ok(())
    }

    pub fn to_file_text(&self) -> String {
        format!(
            concat!(
                "# HYDRA-MSG local app config\n",
                "data_dir={}\n",
                "direct_rekey_every_messages={}\n",
                "group_lite_rekey_every_messages={}\n",
                "group_interactive_rekey_every_messages={}\n",
                "group_broadcast_rekey_every_messages={}\n",
                "group_rekey_on_membership_change={}\n",
                "rotate_identity_after_rekey_count={}\n",
                "incoming_message_policy={}\n",
                "default_group_max_members={}\n",
                "default_chat_list_mode={}\n",
                "chat_whitelist={}\n",
                "chat_blacklist={}\n"
            ),
            self.data_dir.display(),
            self.rekey.direct_every_messages,
            self.rekey.group_lite_every_messages,
            self.rekey.group_interactive_every_messages,
            self.rekey.group_broadcast_every_messages,
            self.rekey.group_on_membership_change,
            self.rekey.rotate_identity_after_rekey_count,
            self.chat.incoming_message_policy.as_str(),
            self.chat.default_group_max_members,
            self.chat.default_chat_list_mode.as_str(),
            encode_access_list(&self.chat.whitelist),
            encode_access_list(&self.chat.blacklist),
        )
    }
}

impl fmt::Display for AppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            concat!(
                "[Config]\n",
                "data_dir: {}\n",
                "\n[Rekey policy]\n",
                "1:1 rekey every messages: {}\n",
                "Lite group rekey every messages: {}\n",
                "Interactive group rekey every messages: {}\n",
                "Broadcast group rekey every messages: {}\n",
                "Group membership-change rekey: {}\n",
                "Identity rotation after rekey count: {}\n",
                "\n[Chat policy]\n",
                "Incoming messages: {}\n",
                "Default group max members: {}\n",
                "Default chat access list: {}\n",
                "Whitelist entries: {}\n",
                "Blacklist entries: {}\n"
            ),
            self.data_dir.display(),
            self.rekey.direct_every_messages,
            self.rekey.group_lite_every_messages,
            self.rekey.group_interactive_every_messages,
            self.rekey.group_broadcast_every_messages,
            self.rekey.group_on_membership_change,
            self.rekey.rotate_identity_after_rekey_count,
            self.chat.incoming_message_policy.as_str(),
            self.chat.default_group_max_members,
            self.chat.default_chat_list_mode.as_str(),
            encode_access_list(&self.chat.whitelist),
            encode_access_list(&self.chat.blacklist),
        )
    }
}

#[must_use]
pub fn is_advanced_config_key(key: &str) -> bool {
    matches!(
        key,
        "data_dir"
            | "direct_rekey_every_messages"
            | "group_lite_rekey_every_messages"
            | "group_interactive_rekey_every_messages"
            | "group_broadcast_rekey_every_messages"
            | "group_rekey_on_membership_change"
            | "rotate_identity_after_rekey_count"
            | "incoming_message_policy"
            | "default_group_max_members"
            | "default_chat_list_mode"
            | "chat_whitelist"
            | "chat_blacklist"
    )
}

pub fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONFIG_FILE)
}

fn default_data_dir() -> PathBuf {
    env::var_os("HYDRA_APP_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR))
}

fn parse_rekey_messages(key: &str, value: &str) -> Result<u64, String> {
    let parsed = parse_u64(key, value)?;
    if !(MIN_REKEY_MESSAGES..=MAX_REKEY_MESSAGES).contains(&parsed) {
        Err(format!(
            "{key} must be between {MIN_REKEY_MESSAGES} and {MAX_REKEY_MESSAGES} messages"
        ))
    } else {
        Ok(parsed)
    }
}

fn parse_rotate_identity_after_rekey_count(key: &str, value: &str) -> Result<u64, String> {
    let parsed = parse_u64(key, value)?;
    if parsed > MAX_ROTATE_IDENTITY_AFTER_REKEY_COUNT {
        Err(format!(
            "{key} must be 0 or at most {MAX_ROTATE_IDENTITY_AFTER_REKEY_COUNT}"
        ))
    } else {
        Ok(parsed)
    }
}

fn parse_group_members(key: &str, value: &str) -> Result<u16, String> {
    let parsed = parse_u64(key, value)?;
    if parsed < u64::from(MIN_GROUP_MEMBERS) || parsed > u64::from(MAX_GROUP_MEMBERS) {
        Err(format!(
            "{key} must be between {MIN_GROUP_MEMBERS} and {MAX_GROUP_MEMBERS} members"
        ))
    } else {
        Ok(parsed as u16)
    }
}

fn parse_access_list(key: &str, value: &str) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    for raw in value.split(['\n', '\r', ';', ',']) {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        validate_access_list_entry(key, entry)?;
        if !entries.iter().any(|existing| existing == entry) {
            entries.push(entry.to_owned());
        }
    }
    if entries.len() > MAX_ACCESS_LIST_ENTRIES {
        return Err(format!(
            "{key} may contain at most {MAX_ACCESS_LIST_ENTRIES} entries"
        ));
    }
    entries.sort();
    Ok(entries)
}

fn validate_access_list_entry(key: &str, entry: &str) -> Result<(), String> {
    if entry.len() > MAX_ACCESS_LIST_ENTRY_LEN {
        return Err(format!(
            "{key} entries must be at most {MAX_ACCESS_LIST_ENTRY_LEN} characters"
        ));
    }
    if entry.chars().any(char::is_control) || entry.contains('|') {
        return Err(format!(
            "{key} entries must not contain control characters or pipe separators"
        ));
    }
    Ok(())
}

fn encode_access_list(entries: &[String]) -> String {
    entries.join(";")
}

fn parse_data_dir(key: &str, value: &str) -> Result<PathBuf, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{key} must not be empty"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(format!("{key} must not contain control characters"));
    }
    Ok(PathBuf::from(trimmed))
}

fn parse_u64(key: &str, value: &str) -> Result<u64, String> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("{key} must be a u64: {error}"))
}

fn parse_bool(key: &str, value: &str) -> Result<bool, String> {
    match value.trim() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(format!("{key} must be true or false")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_set_updates_rekey_policy() {
        let mut config = AppConfig::default();
        config.set("direct_rekey_every_messages", "512").unwrap();
        config
            .set("group_rekey_on_membership_change", "false")
            .unwrap();
        assert_eq!(config.rekey.direct_every_messages, 512);
        assert!(!config.rekey.group_on_membership_change);
    }

    #[test]
    fn config_rejects_invalid_rekey_bounds() {
        let mut config = AppConfig::default();
        assert!(config.set("direct_rekey_every_messages", "0").is_err());
        assert!(config
            .set("direct_rekey_every_messages", "1000001")
            .is_err());
        assert!(config
            .set("group_broadcast_rekey_every_messages", "not-a-number")
            .is_err());
    }

    #[test]
    fn config_rejects_invalid_bool_and_unknown_key() {
        let mut config = AppConfig::default();
        assert!(config
            .set("group_rekey_on_membership_change", "sometimes")
            .is_err());
        assert!(config.set("unknown", "1").is_err());
    }

    #[test]
    fn config_rejects_invalid_data_dir() {
        let mut config = AppConfig::default();
        assert!(config.set("data_dir", "").is_err());
        assert!(config.set("data_dir", "bad\npath").is_err());
    }

    #[test]
    fn config_rejects_excessive_identity_rotation_threshold() {
        let mut config = AppConfig::default();
        assert!(config
            .set("rotate_identity_after_rekey_count", "1000001")
            .is_err());
    }

    #[test]
    fn config_set_updates_chat_policy() {
        let mut config = AppConfig::default();
        config
            .set("incoming_message_policy", "allow-unknown")
            .unwrap();
        config.set("default_group_max_members", "64").unwrap();
        config.set("default_chat_list_mode", "whitelist").unwrap();
        config.set("chat_whitelist", "alice;bob").unwrap();
        config.set("chat_blacklist", "mallory").unwrap();
        assert_eq!(
            config.chat.incoming_message_policy,
            IncomingMessagePolicy::AllowUnknown
        );
        assert_eq!(config.chat.default_group_max_members, 64);
        assert_eq!(config.chat.default_chat_list_mode, ChatListMode::Whitelist);
        assert_eq!(
            config.chat.whitelist,
            vec!["alice".to_owned(), "bob".to_owned()]
        );
        assert_eq!(config.chat.blacklist, vec!["mallory".to_owned()]);
    }

    #[test]
    fn config_rejects_invalid_chat_policy() {
        let mut config = AppConfig::default();
        assert!(config.set("incoming_message_policy", "maybe").is_err());
        assert!(config.set("default_group_max_members", "1").is_err());
        assert!(config.set("default_group_max_members", "513").is_err());
        assert!(config.set("default_chat_list_mode", "greylist").is_err());
        assert!(config.set("chat_whitelist", "bad|entry").is_err());
    }
}
