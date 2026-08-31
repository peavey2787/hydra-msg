use std::{
    fmt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Mutex,
    time::Duration,
};

use crate::{
    generative::{LanguageModel, TokenCandidate, TokenId},
    StegoError,
};

mod io;
mod protocol;

use io::{ProcessIo, MAX_REQUEST_BYTES};
use protocol::{hex_decode, hex_encode, join_tokens, parse_tokens};

const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MAX_STARTUP_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_PROCESS_TOKEN_IDS: usize = 4 * 1024 * 1024;
const MAX_CANDIDATES_PER_REQUEST: usize = 4096;
const TOKEN_TEXT_UPPER_BYTES: usize = 11;

/// Configuration for a persistent deterministic local-model subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessModelConfig {
    pub python: PathBuf,
    pub script: PathBuf,
    pub model: String,
    /// Immutable 40-hex model revision/commit identifier.
    pub revision: String,
    pub device: String,
    pub dtype: String,
    pub startup_timeout: Duration,
    pub request_timeout: Duration,
}

impl ProcessModelConfig {
    /// Creates a process configuration pinned to an immutable model revision.
    pub fn new(
        python: impl Into<PathBuf>,
        script: impl Into<PathBuf>,
        model: impl Into<String>,
        revision: impl Into<String>,
    ) -> Self {
        Self {
            python: python.into(),
            script: script.into(),
            model: model.into(),
            revision: revision.into(),
            device: "cpu".to_owned(),
            dtype: "float32".to_owned(),
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

/// Deterministic [`LanguageModel`] backed by one persistent local process.
///
/// Requests and model startup are time-bounded. A timed-out or protocol-broken
/// process is terminated before control returns to the caller.
pub struct ProcessLanguageModel {
    fingerprint: String,
    request_timeout: Duration,
    io: Mutex<ProcessIo>,
}

impl fmt::Debug for ProcessLanguageModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessLanguageModel")
            .field("fingerprint", &self.fingerprint)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl ProcessLanguageModel {
    pub fn spawn(config: &ProcessModelConfig) -> Result<Self, StegoError> {
        Self::spawn_with_progress(config, |_, _| {})
    }

    /// Starts a model process while reporting bounded initialization progress.
    pub fn spawn_with_progress<F>(
        config: &ProcessModelConfig,
        mut on_progress: F,
    ) -> Result<Self, StegoError>
    where
        F: FnMut(u8, &str),
    {
        validate_config(config)?;
        let mut child = Command::new(&config.python)
            .arg(&config.script)
            .arg("--model")
            .arg(&config.model)
            .arg("--revision")
            .arg(&config.revision)
            .arg("--device")
            .arg(&config.device)
            .arg("--dtype")
            .arg(&config.dtype)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| StegoError::Model(format!("start model process: {error}")))?;
        let Some(stdin) = child.stdin.take() else {
            terminate_child(&mut child);
            return Err(StegoError::Model("model process has no stdin".to_owned()));
        };
        let Some(stdout) = child.stdout.take() else {
            terminate_child(&mut child);
            return Err(StegoError::Model("model process has no stdout".to_owned()));
        };
        let mut io = ProcessIo::new(child, stdin, stdout);
        let fingerprint = io.request_with_progress(
            "info",
            config.startup_timeout,
            "model startup",
            &mut on_progress,
        )?;
        if fingerprint.trim().is_empty() || fingerprint.len() > 1024 {
            io.terminate();
            return Err(StegoError::Model(
                "model process returned an empty or oversized fingerprint".to_owned(),
            ));
        }
        Ok(Self {
            fingerprint,
            request_timeout: config.request_timeout,
            io: Mutex::new(io),
        })
    }

    fn request(&self, request: &str) -> Result<String, StegoError> {
        self.io
            .lock()
            .map_err(|_| StegoError::Model("model process lock is poisoned".to_owned()))?
            .request(request, self.request_timeout, "model inference")
    }
}

impl LanguageModel for ProcessLanguageModel {
    fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    fn tokenize(&self, text: &str) -> Result<Vec<TokenId>, StegoError> {
        ensure_hex_request_fits("tokenize", text.len())?;
        parse_tokens(
            &self.request(&format!("tokenize\t{}", hex_encode(text.as_bytes())))?,
            MAX_PROCESS_TOKEN_IDS,
        )
    }

    fn detokenize(&self, tokens: &[TokenId]) -> Result<String, StegoError> {
        ensure_token_request_fits("detokenize", &[tokens])?;
        let response = self.request(&format!("detokenize\t{}", join_tokens(tokens)))?;
        String::from_utf8(hex_decode(&response)?)
            .map_err(|_| StegoError::Model("model returned non-UTF-8 text".to_owned()))
    }

    fn next_candidates(
        &self,
        context: &[TokenId],
        generated: &[TokenId],
        count: usize,
    ) -> Result<Vec<TokenCandidate>, StegoError> {
        if !(1..=MAX_CANDIDATES_PER_REQUEST).contains(&count) {
            return Err(StegoError::Model(
                "candidate request count must be from 1 through 4096".to_owned(),
            ));
        }
        ensure_token_request_fits("next candidates", &[context, generated])?;
        protocol::parse_candidates(
            &self.request(&format!(
                "next\t{count}\t{}\t{}",
                join_tokens(context),
                join_tokens(generated)
            ))?,
            count,
        )
    }

    fn is_natural_boundary(&self, generated: &[TokenId]) -> Result<bool, StegoError> {
        let text = self.detokenize(generated)?;
        Ok(text
            .trim_end()
            .chars()
            .next_back()
            .is_some_and(|character| matches!(character, '.' | '!' | '?')))
    }
}

fn ensure_hex_request_fits(operation: &'static str, byte_count: usize) -> Result<(), StegoError> {
    let encoded = byte_count
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(operation.len() + 1))
        .ok_or_else(|| StegoError::Model(format!("{operation} request size overflow")))?;
    if encoded > MAX_REQUEST_BYTES {
        return Err(StegoError::Model(format!(
            "{operation} request exceeded the 16 MiB process limit"
        )));
    }
    Ok(())
}

fn ensure_token_request_fits(
    operation: &'static str,
    token_sets: &[&[TokenId]],
) -> Result<(), StegoError> {
    let token_count = token_sets
        .iter()
        .try_fold(0_usize, |total, tokens| total.checked_add(tokens.len()))
        .ok_or_else(|| StegoError::Model(format!("{operation} token count overflow")))?;
    if token_count > MAX_PROCESS_TOKEN_IDS {
        return Err(StegoError::Model(format!(
            "{operation} request exceeded the process token limit"
        )));
    }
    let upper_bound = token_count
        .checked_mul(TOKEN_TEXT_UPPER_BYTES)
        .and_then(|bytes| bytes.checked_add(operation.len() + 64))
        .ok_or_else(|| StegoError::Model(format!("{operation} request size overflow")))?;
    if upper_bound > MAX_REQUEST_BYTES {
        return Err(StegoError::Model(format!(
            "{operation} request exceeded the 16 MiB process limit"
        )));
    }
    Ok(())
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn validate_config(config: &ProcessModelConfig) -> Result<(), StegoError> {
    if config.model.trim().is_empty() {
        return Err(StegoError::InvalidConfig("model name must not be empty"));
    }
    if config.revision.len() != 40 || !config.revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(StegoError::InvalidConfig(
            "model revision must be an immutable 40-hex commit identifier",
        ));
    }
    if !matches!(config.dtype.as_str(), "float32" | "float16" | "bfloat16") {
        return Err(StegoError::InvalidConfig(
            "model dtype must be float32, float16, or bfloat16",
        ));
    }
    if config.startup_timeout.is_zero() || config.startup_timeout > MAX_STARTUP_TIMEOUT {
        return Err(StegoError::InvalidConfig(
            "model startup timeout must be greater than zero and at most two hours",
        ));
    }
    if config.request_timeout.is_zero() || config.request_timeout > MAX_REQUEST_TIMEOUT {
        return Err(StegoError::InvalidConfig(
            "model request timeout must be greater than zero and at most ten minutes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_config_requires_immutable_revision_and_bounded_timeouts() {
        let mut config = ProcessModelConfig::new("python", "model.py", "repo/model", "main");
        assert!(matches!(
            validate_config(&config),
            Err(StegoError::InvalidConfig(_))
        ));
        config.revision = "0123456789abcdef0123456789abcdef01234567".to_owned();
        assert!(validate_config(&config).is_ok());
        config.request_timeout = Duration::ZERO;
        assert!(matches!(
            validate_config(&config),
            Err(StegoError::InvalidConfig(_))
        ));
    }

    #[test]
    fn process_requests_are_bounded_before_surface_encoding() {
        assert!(ensure_hex_request_fits("tokenize", MAX_REQUEST_BYTES).is_err());
        let too_many = vec![u32::MAX; MAX_REQUEST_BYTES / TOKEN_TEXT_UPPER_BYTES + 1];
        assert!(ensure_token_request_fits("detokenize", &[&too_many]).is_err());
    }
}
