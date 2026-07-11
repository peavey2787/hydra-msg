use crate::{
    limits::MAX_ENCRYPTED_STATE_BYTES, HydraMsgError, HydraResult, STATE_FILE_NAME,
    STATE_ROLLBACK_FILE_NAME,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const STATE_LOCK_FILE_NAME: &str = "state.hydra.lock";

#[derive(Debug)]
pub(crate) struct NativeProfileLock {
    path: PathBuf,
}

impl NativeProfileLock {
    fn acquire(path: PathBuf) -> HydraResult<Self> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    HydraMsgError::InvalidInput("native profile is already open")
                } else {
                    HydraMsgError::Io(error.to_string())
                }
            })?;
        file.write_all(format!("pid={}\n", std::process::id()).as_bytes())?;
        file.sync_all()?;
        Ok(Self { path })
    }
}

impl Drop for NativeProfileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Native opaque-byte store for encrypted local state and rollback guard files.
///
/// This adapter owns filesystem durability mechanics only. It must never parse
/// decrypted snapshot records, derive keys, or inspect HYDRA plaintext state.
#[derive(Clone, Debug)]
pub(crate) struct NativeStateStore {
    data_dir: PathBuf,
}

impl NativeStateStore {
    pub(crate) fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    pub(crate) fn ensure_dir(&self) -> HydraResult<()> {
        fs::create_dir_all(&self.data_dir)?;
        Ok(())
    }

    pub(crate) fn state_path(&self) -> PathBuf {
        self.data_dir.join(STATE_FILE_NAME)
    }

    pub(crate) fn rollback_path(&self) -> PathBuf {
        self.data_dir.join(STATE_ROLLBACK_FILE_NAME)
    }

    pub(crate) fn lock_path(&self) -> PathBuf {
        self.data_dir.join(STATE_LOCK_FILE_NAME)
    }

    pub(crate) fn acquire_profile_lock(&self) -> HydraResult<NativeProfileLock> {
        NativeProfileLock::acquire(self.lock_path())
    }

    pub(crate) fn state_exists(&self) -> bool {
        self.state_path().exists()
    }

    pub(crate) fn read_encrypted_snapshot(&self) -> HydraResult<Vec<u8>> {
        read_opaque_bytes(
            &self.state_path(),
            MAX_ENCRYPTED_STATE_BYTES,
            "encrypted state",
        )
    }

    pub(crate) fn write_encrypted_snapshot(&self, encrypted_snapshot: &[u8]) -> HydraResult<()> {
        if encrypted_snapshot.len() > MAX_ENCRYPTED_STATE_BYTES {
            return Err(HydraMsgError::InvalidInput("encrypted state size"));
        }
        write_atomic_opaque_bytes(&self.state_path(), encrypted_snapshot)
    }

    pub(crate) fn read_rollback_guard(&self) -> HydraResult<Option<String>> {
        let path = self.rollback_path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_opaque_bytes(&path, 64, "rollback guard size")?;
        let value = String::from_utf8(bytes)
            .map_err(|_| HydraMsgError::InvalidEncoding("rollback guard utf-8"))?;
        Ok(Some(value))
    }

    pub(crate) fn write_rollback_guard(&self, state_generation: u64) -> HydraResult<()> {
        write_atomic_opaque_bytes(
            &self.rollback_path(),
            format!("{}\n", state_generation).as_bytes(),
        )
    }
}

fn read_opaque_bytes(
    path: &Path,
    max_bytes: usize,
    description: &'static str,
) -> HydraResult<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    let read_limit = u64::try_from(max_bytes)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(HydraMsgError::InvalidEncoding(description))?;
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(HydraMsgError::InvalidEncoding(description));
    }
    Ok(bytes)
}

fn write_atomic_opaque_bytes(path: &Path, bytes: &[u8]) -> HydraResult<()> {
    let parent = path
        .parent()
        .ok_or(HydraMsgError::InvalidInput("state path parent"))?;
    fs::create_dir_all(parent)?;

    let tmp = temporary_path(path)?;
    let _ = fs::remove_file(&tmp);

    let write_result = (|| -> HydraResult<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        test_failpoint(path, "write temp file")?;
        file.write_all(bytes)?;
        test_failpoint(path, "sync temp file")?;
        file.sync_all()?;
        drop(file);
        test_failpoint(path, "rename/replace state")?;
        replace_file(&tmp, path)?;
        test_failpoint(path, "sync parent dir")?;
        sync_parent_dir(parent);
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp);
    }

    write_result
}

fn temporary_path(path: &Path) -> HydraResult<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(HydraMsgError::InvalidInput("state path filename"))?;
    Ok(path.with_file_name(format!("{file_name}.tmp")))
}

#[cfg(not(windows))]
fn replace_file(tmp: &Path, path: &Path) -> HydraResult<()> {
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(windows)]
fn replace_file(tmp: &Path, path: &Path) -> HydraResult<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static TEST_FAILPOINT: std::cell::RefCell<Option<(&'static str, &'static str)>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_test_failpoint(stage: Option<(&'static str, &'static str)>) {
    TEST_FAILPOINT.with(|failpoint| {
        *failpoint.borrow_mut() = stage;
    });
}

#[cfg(test)]
fn test_failpoint(path: &Path, stage: &'static str) -> HydraResult<()> {
    TEST_FAILPOINT.with(|failpoint| {
        let Some((requested_target, requested_stage)) = *failpoint.borrow() else {
            return Ok(());
        };
        if requested_stage != stage {
            return Ok(());
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Ok(());
        };
        if name != requested_target {
            return Ok(());
        }
        Err(HydraMsgError::Io(format!(
            "injected native persistence failure: {stage}"
        )))
    })
}

#[cfg(not(test))]
fn test_failpoint(_path: &Path, _stage: &'static str) -> HydraResult<()> {
    Ok(())
}

fn sync_parent_dir(parent: &Path) {
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
}
