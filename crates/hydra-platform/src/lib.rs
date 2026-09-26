//! Narrow platform integration boundary for native operating-system primitives.
//!
//! All callers use safe Rust APIs. The Windows implementation below is the
//! repository's only audited FFI boundary and exists to provide replace-existing
//! semantics that `std::fs::rename` does not expose portably on Windows. The
//! bounded transient-lock retry is shared by every platform. Exclusive profile
//! locks use the OS lock primitive (`LockFileEx` / `flock`) so a crashed or
//! killed process never leaves a profile permanently locked.

#![deny(unsafe_code)]

use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
    thread,
    time::Duration,
};

/// Bounded retry budget for transient locks: 10 attempts, ~1.1s worst case.
const REPLACE_ATTEMPTS: u32 = 10;
const REPLACE_BACKOFF_STEP: Duration = Duration::from_millis(25);

/// Atomically replaces `destination` with `source` when the operating system
/// provides same-filesystem rename/replace semantics.
///
/// `source` and `destination` are expected to be in the same directory. On
/// Windows this uses `MoveFileExW` with replace-existing and write-through
/// flags, avoiding the non-atomic delete-then-rename sequence. A replacement
/// blocked by a transient lock (antivirus, search indexer, or a sync client
/// briefly holding the just-written file, which a WSL/drvfs mount of a Windows
/// folder reports as `EACCES`) is retried a bounded number of times; every
/// other error, and a lock that outlives the budget, is returned.
pub fn atomic_replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    let mut attempt = 1;
    loop {
        match replace_once(source, destination) {
            Err(error) if attempt < REPLACE_ATTEMPTS && is_transient_lock(&error) => {
                thread::sleep(REPLACE_BACKOFF_STEP * attempt);
                attempt += 1;
            }
            outcome => return outcome,
        }
    }
}

#[cfg(unix)]
use unix::lock_exclusive;
#[cfg(windows)]
use windows::{is_transient_lock, lock_exclusive, replace_once};

/// An exclusive, OS-held lock on a profile lock file. It is released when this
/// value is dropped and, because the operating system owns it, also when the
/// process exits or is killed. The lock file itself is left in place: it is only
/// a lock target, never evidence that the profile is open.
#[derive(Debug)]
pub struct ExclusiveFileLock {
    _file: File,
}

/// Takes the exclusive lock on `path`, creating the file if needed. Returns
/// `Ok(None)` when another live handle already holds it.
pub fn try_lock_exclusive(path: &Path) -> io::Result<Option<ExclusiveFileLock>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    if lock_exclusive(&file)? {
        Ok(Some(ExclusiveFileLock { _file: file }))
    } else {
        Ok(None)
    }
}

#[cfg(not(any(unix, windows)))]
fn lock_exclusive(_file: &File) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "exclusive file locks are unavailable on this platform",
    ))
}

#[cfg(not(windows))]
fn replace_once(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::rename(source, destination)
}

/// `EACCES` and `EBUSY`: what a drvfs/network mount returns while the host holds
/// the file. A genuine permission error still surfaces once the budget is spent.
#[cfg(not(windows))]
fn is_transient_lock(error: &io::Error) -> bool {
    const EACCES: i32 = 13;
    const EBUSY: i32 = 16;
    matches!(error.raw_os_error(), Some(EACCES | EBUSY))
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::{
        ffi::c_void,
        fs::File,
        io,
        os::windows::{ffi::OsStrExt, io::AsRawHandle},
        path::Path,
    };

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut c_void,
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
        fn LockFileEx(
            file: *mut c_void,
            flags: u32,
            reserved: u32,
            bytes_low: u32,
            bytes_high: u32,
            overlapped: *mut Overlapped,
        ) -> i32;
    }

    /// Byte-range lock on the first byte. Unlike an exclusive-share open, it is
    /// unaffected by scanners or sync clients that merely open the file.
    pub(crate) fn lock_exclusive(file: &File) -> io::Result<bool> {
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: std::ptr::null_mut(),
        };
        let locked = unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if locked != 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
            Ok(false)
        } else {
            Err(error)
        }
    }

    pub(super) fn is_transient_lock(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        )
    }

    pub(super) fn replace_once(source: &Path, destination: &Path) -> io::Result<()> {
        let source = wide_path(source);
        let destination = wide_path(destination);
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
mod unix;

#[cfg(test)]
mod tests;

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::time::Duration;

    fn scratch_dir(label: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("hydra-platform-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// Opens `path` with no sharing, the way a scanner or sync client can.
    fn exclusive_lock(path: &std::path::Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(path)
            .unwrap()
    }

    #[test]
    fn windows_atomic_replace_replaces_existing_destination_without_delete_gap() {
        let root = std::env::temp_dir().join(format!(
            "hydra-platform-atomic-replace-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("state.hydra.tmp");
        let destination = root.join("state.hydra");
        std::fs::write(&destination, b"old-state").unwrap();
        std::fs::write(&source, b"new-state").unwrap();

        atomic_replace_file(&source, &destination).unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"new-state");
        assert!(!source.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_atomic_replace_waits_out_a_transient_sharing_lock() {
        let root = scratch_dir("transient-lock");
        let source = root.join("state.hydra.tmp");
        let destination = root.join("state.hydra");
        std::fs::write(&destination, b"old-state").unwrap();
        std::fs::write(&source, b"new-state").unwrap();
        let lock = exclusive_lock(&destination);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(lock);
        });

        atomic_replace_file(&source, &destination).unwrap();
        release.join().unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"new-state");
        assert!(!source.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_atomic_replace_reports_a_lock_that_outlives_the_retry_budget() {
        let root = scratch_dir("persistent-lock");
        let source = root.join("state.hydra.tmp");
        let destination = root.join("state.hydra");
        std::fs::write(&destination, b"old-state").unwrap();
        std::fs::write(&source, b"new-state").unwrap();
        let lock = exclusive_lock(&destination);

        let error = atomic_replace_file(&source, &destination).unwrap_err();
        drop(lock);

        assert!(matches!(error.raw_os_error(), Some(5 | 32 | 33)));
        assert_eq!(std::fs::read(&destination).unwrap(), b"old-state");
        assert!(source.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
