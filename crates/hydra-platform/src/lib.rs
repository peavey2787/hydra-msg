//! Narrow platform integration boundary for native operating-system primitives.
//!
//! All callers use safe Rust APIs. The Windows implementation below is the
//! repository's only audited FFI boundary and exists to provide replace-existing
//! semantics that `std::fs::rename` does not expose portably on Windows.

#![deny(unsafe_code)]

use std::{io, path::Path};

/// Atomically replaces `destination` with `source` when the operating system
/// provides same-filesystem rename/replace semantics.
///
/// `source` and `destination` are expected to be in the same directory. On
/// Windows this uses `MoveFileExW` with replace-existing and write-through
/// flags, avoiding the non-atomic delete-then-rename sequence.
pub fn atomic_replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        windows::atomic_replace_file(source, destination)
    }

    #[cfg(not(windows))]
    {
        std::fs::rename(source, destination)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::{io, os::windows::ffi::OsStrExt, path::Path};

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "Kernel32")]
    extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    pub(super) fn atomic_replace_file(source: &Path, destination: &Path) -> io::Result<()> {
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;

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
}
