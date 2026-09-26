//! Cross-platform lock tests and Unix transient-error classification.

mod lock {
    use crate::*;

    fn lock_path(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hydra-platform-lock-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root.join("state.hydra.lock")
    }

    #[test]
    fn second_lock_fails_until_the_first_is_released() {
        let path = lock_path("exclusive");
        let first = try_lock_exclusive(&path).unwrap().expect("first lock");
        assert!(try_lock_exclusive(&path).unwrap().is_none());
        drop(first);
        assert!(try_lock_exclusive(&path).unwrap().is_some());
    }

    #[test]
    fn a_leftover_lock_file_without_a_live_holder_is_reclaimed() {
        let path = lock_path("stale-file");
        std::fs::write(
            &path,
            b"pid=4294967295
    ",
        )
        .unwrap();
        assert!(try_lock_exclusive(&path).unwrap().is_some());
    }
}

#[cfg(not(windows))]
mod unix {
    use crate::*;

    #[test]
    fn host_lock_errors_are_transient_and_missing_files_are_not() {
        assert!(is_transient_lock(&io::Error::from_raw_os_error(13)));
        assert!(is_transient_lock(&io::Error::from_raw_os_error(16)));
        assert!(!is_transient_lock(&io::Error::from_raw_os_error(2)));
    }
}
