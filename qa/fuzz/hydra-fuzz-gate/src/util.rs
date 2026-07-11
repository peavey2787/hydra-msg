use std::panic::{self, AssertUnwindSafe};

pub type FuzzResult<T> = Result<T, String>;

pub fn no_panic<F>(name: &str, input_name: &str, input_len: usize, f: F) -> FuzzResult<()>
where
    F: FnOnce(),
{
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(()) => Ok(()),
        Err(_) => Err(format!(
            "fuzz target panicked: target={name} input={input_name} len={input_len}"
        )),
    }
}

pub fn temp_case_dir(scope: &str, index: usize) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "hydra-msg-fuzz-{scope}-{}-{index}",
        std::process::id()
    ));
    path
}
