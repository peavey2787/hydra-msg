use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub(crate) type RuntimeResult<T> = Result<T, String>;

const REQUIRED_IMPORTS: &str = "import torch, transformers, huggingface_hub, safetensors";
const REQUIRED_PACKAGES: &[&str] = &[
    "torch>=2.4,<3",
    "transformers>=4.45,<6",
    "huggingface-hub>=0.25,<2",
    "safetensors>=0.4,<1",
];

pub(crate) fn resolve_or_bootstrap<F>(mut progress: F) -> RuntimeResult<PathBuf>
where
    F: FnMut(u8, &str),
{
    if let Some(path) = env::var_os("HYDRA_STEGO_PYTHON") {
        let path = PathBuf::from(path);
        validate_override(&path)?;
        progress(8, "Using HYDRA_STEGO_PYTHON runtime");
        return Ok(path);
    }

    let root = repository_root()?;
    let runtime_dir = root.join("target/stego-model-runtime");
    let python = runtime_python_path(&runtime_dir);

    progress(2, "Checking the private Python model runtime");
    if !python_responds(&python) {
        progress(3, "Creating the private Python model runtime");
        recreate_runtime(&runtime_dir)?;
    }

    if !imports_ready(&python) {
        progress(
            5,
            "Installing local AI runtime dependencies (first use only)",
        );
        install_dependencies(&python)?;
    }

    progress(9, "Verifying the local AI runtime");
    if !imports_ready(&python) {
        return Err(format!(
            "local AI runtime setup finished but required imports still fail at {}",
            python.display()
        ));
    }
    Ok(python)
}

fn repository_root() -> RuntimeResult<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "could not resolve the repository root".to_owned())
}

fn runtime_python_path(runtime_dir: &Path) -> PathBuf {
    if cfg!(windows) {
        runtime_dir.join("Scripts/python.exe")
    } else {
        runtime_dir.join("bin/python")
    }
}

fn validate_override(path: &Path) -> RuntimeResult<()> {
    if !path.is_file() {
        return Err(format!(
            "HYDRA_STEGO_PYTHON does not point to a file: {}",
            path.display()
        ));
    }
    if !imports_ready(path) {
        return Err(format!(
            "HYDRA_STEGO_PYTHON is missing one or more required packages (torch, transformers, huggingface-hub, safetensors): {}",
            path.display()
        ));
    }
    Ok(())
}

fn recreate_runtime(runtime_dir: &Path) -> RuntimeResult<()> {
    if runtime_dir.exists() {
        fs::remove_dir_all(runtime_dir).map_err(|error| {
            format!(
                "could not repair the incomplete model runtime at {}: {error}",
                runtime_dir.display()
            )
        })?;
    }
    if let Some(parent) = runtime_dir.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "could not create the model runtime parent directory {}: {error}",
                parent.display()
            )
        })?;
    }

    let mut failures = Vec::new();
    for launcher in launcher_candidates() {
        if !launcher_available(&launcher) {
            continue;
        }
        let mut command = Command::new(launcher.program);
        command
            .args(&launcher.prefix)
            .args(["-m", "venv"])
            .arg(runtime_dir);
        match command.status() {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => failures.push(format!("{} exited with {}", launcher.display(), status)),
            Err(error) => failures.push(format!("{} failed: {error}", launcher.display())),
        }
    }

    let detail = if failures.is_empty() {
        "no supported Python launcher was found".to_owned()
    } else {
        failures.join("; ")
    };
    Err(format!(
        "could not create the private AI model runtime ({detail}). Install Python 3 with venv support and click Download / load selected model again"
    ))
}

fn install_dependencies(python: &Path) -> RuntimeResult<()> {
    run_python(
        python,
        &["-m", "ensurepip", "--upgrade"],
        "initializing pip in the private model runtime",
    )?;
    run_python(
        python,
        &[
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--upgrade",
            "pip",
        ],
        "upgrading pip in the private model runtime",
    )?;

    let mut args = vec![
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
    ];
    args.extend_from_slice(REQUIRED_PACKAGES);
    run_python(
        python,
        &args,
        "installing torch/transformers dependencies for the local model runtime",
    )
}

fn run_python(python: &Path, args: &[&str], action: &str) -> RuntimeResult<()> {
    let status = Command::new(python)
        .args(args)
        .status()
        .map_err(|error| format!("{action} failed to start: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{action} failed with {status}"))
    }
}

fn python_responds(python: &Path) -> bool {
    python.is_file()
        && Command::new(python)
            .args(["-c", "import sys; print(sys.version_info[:2])"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
}

fn imports_ready(python: &Path) -> bool {
    python_responds(python)
        && Command::new(python)
            .args(["-c", REQUIRED_IMPORTS])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
}

struct Launcher {
    program: &'static str,
    prefix: Vec<&'static str>,
}

impl Launcher {
    fn display(&self) -> String {
        if self.prefix.is_empty() {
            self.program.to_owned()
        } else {
            format!("{} {}", self.program, self.prefix.join(" "))
        }
    }
}

fn launcher_candidates() -> Vec<Launcher> {
    if cfg!(windows) {
        vec![
            Launcher {
                program: "py",
                prefix: vec!["-3"],
            },
            Launcher {
                program: "python",
                prefix: Vec::new(),
            },
            Launcher {
                program: "python3",
                prefix: Vec::new(),
            },
        ]
    } else {
        vec![
            Launcher {
                program: "python3",
                prefix: Vec::new(),
            },
            Launcher {
                program: "python",
                prefix: Vec::new(),
            },
        ]
    }
}

fn launcher_available(launcher: &Launcher) -> bool {
    Command::new(launcher.program)
        .args(&launcher.prefix)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_runtime_path_matches_platform_layout() {
        let base = Path::new("target/stego-model-runtime");
        let path = runtime_python_path(base);
        if cfg!(windows) {
            assert!(path.ends_with("Scripts/python.exe"));
        } else {
            assert!(path.ends_with("bin/python"));
        }
    }

    #[test]
    fn runtime_package_contract_covers_model_script_imports() {
        assert_eq!(REQUIRED_PACKAGES.len(), 4);
        for package in ["torch", "transformers", "huggingface-hub", "safetensors"] {
            assert!(REQUIRED_PACKAGES
                .iter()
                .any(|entry| entry.starts_with(package)));
        }
    }
}
