use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=assets/hydra.ico");
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        return;
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let rc_path = out_dir.join("hydra-icon.rc");
    fs::write(&rc_path, "1 ICON \"assets\\\\hydra.ico\"\r\n")
        .expect("write HYDRA Windows icon resource script");

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "msvc" {
        compile_msvc_resource(&manifest_dir, &rc_path, &out_dir);
    } else {
        compile_gnu_resource(&manifest_dir, &rc_path, &out_dir);
    }
}

fn compile_msvc_resource(manifest_dir: &Path, rc_path: &Path, out_dir: &Path) {
    let compiler = find_rc_exe().unwrap_or_else(|| {
        panic!(
            "Windows resource compiler rc.exe was not found; install the Windows SDK or set RC to its path"
        )
    });
    let output = out_dir.join("hydra-icon.res");
    let status = Command::new(&compiler)
        .current_dir(manifest_dir)
        .arg("/nologo")
        .arg(format!("/fo{}", output.display()))
        .arg(rc_path)
        .status()
        .expect("run rc.exe for HYDRA icon");
    assert!(
        status.success(),
        "rc.exe failed while embedding the HYDRA icon"
    );
    println!(
        "cargo:rustc-link-arg-bin=hydra-msg-example-gui={}",
        output.display()
    );
}

fn compile_gnu_resource(manifest_dir: &Path, rc_path: &Path, out_dir: &Path) {
    let target = env::var("TARGET").unwrap_or_default();
    let candidates = [
        env::var("WINDRES").ok(),
        (!target.is_empty()).then(|| format!("{target}-windres")),
        Some("windres".to_owned()),
    ];
    let compiler = candidates
        .into_iter()
        .flatten()
        .find(|candidate| command_exists(candidate))
        .unwrap_or_else(|| {
            panic!("GNU windres was not found; install the MinGW resource compiler or set WINDRES")
        });
    let output = out_dir.join("hydra-icon.o");
    let status = Command::new(&compiler)
        .current_dir(manifest_dir)
        .arg("--input-format=rc")
        .arg("--output-format=coff")
        .arg("--input")
        .arg(rc_path)
        .arg("--output")
        .arg(&output)
        .status()
        .expect("run windres for HYDRA icon");
    assert!(
        status.success(),
        "windres failed while embedding the HYDRA icon"
    );
    println!(
        "cargo:rustc-link-arg-bin=hydra-msg-example-gui={}",
        output.display()
    );
}

fn find_rc_exe() -> Option<PathBuf> {
    if let Some(path) = env::var_os("RC").map(PathBuf::from) {
        if path.is_file() || command_exists(path.as_os_str()) {
            return Some(path);
        }
    }
    if command_exists("rc.exe") {
        return Some(PathBuf::from("rc.exe"));
    }

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("x86") => "x86",
        Ok("aarch64") => "arm64",
        _ => "x64",
    };
    let mut roots = Vec::new();
    if let Some(program_files_x86) = env::var_os("ProgramFiles(x86)") {
        roots.push(PathBuf::from(program_files_x86).join("Windows Kits/10/bin"));
    }
    if let Some(program_files) = env::var_os("ProgramFiles") {
        roots.push(PathBuf::from(program_files).join("Windows Kits/10/bin"));
    }

    for root in roots {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        let mut versions = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        versions.sort();
        versions.reverse();
        for version in versions {
            let candidate = version.join(arch).join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn command_exists(command: impl AsRef<std::ffi::OsStr>) -> bool {
    Command::new(command)
        .arg("/?")
        .output()
        .map(|output| {
            output.status.success() || !output.stderr.is_empty() || !output.stdout.is_empty()
        })
        .unwrap_or(false)
}
