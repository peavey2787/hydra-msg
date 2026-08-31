#!/usr/bin/env python3
"""Shared Miri, sanitizer, and crash-consistency release gate."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import shlex
from datetime import date, timedelta

ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / "docs/validation/gates/miri-sanitizer-fault-injection.md"
CRASH_TESTS = ROOT / "crates/hydra-msg/src/tests/crash_consistency.rs"
NATIVE_STORE = ROOT / "crates/hydra-msg/src/persistence/native_store.rs"


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def require_file(path: Path) -> None:
    if not path.is_file():
        fail(f"required memory-safety gate file missing: {path.relative_to(ROOT)}")


def require_text(path: Path, text: str) -> None:
    body = path.read_text(encoding="utf-8")
    if text not in body:
        fail(f"memory-safety invariant missing from {path.relative_to(ROOT)}: {text}")


def require_command(name: str) -> str:
    command = shutil.which(name)
    if not command:
        fail(f"required command missing: {name}")
    return command


def run(name: str, args: list[str], *, env: dict[str, str] | None = None, quiet: bool = False) -> None:
    if not quiet:
        print(f"\n==> {name}", flush=True)
    completed = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"{name} failed with exit code {completed.returncode}")


def succeeds(args: list[str]) -> bool:
    return subprocess.run(
        args,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def auto_install_enabled() -> bool:
    return os.environ.get("HYDRA_AUTO_INSTALL_RUST_TOOLS", "1") != "0"


def ensure_nightly() -> None:
    require_command("rustup")
    if succeeds(["rustc", "+nightly", "--version"]):
        return
    if not auto_install_enabled():
        fail("nightly Rust is required; auto-install is disabled by HYDRA_AUTO_INSTALL_RUST_TOOLS=0")
    print("nightly Rust is missing; installing the minimal nightly toolchain...", flush=True)
    run("install nightly Rust", ["rustup", "toolchain", "install", "nightly", "--profile", "minimal"])


def ensure_toolchain(toolchain: str) -> None:
    require_command("rustup")
    if succeeds(["rustc", f"+{toolchain}", "--version"]):
        return
    if not auto_install_enabled():
        fail(
            f"Rust toolchain {toolchain!r} is required; auto-install is disabled by "
            "HYDRA_AUTO_INSTALL_RUST_TOOLS=0"
        )
    print(f"Rust toolchain {toolchain!r} is missing; installing it...", flush=True)
    run(
        f"install Rust toolchain {toolchain}",
        ["rustup", "toolchain", "install", toolchain, "--profile", "minimal"],
    )


def ensure_component_for_toolchain(
    toolchain: str, component: str, probe: list[str] | None = None
) -> None:
    ensure_toolchain(toolchain)
    if probe and succeeds(probe):
        return
    installed = subprocess.run(
        ["rustup", "component", "list", "--toolchain", toolchain],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if installed.returncode == 0:
        prefix = component + "-"
        if any(
            line.startswith(prefix) and line.rstrip().endswith("(installed)")
            or line.startswith(component + " ") and line.rstrip().endswith("(installed)")
            for line in installed.stdout.splitlines()
        ):
            if not probe or succeeds(probe):
                return
    if not auto_install_enabled():
        fail(
            f"toolchain component {component!r} for {toolchain!r} is required; auto-install "
            "is disabled by HYDRA_AUTO_INSTALL_RUST_TOOLS=0"
        )
    print(
        f"toolchain component {component!r} is missing for {toolchain!r}; installing it...",
        flush=True,
    )
    run(
        f"install {toolchain} {component}",
        ["rustup", "component", "add", "--toolchain", toolchain, component],
    )
    if probe and not succeeds(probe):
        fail(
            f"toolchain component {component!r} was installed for {toolchain!r} but its "
            "validation probe still fails"
        )


def ensure_component(component: str, probe: list[str] | None = None) -> None:
    ensure_nightly()
    ensure_component_for_toolchain("nightly", component, probe)


def capture(args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def nightly_host() -> str:
    ensure_nightly()
    verbose = capture(["rustc", "+nightly", "-vV"])
    if verbose is None:
        fail("unable to query the nightly Rust host target")
    for line in verbose.splitlines():
        if line.startswith("host: "):
            return line.split(": ", 1)[1].strip()
    fail("nightly rustc did not report a host target")


WINDOWS_SANITIZER_LINUX_TARGET = "x86_64-unknown-linux-gnu"
WINDOWS_SANITIZER_DOCKER_IMAGE = "rustlang/rust:nightly-bookworm-2026-08-17"
WINDOWS_SANITIZER_BACKENDS = {"auto", "docker", "wsl"}


def _windows_sanitizer_backend(env: dict[str, str]) -> tuple[str, str]:
    """Select a supported Linux execution backend for Rust sanitizer evidence on Windows.

    Rust's supported AddressSanitizer target matrix does not include windows-msvc.  Do not
    attempt to combine rustc's sanitizer instrumentation with an MSVC C++ ASan runtime.
    """
    requested = env.get("HYDRA_WINDOWS_SANITIZER_BACKEND", "auto").strip().lower()
    if requested not in WINDOWS_SANITIZER_BACKENDS:
        fail(
            "HYDRA_WINDOWS_SANITIZER_BACKEND must be one of: auto, docker, wsl"
        )

    docker = shutil.which("docker.exe", path=env.get("PATH")) or shutil.which(
        "docker", path=env.get("PATH")
    )
    if requested in ("auto", "docker") and docker:
        probe = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if probe.returncode == 0:
            return "docker", docker
        if requested == "docker":
            fail(
                "Docker was selected for Windows sanitizer evidence, but the Docker daemon "
                "is not available. Start Docker Desktop or set "
                "HYDRA_WINDOWS_SANITIZER_BACKEND=wsl."
            )

    wsl = shutil.which("wsl.exe", path=env.get("PATH")) or shutil.which(
        "wsl", path=env.get("PATH")
    )
    if requested in ("auto", "wsl") and wsl:
        probe = subprocess.run(
            [wsl, "-e", "sh", "-lc", "true"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if probe.returncode == 0:
            return "wsl", wsl
        if requested == "wsl":
            fail(
                "WSL was selected for Windows sanitizer evidence, but no usable Linux "
                "distribution could be started."
            )

    fail(
        "Rust AddressSanitizer does not support x86_64-pc-windows-msvc. Windows release "
        "sanitizer evidence therefore requires a supported Linux backend. Start Docker "
        "Desktop, or install/start a WSL distribution, then rerun from sanitizers. "
        "Override backend selection with HYDRA_WINDOWS_SANITIZER_BACKEND=docker|wsl."
    )


def _sanitizer_linux_shell(packages: list[str], sanitizer: str, target_dir: str) -> str:
    package_commands = "\n".join(
        f"cargo +nightly test -Zbuild-std --target {WINDOWS_SANITIZER_LINUX_TARGET} -p {shlex.quote(package)}"
        for package in packages
    )
    return f"""set -eu
rustup component add --toolchain nightly rust-src
rustc +nightly -vV
export RUSTFLAGS={shlex.quote(f'-Zsanitizer={sanitizer}')}
export CARGO_TARGET_DIR={shlex.quote(target_dir)}
{package_commands}
"""


def _write_windows_sanitizer_evidence(backend: str, detail: str) -> None:
    evidence_dir = ROOT / "target" / "memory-safety"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "windows-sanitizer-backend.txt").write_text(
        "\n".join(
            (
                "host=windows",
                f"backend={backend}",
                f"detail={detail}",
                f"target={WINDOWS_SANITIZER_LINUX_TARGET}",
                "reason=Rust AddressSanitizer does not support windows-msvc; use supported Linux target",
                "",
            )
        ),
        encoding="utf-8",
    )


def _run_windows_sanitizers_docker(
    docker: str, packages: list[str], sanitizer: str, env: dict[str, str]
) -> None:
    image = env.get("HYDRA_WINDOWS_SANITIZER_DOCKER_IMAGE", WINDOWS_SANITIZER_DOCKER_IMAGE)
    target_dir = "/work/target/sanitizer-address-linux-docker"
    script = _sanitizer_linux_shell(packages, sanitizer, target_dir)
    print(
        f"Windows sanitizer backend: Docker ({image}) -> {WINDOWS_SANITIZER_LINUX_TARGET}",
        flush=True,
    )
    run(
        "Windows-hosted Linux AddressSanitizer evidence",
        [
            docker,
            "run",
            "--rm",
            "--mount",
            f"type=bind,source={ROOT},target=/work",
            "--workdir",
            "/work",
            image,
            "sh",
            "-lc",
            script,
        ],
        env=env,
    )
    _write_windows_sanitizer_evidence("docker", image)


def _wsl_path(wsl: str, path: Path, env: dict[str, str]) -> str:
    completed = subprocess.run(
        [wsl, "-e", "wslpath", "-a", str(path)],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        fail("unable to translate the HYDRA repository path into the selected WSL distribution")
    return completed.stdout.strip()


def _run_windows_sanitizers_wsl(
    wsl: str, packages: list[str], sanitizer: str, env: dict[str, str]
) -> None:
    linux_root = _wsl_path(wsl, ROOT, env)
    target_dir = f"{linux_root}/target/sanitizer-address-linux-wsl"
    test_script = _sanitizer_linux_shell(packages, sanitizer, target_dir)
    bootstrap = f"""set -eu
if ! command -v rustup >/dev/null 2>&1; then
  if ! command -v curl >/dev/null 2>&1; then
    echo 'WSL sanitizer backend needs curl to bootstrap rustup' >&2
    exit 127
  fi
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
. "$HOME/.cargo/env" 2>/dev/null || true
rustup toolchain install nightly --profile minimal
cd {shlex.quote(linux_root)}
{test_script}
"""
    print(
        f"Windows sanitizer backend: WSL -> {WINDOWS_SANITIZER_LINUX_TARGET}",
        flush=True,
    )
    run(
        "Windows-hosted WSL AddressSanitizer evidence",
        [wsl, "-e", "sh", "-lc", bootstrap],
        env=env,
    )
    _write_windows_sanitizer_evidence("wsl", linux_root)


def run_windows_supported_sanitizers(packages: list[str], sanitizer: str) -> None:
    if sanitizer != "address":
        fail(
            "Windows-hosted release evidence currently supports the Rust AddressSanitizer "
            f"backend only, not {sanitizer!r}"
        )
    env = os.environ.copy()
    backend, command = _windows_sanitizer_backend(env)
    if backend == "docker":
        _run_windows_sanitizers_docker(command, packages, sanitizer, env)
    else:
        _run_windows_sanitizers_wsl(command, packages, sanitizer, env)

def static_policy_checks() -> None:
    for path in (POLICY, CRASH_TESTS, NATIVE_STORE):
        require_file(path)
    for text in (
        "Miri",
        "sanitizer",
        "fault-injection",
        "HYDRA_RUN_MIRI=0",
        "HYDRA_RUN_SANITIZERS=1",
        "HYDRA_WINDOWS_SANITIZER_BACKEND",
        "x86_64-unknown-linux-gnu",
    ):
        require_text(POLICY, text)
    for stage in ("write temp file", "sync temp file", "rename/replace state", "sync parent dir"):
        require_text(NATIVE_STORE, f'test_failpoint(path, "{stage}")?')
        require_text(CRASH_TESTS, stage)
    for text in ("#[cfg(test)]", "set_test_failpoint"):
        require_text(NATIVE_STORE, text)
    for text in (
        "backup_import_failure_is_atomic_in_memory_and_on_disk",
        "delete_identity_failure_restores_memory_and_disk",
        "delete_contact_failure_restores_memory_and_disk",
        "delete_message_failure_restores_memory_and_disk",
    ):
        require_text(CRASH_TESTS, text)


def run_fault_injection() -> None:
    require_command("cargo")
    if os.environ.get("HYDRA_WORKSPACE_TESTS_ALREADY_RAN") == "1":
        print("fault-injection crash-consistency tests already executed by the workspace test pass; not repeating.")
        return
    run(
        "fault-injection crash-consistency tests",
        ["cargo", "test", "-p", "hydra-msg", "--lib", "tests::crash_consistency"],
    )


def _parse_rustc_verbose(verbose: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in verbose.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key.strip()] = value.strip()
    return fields


def _nightly_archive_candidates(commit_date: str) -> list[str]:
    """Return nearby rustup archive dates likely to contain a rustc commit.

    rustc's `commit-date` is the source/compiler commit date, while rustup's
    `nightly-YYYY-MM-DD` suffix names the *distribution archive date*.  They are
    commonly one day apart, so never assume those dates are identical.
    """
    try:
        compiler_date = date.fromisoformat(commit_date)
    except ValueError:
        fail(f"nightly rustc reported an invalid commit-date: {commit_date!r}")
    offsets = (1, 0, 2, -1)
    return [f"nightly-{compiler_date + timedelta(days=offset)}" for offset in offsets]


def _matching_dated_nightly(commit_date: str, commit_hash: str, host: str) -> tuple[str, str]:
    override = os.environ.get("HYDRA_MIRI_TOOLCHAIN", "").strip()
    candidates = [override] if override else _nightly_archive_candidates(commit_date)
    observed: list[str] = []
    for toolchain in candidates:
        if not toolchain:
            continue
        ensure_toolchain(toolchain)
        verbose = capture(["rustc", f"+{toolchain}", "-vV"])
        if verbose is None:
            observed.append(f"{toolchain}=unavailable")
            continue
        fields = _parse_rustc_verbose(verbose)
        candidate_hash = fields.get("commit-hash")
        candidate_host = fields.get("host")
        observed.append(f"{toolchain}={candidate_hash or '<unknown>'}")
        if candidate_hash == commit_hash and candidate_host == host:
            archive_date = toolchain.removeprefix("nightly-")
            return toolchain, archive_date
        if override:
            fail(
                f"HYDRA_MIRI_TOOLCHAIN={toolchain!r} does not match the resolved floating "
                f"nightly compiler {commit_hash} on {host}; got "
                f"{candidate_hash or '<unknown>'} on {candidate_host or '<unknown>'}"
            )
    fail(
        "unable to map the resolved floating nightly compiler to an immutable rustup "
        "archive date; tried: " + ", ".join(observed)
    )


def _pinned_miri_toolchain() -> tuple[str, str, str, str, str]:
    """Resolve floating nightly once, then pin Miri to the matching archive toolchain."""
    ensure_nightly()
    floating = capture(["rustc", "+nightly", "-vV"])
    if floating is None:
        fail("unable to query the floating nightly Rust compiler for Miri")
    fields = _parse_rustc_verbose(floating)
    commit_date = fields.get("commit-date")
    commit_hash = fields.get("commit-hash")
    host = fields.get("host")
    if not commit_date or not commit_hash or not host:
        fail("nightly rustc did not report commit-date, commit-hash, and host for Miri pinning")

    toolchain, archive_date = _matching_dated_nightly(commit_date, commit_hash, host)
    ensure_component_for_toolchain(
        toolchain, "miri", ["cargo", f"+{toolchain}", "miri", "--version"]
    )
    ensure_component_for_toolchain(toolchain, "rust-src")
    pinned = capture(["rustc", f"+{toolchain}", "-vV"])
    if pinned is None:
        fail(f"unable to query pinned Miri toolchain {toolchain}")
    pinned_fields = _parse_rustc_verbose(pinned)
    if pinned_fields.get("commit-hash") != commit_hash or pinned_fields.get("host") != host:
        fail(
            f"pinned Miri toolchain changed unexpectedly: expected rustc {commit_hash} "
            f"on {host}, got {pinned_fields.get('commit-hash', '<unknown>')} on "
            f"{pinned_fields.get('host', '<unknown>')}"
        )
    return toolchain, archive_date, commit_date, commit_hash, host


def _prepare_miri_environment(
    toolchain: str, archive_date: str, commit_date: str, commit_hash: str, host: str
) -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("MIRIFLAGS", "-Zmiri-disable-isolation")
    # Never reuse a sysroot or Cargo target built by a different nightly.  A moving
    # `+nightly` alias can update during a multi-hour Miri run, especially before
    # doctests.  Key both caches to the immutable compiler commit instead.
    cache_key = f"{archive_date}-{commit_hash[:12]}-{host}"
    miri_root = ROOT / "target" / "miri-release"
    sysroot = miri_root / "sysroots" / cache_key
    cargo_target = miri_root / "cargo" / cache_key
    sysroot.parent.mkdir(parents=True, exist_ok=True)
    cargo_target.mkdir(parents=True, exist_ok=True)
    env["MIRI_SYSROOT"] = str(sysroot)
    env["CARGO_TARGET_DIR"] = str(cargo_target)
    # Remove inherited compiler wrappers, then pin rustup for every child process
    # (including rustdoc/doctest subprocesses launched by cargo-miri).  The explicit
    # +toolchain selectors and this environment pin must agree.
    for name in ("RUSTC", "RUSTDOC"):
        env.pop(name, None)
    env["RUSTUP_TOOLCHAIN"] = toolchain

    setup = subprocess.run(
        ["cargo", f"+{toolchain}", "miri", "setup"],
        cwd=ROOT,
        env=env,
        check=False,
    )
    if setup.returncode != 0:
        print(
            "Miri setup failed once; removing the commit-keyed sysroot and retrying cleanly...",
            flush=True,
        )
        shutil.rmtree(sysroot, ignore_errors=True)
        run(
            "Miri sysroot setup retry",
            ["cargo", f"+{toolchain}", "miri", "setup"],
            env=env,
        )

    evidence_dir = ROOT / "target" / "memory-safety"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "miri-toolchain.txt").write_text(
        "\n".join(
            (
                f"toolchain={toolchain}",
                f"archive_date={archive_date}",
                f"commit_date={commit_date}",
                f"commit_hash={commit_hash}",
                f"host={host}",
                f"miri_sysroot={sysroot}",
                f"cargo_target_dir={cargo_target}",
                "",
            )
        ),
        encoding="utf-8",
    )
    return env


def run_miri() -> None:
    if os.environ.get("HYDRA_RUN_MIRI") == "0":
        if os.environ.get("HYDRA_MIRI_ALREADY_RAN") == "1":
            print("\nMiri release evidence already passed in the preceding Miri section; not repeating.")
        else:
            print("\nMiri execution explicitly disabled by HYDRA_RUN_MIRI=0.")
        return
    require_command("cargo")
    toolchain, archive_date, commit_date, commit_hash, host = _pinned_miri_toolchain()
    env = _prepare_miri_environment(toolchain, archive_date, commit_date, commit_hash, host)
    print(
        f"Miri pinned toolchain: {toolchain} ({commit_hash[:12]}) on {host}",
        flush=True,
    )
    packages = os.environ.get("HYDRA_MIRI_PACKAGES", "hydra-core hydra-envelope hydra-session").split()
    for package in packages:
        run(
            f"Miri: {package}",
            ["cargo", f"+{toolchain}", "miri", "test", "-p", package],
            env=env,
        )


def run_sanitizers() -> None:
    if os.environ.get("HYDRA_RUN_SANITIZERS") != "1":
        print("\nSanitizer execution skipped. Set HYDRA_RUN_SANITIZERS=1 for the nightly sanitizer gate.")
        return
    sanitizer = os.environ.get("HYDRA_SANITIZER", "address")
    packages = os.environ.get(
        "HYDRA_SANITIZER_PACKAGES", "hydra-core hydra-envelope hydra-session hydra-msg"
    ).split()

    if os.name == "nt":
        run_windows_supported_sanitizers(packages, sanitizer)
        return

    require_command("cargo")
    ensure_component("rust-src")
    if not succeeds(["cargo", "+nightly", "-Z", "help"]):
        fail("nightly Cargo is unavailable after nightly toolchain setup")
    target = os.environ.get("HYDRA_SANITIZER_TARGET") or nightly_host()
    env = os.environ.copy()
    rustflags = env.get("RUSTFLAGS", "").strip()
    env["RUSTFLAGS"] = f"-Zsanitizer={sanitizer}" + (f" {rustflags}" if rustflags else "")
    for package in packages:
        run(
            f"sanitizer({sanitizer}): {package}",
            ["cargo", "+nightly", "test", "-Zbuild-std", "--target", target, "-p", package],
            env=env,
        )


def main() -> int:
    static_policy_checks()
    run_fault_injection()
    run_miri()
    run_sanitizers()
    print("\nMiri/sanitizer/fault-injection gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
