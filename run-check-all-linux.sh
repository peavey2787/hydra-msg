#!/usr/bin/env sh
set -eu


prepare_rust_path() {
    # Desktop launchers often start with a minimal PATH and do not load the
    # user's interactive shell startup files. Prefer the official rustup env
    # file, then add the common per-user cargo bin directory as a fallback.
    if [ -f "${HOME}/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "${HOME}/.cargo/env"
    fi

    case ":${PATH:-}:" in
        *:"${HOME}/.cargo/bin":*) ;;
        *) PATH="${HOME}/.cargo/bin:${PATH:-}" ;;
    esac
    export PATH
}

run_check_all() {
    prepare_rust_path
    downloads_dir="${HOME}/Downloads"
    if [ ! -d "$downloads_dir" ]; then
        echo "Downloads directory not found: $downloads_dir" >&2
        exit 1
    fi

    repo_dir=$(find "$downloads_dir" -maxdepth 1 -type d -name 'hydra*' -print | sort | while IFS= read -r candidate; do
        if [ -f "$candidate/qa/ci/check-all.sh" ]; then
            printf '%s\n' "$candidate"
            break
        fi
    done)

    if [ -z "$repo_dir" ]; then
        echo "No ~/Downloads/hydra*/qa/ci/check-all.sh repo found." >&2
        echo "Extract the repo under ~/Downloads with a folder name starting with hydra, then try again." >&2
        exit 1
    fi

    cd "$repo_dir"
    echo "HYDRA-MSG validation repo: $repo_dir"
    echo
    ./qa/ci/check-all.sh
}

run_inside_terminal() {
    status=0
    run_check_all || status=$?
    echo
    echo "check-all exit code: $status"
    printf 'Press Enter to close this terminal... '
    # shellcheck disable=SC2034
    read _answer || true
    exit "$status"
}

if [ "${HYDRA_CHECK_ALL_INSIDE_TERMINAL:-}" = "1" ]; then
    run_inside_terminal
fi

script_path=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || printf '%s\n' "$0")

open_with_terminal() {
    terminal="$1"
    case "$terminal" in
        gnome-terminal|cinnamon-terminal|mate-terminal)
            "$terminal" -- env HYDRA_CHECK_ALL_INSIDE_TERMINAL=1 "$script_path"
            ;;
        konsole)
            "$terminal" -e env HYDRA_CHECK_ALL_INSIDE_TERMINAL=1 "$script_path"
            ;;
        xfce4-terminal)
            "$terminal" --command "env HYDRA_CHECK_ALL_INSIDE_TERMINAL=1 '$script_path'"
            ;;
        lxterminal)
            "$terminal" -e env HYDRA_CHECK_ALL_INSIDE_TERMINAL=1 "$script_path"
            ;;
        alacritty|kitty|xterm|x-terminal-emulator)
            "$terminal" -e env HYDRA_CHECK_ALL_INSIDE_TERMINAL=1 "$script_path"
            ;;
        *)
            return 1
            ;;
    esac
}

for terminal in x-terminal-emulator gnome-terminal cinnamon-terminal mate-terminal konsole xfce4-terminal lxterminal alacritty kitty xterm; do
    if command -v "$terminal" >/dev/null 2>&1; then
        open_with_terminal "$terminal"
        exit 0
    fi
done

# Fallback for systems without a known terminal command.
run_inside_terminal
