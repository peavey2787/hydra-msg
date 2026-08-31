#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
cd "$repo_root"

address=${HYDRA_GUI_ADDRESS:-127.0.0.1:8787}
url="http://$address/"
profile_dir="$repo_root/target/hydra-gui-browser-profile-linux"
log_dir="$repo_root/target/hydra-gui-logs"
mkdir -p "$profile_dir" "$log_dir"

if [ ! -f examples/hydra-gui/web/pkg/hydra_msg_wasm.js ] || [ ! -f examples/hydra-gui/web/pkg/hydra_msg_wasm_bg.wasm ]; then
    "$script_dir/build-wasm.sh"
fi

cargo build --manifest-path examples/hydra-gui/Cargo.toml
host="$repo_root/target/debug/hydra-msg-example-gui"
if [ ! -x "$host" ]; then
    echo "HYDRA GUI host binary was not produced at $host" >&2
    exit 1
fi

"$host" "$address" >"$log_dir/host.stdout.log" 2>"$log_dir/host.stderr.log" &
host_pid=$!
cleanup() {
    kill "$host_pid" 2>/dev/null || true
    wait "$host_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP

ready=0
for _attempt in $(seq 1 80); do
    if command -v curl >/dev/null 2>&1 && curl --fail --silent --max-time 1 "$url/api/health" >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "$host_pid" 2>/dev/null; then
        echo "HYDRA GUI host exited during startup; see $log_dir/host.stderr.log" >&2
        exit 1
    fi
    sleep 0.25
done
if [ "$ready" -ne 1 ] && command -v curl >/dev/null 2>&1; then
    echo "HYDRA GUI host did not become ready at $url" >&2
    exit 1
fi

browser=""
for candidate in chromium chromium-browser google-chrome google-chrome-stable microsoft-edge microsoft-edge-stable brave-browser; do
    if command -v "$candidate" >/dev/null 2>&1; then
        browser=$(command -v "$candidate")
        break
    fi
done
if [ -z "$browser" ]; then
    echo "A Chromium-family browser is required for the dedicated HYDRA taskbar identity." >&2
    echo "Install Chromium, Chrome, Edge, or Brave, then run this launcher again." >&2
    exit 1
fi

# --class matches the installed hydra-msg.desktop StartupWMClass so Linux shells
# use the HYDRA icon instead of the browser's generic icon for this app window.
"$browser" \
    --user-data-dir="$profile_dir" \
    --class=hydra-msg \
    --app="$url"
