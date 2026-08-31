#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
launcher="$script_dir/run-app-linux.sh"
icon_source="$repo_root/examples/hydra-gui/assets/hydra-icon-512.png"
applications_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
icons_dir="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/512x512/apps"
mkdir -p "$applications_dir" "$icons_dir"
cp "$icon_source" "$icons_dir/hydra-msg.png"

desktop_file="$applications_dir/hydra-msg.desktop"
cat > "$desktop_file" <<EOF
[Desktop Entry]
Type=Application
Name=HYDRA
Comment=HYDRA private local chat
Exec="$launcher"
Icon=hydra-msg
Terminal=false
Categories=Network;Chat;Security;
StartupNotify=true
StartupWMClass=hydra-msg
EOF
chmod 0644 "$desktop_file"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$applications_dir" >/dev/null 2>&1 || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" >/dev/null 2>&1 || true
fi

echo "Installed HYDRA desktop launcher: $desktop_file"
echo "The launcher uses WM_CLASS hydra-msg so supported Linux taskbars map the running app to the HYDRA icon."
