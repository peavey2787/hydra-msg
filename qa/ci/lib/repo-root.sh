#!/usr/bin/env sh
# Shared repository-root helper for HYDRA-MSG QA scripts.
#
# Important: do not ask git for the repo root here. If a ZIP is extracted over
# an older folder, .git/config can retain a stale core.worktree path. The QA
# scripts must anchor themselves to their own physical location instead.

set -eu

hydra_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
hydra_root_candidate=$hydra_script_dir
while [ "$hydra_root_candidate" != "/" ]; do
  if [ -f "$hydra_root_candidate/Cargo.toml" ] && [ -d "$hydra_root_candidate/qa/ci" ]; then
    HYDRA_REPO_ROOT=$hydra_root_candidate
    break
  fi
  hydra_root_candidate=$(CDPATH= cd -- "$hydra_root_candidate/.." && pwd -P)
done
if [ -z "${HYDRA_REPO_ROOT:-}" ]; then
  echo "Unable to locate HYDRA-MSG repo root from $hydra_script_dir" >&2
  exit 1
fi
export HYDRA_REPO_ROOT

hydra_repair_git_worktree() {
  if [ ! -d "$HYDRA_REPO_ROOT/.git" ]; then
    return 0
  fi

  current_worktree=$(git -C "$HYDRA_REPO_ROOT" config --get core.worktree 2>/dev/null || true)
  if [ -n "$current_worktree" ]; then
    resolved_worktree=$(CDPATH= cd -- "$current_worktree" 2>/dev/null && pwd -P || printf '%s' "$current_worktree")
    if [ "$resolved_worktree" != "$HYDRA_REPO_ROOT" ]; then
      printf 'Repairing stale git core.worktree:\n' >&2
      printf '  old: %s\n' "$current_worktree" >&2
      printf '  new: %s\n' "$HYDRA_REPO_ROOT" >&2
      git -C "$HYDRA_REPO_ROOT" config --unset core.worktree || true
    fi
  fi

  git_root=$(git -C "$HYDRA_REPO_ROOT" rev-parse --show-toplevel 2>/dev/null || true)
  if [ -n "$git_root" ]; then
    resolved_git_root=$(CDPATH= cd -- "$git_root" 2>/dev/null && pwd -P || printf '%s' "$git_root")
    if [ "$resolved_git_root" != "$HYDRA_REPO_ROOT" ]; then
      printf 'ERROR: Git still resolves this repo to a different path.\n' >&2
      printf '  script root: %s\n' "$HYDRA_REPO_ROOT" >&2
      printf '  git root:    %s\n' "$git_root" >&2
      printf 'Try: git -C "%s" config --unset core.worktree\n' "$HYDRA_REPO_ROOT" >&2
      exit 1
    fi
  fi
}

hydra_enter_repo_root() {
  hydra_repair_git_worktree
  cd "$HYDRA_REPO_ROOT"
  printf 'HYDRA-MSG repo root: %s\n' "$HYDRA_REPO_ROOT"
}
