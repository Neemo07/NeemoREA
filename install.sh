#!/usr/bin/env bash
# install.sh — Install or remove the NeemoREA skill for OpenCode, Claude Code, Codex CLI, and Cursor.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${HOME}"
ACTION="install"
AGENTS=()

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

Agents (default when omitted: --claude):
  --opencode       ~/.config/opencode/skills/neemorea
  --claude         ~/.claude/skills/neemorea
  --codex          ~/.agents/skills/neemorea
  --cursor         ~/.cursor/rules/neemorea/neemorea.mdc (+ neemorea/references/)
  --all            install for all four agents above

Options:
  --dir <path>     override target root directory (e.g. a project root instead of $HOME)
  --uninstall      remove installed skill files for the selected agent(s)
  -h, --help       show this help message
EOF
}

add_agent() {
  local a
  for a in "${AGENTS[@]:-}"; do [[ "$a" == "$1" ]] && return 0; done
  AGENTS+=("$1")
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --opencode|--claude|--codex|--cursor) add_agent "${1#--}"; shift ;;
    --all) add_agent opencode; add_agent claude; add_agent codex; add_agent cursor; shift ;;
    --dir) [[ $# -ge 2 ]] || { echo "error: --dir requires a path" >&2; exit 2; }; ROOT_DIR="$2"; shift 2 ;;
    --uninstall) ACTION="uninstall"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown flag '$1' (try --help)" >&2; exit 2 ;;
  esac
done

[[ ${#AGENTS[@]} -gt 0 ]] || AGENTS=(claude)

install_skill_dir() {
  local dest="$1"
  rm -rf "$dest"
  mkdir -p "$dest"
  cp "$REPO_DIR/SKILL.md" "$dest/SKILL.md"
  cp -R "$REPO_DIR/references" "$dest/references"
  echo "installed: $dest"
}

install_cursor_rule() {
  local rules_dir="$1" dest="$1/neemorea"
  # Everything lives under rules/neemorea/ so we never touch the user's own rules or references/ dirs.
  rm -rf "$dest"
  mkdir -p "$dest"
  {
    printf '%s\n' "---"
    printf '%s\n' "description: NeemoREA — reverse engineer shipped software with plain local CLI tools."
    printf '%s\n' 'globs: ["**/*"]'
    printf '%s\n' "alwaysApply: false"
    printf '%s\n\n' "---"
    # tr -d '\r' keeps the frontmatter strip working on CRLF checkouts
    tr -d '\r' < "$REPO_DIR/SKILL.md" | awk 'NR==1 && /^---$/{in_fm=1; next} in_fm && /^---$/{in_fm=0; next} !in_fm{print}'
  } > "$dest/neemorea.mdc"
  cp -R "$REPO_DIR/references" "$dest/references"
  # Remove the flat file older versions of this installer wrote (never the shared references/ dir).
  rm -f "$rules_dir/neemorea.mdc"
  echo "installed: $dest/neemorea.mdc (+ references/)"
}

for agent in "${AGENTS[@]}"; do
  case "$agent" in
    opencode) target="$ROOT_DIR/.config/opencode/skills/neemorea" ;;
    claude)   target="$ROOT_DIR/.claude/skills/neemorea" ;;
    codex)    target="$ROOT_DIR/.agents/skills/neemorea" ;;
    cursor)   target="$ROOT_DIR/.cursor/rules" ;;
  esac

  if [[ "$ACTION" == "uninstall" ]]; then
    if [[ "$agent" == "cursor" ]]; then
      rm -rf "$target/neemorea"
      rm -f "$target/neemorea.mdc"   # legacy flat install
      echo "removed:   $target/neemorea"
    else
      rm -rf "$target"
      echo "removed:   $target"
    fi
  else
    if [[ "$agent" == "cursor" ]]; then
      install_cursor_rule "$target"
    else
      install_skill_dir "$target"
    fi
  fi
done
