#!/usr/bin/env bash
# NeckBeard terminal statusline widget for Claude Code.
# Displays active intensity level and total PreToolUse guard blocks from local state.
uid_val=$(id -u 2>/dev/null || echo u)
nb_state="${NECKBEARD_STATE_DIR:-${TMPDIR:-/tmp}/neckbeard-$uid_val}"
active_file="$nb_state/.neckbeard-active"
guard_file="$nb_state/guard-stats.json"

lvl="${NECKBEARD_LEVEL:-full}"
if [ -f "$active_file" ]; then
  lvl=$(tr -d '[:space:]' < "$active_file")
fi
[ "$lvl" = "off" ] && exit 0

blocks=""
if [ -f "$guard_file" ]; then
  cnt=$(sed -n 's/.*"total":\([0-9][0-9]*\).*/\1/p' "$guard_file" | head -n 1)
  if [ -n "$cnt" ] && [ "$cnt" -gt 0 ] 2>/dev/null; then
    blocks=" · ${cnt} blocked"
  fi
fi

upper_lvl=$(printf '%s' "$lvl" | tr '[:lower:]' '[:upper:]')
if [ "$lvl" = "paranoid" ]; then
  printf '\033[38;5;214m● NECKBEARD [%s%s]\033[0m' "$upper_lvl" "$blocks"
else
  printf '\033[38;5;42m● NECKBEARD [%s%s]\033[0m' "$upper_lvl" "$blocks"
fi
