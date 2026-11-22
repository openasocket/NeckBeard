#!/usr/bin/env bash
# Prints the active NeckBeard level for Claude Code's terminal statusLine.
uid=$(id -u 2>/dev/null || echo u)
state_dir="${NECKBEARD_STATE_DIR:-${TMPDIR:-/tmp}/neckbeard-$uid}"
flag="$state_dir/.neckbeard-active"
mode="${NECKBEARD_LEVEL:-full}"
[ -f "$flag" ] && mode=$(head -n1 "$flag" | tr -d '[:space:]')
[ "$mode" = "off" ] && exit 0

color=108
[ "$mode" = "paranoid" ] && color=173

if [ -z "$mode" ] || [ "$mode" = "full" ]; then
    printf '\033[38;5;%sm[NECKBEARD]\033[0m' "$color"
else
    printf '\033[38;5;%sm[NECKBEARD:%s]\033[0m' "$color" "$(printf '%s' "$mode" | tr '[:lower:]' '[:upper:]')"
fi
