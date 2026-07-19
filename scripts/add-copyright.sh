#!/usr/bin/env bash
# Prepends a copyright header to Go source files that do not already have one.
# Usage:
#   ./scripts/add-copyright.sh                  # all tracked *.go files
#   ./scripts/add-copyright.sh crypto/hmac.go   # specific file(s)
set -euo pipefail

YEAR=$(date +%Y)
HEADER="// Copyright (c) ${YEAR} iamvirul. All rights reserved.
// Use of this source code is governed by the MIT license."

REPO_ROOT="$(git rev-parse --show-toplevel)"

added=0
skipped=0

process_file() {
    local f="$1"
    local abs="$REPO_ROOT/$f"
    [[ -f "$abs" ]] || abs="$f"
    [[ -f "$abs" ]] || { echo "skip (not found): $f"; return; }

    if head -1 "$abs" | grep -q "^// Copyright"; then
        skipped=$((skipped + 1))
        return
    fi

    local tmp
    tmp=$(mktemp)
    printf '%s\n\n' "$HEADER" | cat - "$abs" > "$tmp"
    mv "$tmp" "$abs"
    echo "added: $abs"
    added=$((added + 1))
}

if [[ $# -gt 0 ]]; then
    for f in "$@"; do
        process_file "$f"
    done
else
    while IFS= read -r f; do
        process_file "$f"
    done < <(git -C "$REPO_ROOT" ls-files '*.go')
fi

echo "done: ${added} file(s) updated, ${skipped} already had a header."
