#!/usr/bin/env bash
# Copyright (c) 2026 iamvirul. All rights reserved.
# Use of this source code is governed by the MIT license.
#
# Generates shell completion scripts into completions/ for the deb and rpm packages.
# Run by GoReleaser before building.
set -euo pipefail

cd "$(dirname "$0")/.."
rm -rf completions
mkdir -p completions
for shell in bash zsh fish; do
  go run ./cmd/sarc completion "$shell" > "completions/sarc.$shell"
done
