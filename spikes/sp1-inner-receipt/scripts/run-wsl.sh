#!/usr/bin/env bash
# Runs the isolated spike using the supported Linux SP1 environment.
set -euo pipefail

if [[ $# -ne 1 || ( "$1" != "--execute" && "$1" != "--prove" ) ]]; then
    echo "usage: bash scripts/run-wsl.sh --execute|--prove" >&2
    exit 64
fi

export PATH="$HOME/.cargo/bin:$HOME/.sp1/bin:$PATH"
cd "$(dirname "$0")/../script"

cargo run --release -- "$1"
