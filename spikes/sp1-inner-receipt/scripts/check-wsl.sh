#!/usr/bin/env bash
# Reproducible host-side compilation for the isolated SP1 spike.
set -euo pipefail

export PATH="$HOME/.cargo/bin:$HOME/.sp1/bin:$PATH"
cd "$(dirname "$0")/.."

cargo check -p noxis-sp1-inner-receipt-script
