#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
data_dir=${NOXIS_DEMO_DATA_DIR:-"$repo_dir/target/noxis-demo-local/$(date +%Y%m%d-%H%M%S)-$$"}

cd "$repo_dir"
exec cargo run -p noxis-node --features research-testing -- demo-local --data-dir "$data_dir"
