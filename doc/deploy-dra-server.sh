#!/bin/bash
# Example: build and install PrettyDiameter on a target host.
# Set SRC_ROOT to your git checkout; run with appropriate privileges for install.
set -e
SRC="${SRC_ROOT:-.}"
BUILD="${BUILD_DIR:-$SRC/build}"

mkdir -p "$BUILD"
cd "$BUILD"
cmake -DCMAKE_BUILD_TYPE=MaxPerformance ..
cmake --build . -j"$(nproc)"
cmake --install .

export STAGING_ROOT="${STAGING_ROOT:-/opt/prettydiameter/staging}"
export BUILD_ROOT="$BUILD"
export SRC_ROOT="$SRC"
bash "$SRC/doc/stage-deploy.sh"
sudo bash "$SRC/doc/install-as-root.sh"

echo "Add LoadExtension for dra_rtstats in your freeDiameter.conf if needed."
echo "Stats UI (default): http://<host>:8088/"
