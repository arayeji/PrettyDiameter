#!/bin/bash
# Stage build artifacts for install (run as unprivileged user after cmake build).
set -e
ST="${STAGING_ROOT:-/opt/prettydiameter/staging}"
B="${BUILD_ROOT:-/opt/prettydiameter/build}"
SRC="${SRC_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

mkdir -p "$ST/bin" "$ST/lib" "$ST/etc"
cp -f "$B/libfdcore/libfdcore.la" "$ST/lib/" 2>/dev/null || true
cp -f "$B/libfdproto/libfdproto.la" "$ST/lib/" 2>/dev/null || true
cp -f "$B/libfdcore/freeDiameterd" "$ST/bin/"
cp -f "$B/extensions/dra_rtstats/dra_rtstats.fdx" "$ST/lib/" 2>/dev/null || true
cp -f "$B/extensions/dra_peerctl/dra_peerctl.fdx" "$ST/lib/" 2>/dev/null || true
cp -f "$SRC/doc/dra_rtstats.conf.sample" "$ST/etc/dra_rtstats.conf"
cp -f "$SRC/doc/dra_peerctl.conf.sample" "$ST/etc/dra_peerctl.conf"
echo "Staged to $ST"
