#!/bin/bash
# Copy route_match examples into dra_rtstats.conf (edit doc/dra_rtstats.conf.sample first).
set -e
STATS="${DRA_RTSTATS_CONF:-/etc/freeDiameter/dra_rtstats.conf}"
SAMPLE="$(dirname "$0")/dra_rtstats.conf.sample"
if [ ! -f "$STATS" ]; then
	install -m 644 "$SAMPLE" "$STATS"
else
	echo "Edit $STATS — uncomment route_match lines from $SAMPLE"
fi
