#!/bin/bash
# Append IMSI-prefix rt_default rules from doc/dra_rt-imsi-fix.snippet
set -e
CONF="${RT_DEFAULT_CONF:-/etc/freeDiameter/dra_rt.conf}"
SNIP="$(dirname "$0")/dra_rt-imsi-fix.snippet"
MARK="# IMSI prefix routing (PrettyDiameter sample)"

cp -a "$CONF" "${CONF}.bak.imsi-$(date +%Y%m%d%H%M)"
if ! grep -qF "$MARK" "$CONF"; then
	{ echo ""; echo "$MARK"; cat "$SNIP"; } >> "$CONF"
fi
kill -USR1 "$(pgrep -x freeDiameterd)" 2>/dev/null || true
echo "Applied IMSI routing sample to $CONF"
