#!/bin/bash
# Append DH→MME rt_default rules from doc/dra_rt-dh-mme-routing.snippet
set -e
CONF="${RT_DEFAULT_CONF:-/etc/freeDiameter/dra_rt.conf}"
SNIP="$(dirname "$0")/dra_rt-dh-mme-routing.snippet"
MARK="# DH routing (PrettyDiameter sample)"

cp -a "$CONF" "${CONF}.bak.dh-mme-$(date +%Y%m%d%H%M)"
if ! grep -qF "$MARK" "$CONF"; then
	{ echo ""; echo "$MARK"; cat "$SNIP"; } >> "$CONF"
fi
kill -USR1 "$(pgrep -x freeDiameterd)" 2>/dev/null || systemctl reload freeDiameter 2>/dev/null || true
echo "Applied DH MME rules to $CONF"
