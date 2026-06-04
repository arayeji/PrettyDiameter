#!/bin/bash
# Append DR= realm routing examples from doc/dra_rt-realm-routing.snippet
set -e
CONF="${RT_DEFAULT_CONF:-/etc/freeDiameter/dra_rt.conf}"
SNIP="$(dirname "$0")/dra_rt-realm-routing.snippet"
MARK="# Realm routing (PrettyDiameter sample)"

cp -a "$CONF" "${CONF}.bak.realm-$(date +%Y%m%d%H%M)"
if ! grep -qF "$MARK" "$CONF"; then
	{ echo ""; echo "$MARK"; cat "$SNIP"; } >> "$CONF"
fi
kill -USR1 "$(pgrep -x freeDiameterd)" 2>/dev/null || true
echo "Applied realm routing sample to $CONF"
