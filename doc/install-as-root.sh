#!/bin/bash
# Install staged PrettyDiameter build (run as root).
set -e
ST="${STAGING_ROOT:-/opt/prettydiameter/staging}"

if [ ! -x "$ST/bin/freeDiameterd" ]; then
	echo "Missing $ST/bin/freeDiameterd — run stage-deploy.sh first" >&2
	exit 1
fi

install -m 755 "$ST/bin/freeDiameterd" /usr/local/bin/
install -d /usr/local/lib/freeDiameter
install -m 644 "$ST/lib/"*.fdx /usr/local/lib/freeDiameter/ 2>/dev/null || true
install -d /etc/freeDiameter
if [ ! -f /etc/freeDiameter/dra_rtstats.conf ]; then
	install -m 644 "$ST/etc/dra_rtstats.conf" /etc/freeDiameter/
fi
echo "Installed. Restart your freeDiameter service."
