#!/bin/bash
# Enable dra_peerctl in an existing dra.conf (run as root).
set -e
CONF="${1:-/etc/freeDiameter/dra.conf}"
PEERCTL_LINE='LoadExtension = "/usr/local/lib/freeDiameter/dra_peerctl.fdx" : "/etc/freeDiameter/dra_peerctl.conf";'
SAMPLE="${2:-/usr/share/doc/prettydiameter/dra_peerctl.conf.sample}"

if grep -q 'dra_peerctl.fdx' "$CONF" 2>/dev/null; then
	python3 - "$CONF" "$PEERCTL_LINE" <<'PY'
import re, sys
path, line = sys.argv[1], sys.argv[2] + "\n"
text = open(path).read()
text = re.sub(r'LoadExtension\s*=.*dra_peerctl[^\n]*\n', line, text)
open(path, 'w').write(text)
PY
else
	python3 - "$CONF" "$PEERCTL_LINE" <<'PY'
import sys
path, line = sys.argv[1], sys.argv[2] + "\n"
text = open(path).read()
needle = 'LoadExtension = "/usr/local/lib/freeDiameter/dra_rtstats.fdx"'
if needle in text:
	text = text.replace(
		needle + ' : "/etc/freeDiameter/dra_rtstats.conf";\n',
		needle + ' : "/etc/freeDiameter/dra_rtstats.conf";\n' + line,
		1,
	)
else:
	text += "\n" + line
open(path, 'w').write(text)
PY
fi

if [ -f "$SAMPLE" ] && [ ! -f /etc/freeDiameter/dra_peerctl.conf ]; then
	install -m 644 "$SAMPLE" /etc/freeDiameter/dra_peerctl.conf
fi

echo "Updated $CONF:"
grep dra_peerctl "$CONF"
