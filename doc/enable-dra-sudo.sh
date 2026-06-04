#!/bin/bash
# Example sudoers fragment (adjust user and paths). Review with visudo before applying.
# Usage: sudo visudo -f /etc/sudoers.d/prettydiameter
cat <<'EOF'
# prettydiameter operator — replace %prettydiameter with your deploy group
%prettydiameter ALL=(ALL) NOPASSWD: /bin/systemctl restart freeDiameter.service, /bin/systemctl restart freediameter.service, /usr/local/bin/freeDiameterd
EOF
