#!/usr/bin/env bash
# Install or update the thepile services on this machine. Idempotent.
set -euo pipefail
cd "$(dirname "$0")"
sudo cp thepile-poller.service thepile-refresh.service thepile-refresh.timer \
        thepile-verify.service thepile-verify.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now thepile-poller
sudo systemctl enable --now thepile-refresh.timer
sudo systemctl enable --now thepile-verify.timer
echo
systemctl list-timers 'thepile-*' --no-pager
echo
echo "poller:   journalctl -u thepile-poller -f"
echo "refresh:  journalctl -u thepile-refresh -n 40 --no-pager"
echo "run now:  sudo systemctl start thepile-refresh"
