#!/usr/bin/env python3
"""Apply PowerSVX host hygiene (journald 1G + disk-guard cron) to all inventory hosts with SSH."""
from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import paramiko
import yaml

ROOT = Path(__file__).resolve().parents[1]
INV = ROOT / "ops" / "inventory.local.yaml"
SCRIPT = (ROOT / "deploy" / "linux" / "disk-guard.sh").read_text(encoding="utf-8")


def hosts():
    inv = yaml.safe_load(INV.read_text(encoding="utf-8"))
    default_user = inv.get("ssh_user", "hendra")
    default_dir = inv.get("remote_dir", "/home/hendra/powersvx")
    out = []
    for h in inv.get("hosts", []):
        if h.get("role") != "production":
            continue
        if not h.get("ssh_password") or not h.get("ip"):
            print(f"SKIP {h.get('name')}: no ssh creds")
            continue
        out.append(
            {
                "name": h["name"],
                "ip": h["ip"],
                "user": h.get("ssh_user") or default_user,
                "password": h["ssh_password"],
                "port": int(h.get("ssh_port") or 22),
                "remote_dir": h.get("remote_dir") or default_dir,
            }
        )
    return out


REMOTE_APPLY = r'''#!/bin/bash
set -euo pipefail
PASS="$1"
RD="$2"
sud(){ echo "$PASS" | sudo -S -p '' "$@"; }

sud install -m 755 /tmp/powersvx-disk-guard.sh /usr/local/sbin/powersvx-disk-guard
echo "POWERSVX_DIR=$RD" | sud tee /etc/default/powersvx-disk-guard >/dev/null
echo "15 * * * * root . /etc/default/powersvx-disk-guard 2>/dev/null; /usr/local/sbin/powersvx-disk-guard" | sud tee /etc/cron.d/powersvx-disk-guard >/dev/null
# Also copy into tree if present
if [ -d "$RD/deploy/linux" ]; then
  sud cp /tmp/powersvx-disk-guard.sh "$RD/deploy/linux/disk-guard.sh"
  sud chmod 755 "$RD/deploy/linux/disk-guard.sh"
fi

echo "=== BEFORE ==="
df -h / | tail -1
sud journalctl --disk-usage 2>/dev/null || true

# First-time standardize: hard prune unused images/cache + journal 1G
sud bash -c 'DISK_GUARD_PCT=0 POWERSVX_DIR='"$RD"' /usr/local/sbin/powersvx-disk-guard' || true
# Force hard docker prune once (script only hard-prunes when over threshold)
if command -v docker >/dev/null 2>&1; then
  sud docker image prune -af >/dev/null 2>&1 || true
  sud docker builder prune -af >/dev/null 2>&1 || true
fi

echo "=== AFTER ==="
df -h / | tail -1
sud journalctl --disk-usage 2>/dev/null || true
sud cat /etc/systemd/journald.conf.d/powersvx-size.conf 2>/dev/null || sud cat /etc/systemd/journald.conf.d/size.conf 2>/dev/null || echo 'no journal conf'
sud docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | head -10 || true
'''


def apply_one(h: dict) -> str:
    name, ip = h["name"], h["ip"]
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            ip,
            username=h["user"],
            password=h["password"],
            port=h["port"],
            timeout=25,
            allow_agent=False,
            look_for_keys=False,
        )
        sftp = c.open_sftp()
        with sftp.file("/tmp/powersvx-disk-guard.sh", "w") as f:
            f.write(SCRIPT)
        with sftp.file("/tmp/powersvx-hygiene-apply.sh", "w") as f:
            f.write(REMOTE_APPLY)
        sftp.chmod("/tmp/powersvx-disk-guard.sh", 0o755)
        sftp.chmod("/tmp/powersvx-hygiene-apply.sh", 0o755)
        sftp.close()

        cmd = f"bash /tmp/powersvx-hygiene-apply.sh {h['password']!r} {h['remote_dir']!r}"
        _, o, e = c.exec_command(cmd, timeout=600)
        out = (o.read() + e.read()).decode("utf-8", "replace")
        c.close()
        # redact password if echoed
        out = out.replace(h["password"], "***")
        return f"OK {name} ({ip})\n{out[-2500:]}"
    except Exception as ex:
        return f"FAIL {name} ({ip}): {ex}"


def main():
    hs = hosts()
    print(f"Applying hygiene to {len(hs)} hosts…")
    # sequential is safer for many SSH; parallel with small workers
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(apply_one, h): h["name"] for h in hs}
        for fut in as_completed(futs):
            print("\n" + "=" * 60)
            print(fut.result())


if __name__ == "__main__":
    main()
