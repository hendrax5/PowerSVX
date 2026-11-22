#!/usr/bin/env python3
"""
Secure Production Probe & Health Diagnostic for PowerSVX Fleet.
Usage:
  python ops/probe.py [HOST_NAME_OR_IP]
  python ops/probe.py all

Resolves credentials dynamically from ops/vault.local.yaml via ops.vault.
Never hardcodes passwords.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import paramiko
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ops.vault import find_host, host_ssh, load_vault  # noqa: E402

INV_PATH = ROOT / "ops" / "inventory.local.yaml"

DIAGNOSTIC_COMMANDS = [
    ("Docker Containers", "docker ps --format 'table {{.Names}}\t{{.Status}}' | head -12"),
    ("Listening Sockets (:53 / :5353)", "ss -ulnp | grep -E ':53 |:5353 ' | head -8"),
    ("Memory Usage", "free -h | head -2"),
    ("DNS Dig Public (google.com)", "dig @127.0.0.1 -p 53 google.com +time=2 +tries=1 | tail -6"),
    ("DNS Dig Whitelist (bca.co.id)", "dig @127.0.0.1 -p 53 bca.co.id +short +time=2 | head -2"),
    ("DNS Dig Blocked Test", "dig @127.0.0.1 -p 53 gacor80819.bocoranmantap.cfd +short +time=2 | head -2"),
    ("Configured Dataplane mode", "docker inspect powersvx --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -E '^POWERSVX_DNS_DATAPLANE=' || echo 'POWERSVX_DNS_DATAPLANE unset (host default: dnsdist)'"),
    ("PowerSVX API Health", "curl -sS -m 5 http://127.0.0.1:5380/api/v1/health 2>/dev/null || echo 'API unreachable'"),
    ("dnsdist Live Stats", "curl -sS -m 3 -u dontcare:powersvx 'http://127.0.0.1:8083/jsonstat?command=stats' 2>/dev/null | python3 -c \"import sys,json;d=json.load(sys.stdin);ks=['queries','cache-hits','cache-misses','self-answered','downstream-timeouts','servfail-responses','acl-drops','rule-drop','uptime'];print({k:d.get(k) for k in ks})\" 2>/dev/null || echo 'dnsdist stats unreachable'"),
    ("Conntrack Limits", "sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max 2>/dev/null || true"),
    ("Blocklist Meta", "python3 -c \"import json;print(open('/home/hendra/powersvx/data/blocklist/blocklist.meta.json').read())\" 2>/dev/null || cat data/blocklist/blocklist.meta.json 2>/dev/null || echo 'meta missing'"),
]


def probe_single_host(host_row: dict, vault: dict):
    name = host_row.get("name", "unknown")
    ip = host_row.get("ip")
    if not ip:
        print(f"[-] Host {name} has no IP configured, skipping.")
        return

    user, password = host_ssh(host_row, vault)
    if not password:
        print(f"[-] Host {name} ({ip}): No SSH password or vault credential found.")
        return

    port = int(host_row.get("ssh_port") or 22)
    print(f"\n{'='*30} PROBING {name.upper()} ({ip}) {'='*30}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(ip, port=port, username=user, password=password, timeout=15)
        for label, cmd in DIAGNOSTIC_COMMANDS:
            print(f"\n--- [{label}] ---")
            full_cmd = f"sudo -S bash -lc {json.dumps(cmd)}"
            stdin, stdout, stderr = client.exec_command(full_cmd, timeout=30, get_pty=True)
            stdin.write(password + "\n")
            stdin.flush()
            output = stdout.read().decode("utf-8", "replace").replace(password, "***").strip()
            print(output if output else "(no output)")
    except Exception as exc:
        print(f"[!] Error probing {name} ({ip}): {exc}")
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="PowerSVX Remote Node Probe")
    parser.add_argument("target", nargs="?", default="isehat2", help="Host name, IP, or 'all'")
    args = parser.parse_args()

    if not INV_PATH.is_file():
        print(f"[!] Missing {INV_PATH}. Please prepare inventory.local.yaml.")
        sys.exit(1)

    vault = load_vault()
    inv_data = yaml.safe_load(INV_PATH.read_text(encoding="utf-8")) or {}
    hosts = inv_data.get("hosts", [])

    if args.target.lower() == "all":
        prod_hosts = [h for h in hosts if h.get("role") == "production"]
        print(f"Probing all {len(prod_hosts)} production hosts...")
        for h in prod_hosts:
            probe_single_host(h, vault)
    else:
        try:
            h = find_host(args.target)
            probe_single_host(h, vault)
        except KeyError:
            print(f"[!] Target '{args.target}' not found in inventory.")
            sys.exit(1)


if __name__ == "__main__":
    main()
