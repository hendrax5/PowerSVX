#!/usr/bin/env python3
"""Load ops/vault.local.yaml credentials (never print secrets)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
VAULT_PATH = ROOT / "ops" / "vault.local.yaml"
INV_PATH = ROOT / "ops" / "inventory.local.yaml"


def load_vault(path: Path = VAULT_PATH) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"missing {path} — copy ops/vault.example.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    creds = data.get("credentials") or {}
    if not isinstance(creds, dict):
        raise ValueError("vault.credentials must be a mapping")
    return creds


def cred(name: str, vault: dict[str, Any] | None = None) -> dict[str, str]:
    v = vault if vault is not None else load_vault()
    if name not in v:
        raise KeyError(f"vault credential {name!r} not found")
    c = v[name] or {}
    return {
        "user": str(c.get("user") or ""),
        "password": str(c.get("password") or ""),
    }


def host_ssh(host_row: dict[str, Any], vault: dict[str, Any] | None = None) -> tuple[str, str]:
    """Return (user, password) for a host row."""
    v = vault if vault is not None else load_vault()
    user = str(host_row.get("ssh_user") or "")
    if host_row.get("ssh_vault"):
        c = cred(str(host_row["ssh_vault"]), v)
        return c["user"] or user, c["password"]
    return user, str(host_row.get("ssh_password") or "")


def find_host(query: str) -> dict[str, Any]:
    inv = yaml.safe_load(INV_PATH.read_text(encoding="utf-8")) or {}
    q = query.strip().lower()
    for h in inv.get("hosts") or []:
        names = [str(h.get("name", "")), str(h.get("ip", ""))]
        names += [str(a) for a in (h.get("aliases") or [])]
        if q in {n.lower() for n in names if n}:
            return h
    raise KeyError(f"host not found: {query}")


if __name__ == "__main__":
    # Safe CLI: list credential *names* only
    names = sorted(load_vault().keys())
    print("vault keys:", ", ".join(names))
