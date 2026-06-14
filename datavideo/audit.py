"""Privacy-respecting append-only audit log.

Opt-in. Disabled unless the environment variable ``FRAMECOURIER_AUDIT_LOG`` is
set to a writable file path. Each embed and extract appends a single JSON line:

    {"ts": "2025-…", "op": "embed", "mode": "stego-shuffled", "crypto": "aes-gcm",
     "ecc": "none", "payload_sha256": "ab…", "carrier_path": "…", "bytes": 8005}

The audit log NEVER contains passphrases, private keys, or plaintext bytes.
SHA-256 fingerprints of the plaintext and the carrier file are recorded so the
operator can later verify that the file they have matches a recorded operation.

``framecourier audit`` reads and pretty-prints the log; ``--filter`` accepts a
substring that must appear in the JSON line.
"""

import json
import os
import time
from pathlib import Path

ENV_VAR = "FRAMECOURIER_AUDIT_LOG"


def log_path():
    raw = os.environ.get(ENV_VAR)
    if not raw:
        # Fall back to the optional config file's audit_log field.
        try:
            from . import config as _config
            raw = _config.get("audit_log")
        except Exception:
            raw = None
    if not raw:
        return None
    return Path(os.path.expanduser(raw))


def is_enabled():
    return log_path() is not None


def _carrier_sha256(path):
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def append(*, op, metadata, carrier_path=None):
    """Append a JSON line summarising an embed or extract operation. Silently
    returns if the audit log is not enabled."""
    target = log_path()
    if target is None:
        return
    payload = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z") or time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "op": op,
        "mode": metadata.get("mode"),
        "crypto": metadata.get("crypto"),
        "kdf": metadata.get("kdf"),
        "ecc": metadata.get("ecc"),
        "payload_sha256": metadata.get("sha256"),
        "payload_bytes": metadata.get("payload_size") or metadata.get("file_size"),
        "stored_bytes": metadata.get("stored_size"),
        "carrier": str(carrier_path) if carrier_path else None,
        "carrier_sha256": _carrier_sha256(carrier_path),
    }
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, separators=(",", ":")) + "\n")
    except Exception:
        # Audit logging never blocks the primary operation.
        pass


def read(filter_substring=None, limit=None):
    target = log_path()
    if target is None or not target.exists():
        return []
    rows = []
    with open(target, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue
            if filter_substring and filter_substring.lower() not in line.lower():
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    if limit:
        rows = rows[-limit:]
    return rows
