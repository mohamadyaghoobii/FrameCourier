"""Per-user configuration file.

Read from ``$FRAMECOURIER_CONFIG`` if set, otherwise from
``~/.framecourier/config.json``. The file is plain JSON and *opt-in*: if it
does not exist, FrameCourier behaves exactly as before.

Fields that the CLI consults today (all optional)::

    {
      "default_mode":   "stego-shuffled",
      "default_crypto": "aes-gcm",
      "default_kdf":    "argon2id",
      "default_ecc":    "none",
      "default_cover":  "C:/Users/me/Videos/cover.mp4",
      "default_dir":    "default",
      "audit_log":      "C:/Users/me/.framecourier/audit.log",
      "x264_preset":    "veryfast",
      "adaptive_threshold": 4
    }

A flag on the CLI ALWAYS overrides the config file value. The config file is
itself never written to by FrameCourier except via the explicit
``framecourier config set`` command.
"""

import json
import os
from pathlib import Path

ENV_VAR = "FRAMECOURIER_CONFIG"
KNOWN_FIELDS = {
    "default_mode", "default_crypto", "default_kdf", "default_ecc",
    "default_cover", "default_dir", "audit_log",
    "x264_preset", "adaptive_threshold",
}


def default_path():
    return Path.home() / ".framecourier" / "config.json"


def config_path():
    raw = os.environ.get(ENV_VAR)
    if raw:
        return Path(raw)
    return default_path()


def load():
    path = config_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save(data):
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def get(key, fallback=None):
    return load().get(key, fallback)


def set_(key, value):
    data = load()
    if value is None:
        data.pop(key, None)
    else:
        data[key] = value
    save(data)
    return data
