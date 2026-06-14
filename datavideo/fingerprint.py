"""Deterministic carrier fingerprint and diff.

A FrameCourier carrier can be summarised by:
  * file SHA-256 (the canonical identity)
  * container shape (resolution, fps, duration, frame count, codec, pix_fmt)
  * v2 stego header fields (mode, crypto, kdf, ecc, plaintext_sha256, KDF params)
  * presence/absence of a sibling ``.sig`` file and its signer fingerprint

The fingerprint() function returns a dict suitable for json.dumps with sort_keys
(so two runs produce byte-identical JSON for the same carrier). The diff()
function reports field-by-field differences between two fingerprint dicts.
"""

import hashlib
import json
from pathlib import Path

import numpy as np

from . import crypto, ecc, stego
from .stego_carrier import _probe_video, _read_first_frame_bytes, is_stego_carrier


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _signer_summary(sig_path):
    try:
        record = json.loads(Path(sig_path).read_text(encoding="utf-8"))
    except Exception:
        return None
    if record.get("magic") != "FCSIG-v1":
        return None
    return {
        "alg": record.get("alg"),
        "signer_pubkey_b64": record.get("signer_pubkey_b64"),
        "file_sha256_in_sig": record.get("file_sha256"),
    }


def fingerprint(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    info = _probe_video(path)
    out = {
        "path": str(path.resolve()),
        "size_bytes": path.stat().st_size,
        "file_sha256": _sha256_file(path),
        "container": {
            "width": info["width"],
            "height": info["height"],
            "fps": info["fps"],
            "frame_count": info["frame_count"],
            "has_audio": info["has_audio"],
        },
        "stego": None,
        "signature": None,
    }
    if is_stego_carrier(path):
        frame_size = stego.yuv420p_frame_bytes(info["width"], info["height"])
        first = _read_first_frame_bytes(path, info["width"], info["height"], frame_size)
        arr = np.frombuffer(first, dtype=np.uint8).copy()
        magic = stego.reveal_bytes_from_plane(arr, 4, offset=0)
        if magic == stego.STEGO_MAGIC_V2:
            header_bytes = stego.reveal_bytes_from_plane(arr, stego.HEADER_SIZE, offset=0)
            h = stego.parse_stego_header_v2(header_bytes)
            out["stego"] = {
                "version": 2,
                "mode": stego.MODE_NAMES.get(h["mode_id"]),
                "crypto": crypto.LAYER_NAMES.get(h["crypto_id"]),
                "kdf": crypto.KDF_NAMES.get(h["kdf_id"]),
                "ecc": ecc.ECC_NAMES.get(h["ecc_id"]),
                "plaintext_bytes": h["plaintext_len"],
                "stored_bytes": h["stored_len"],
                "plaintext_sha256": h["plaintext_sha256"],
                "pbkdf2_iterations": h["pbkdf2_iterations"],
                "argon2_time": h["argon2_time"],
                "argon2_memory_kb": h["argon2_memory_kb"],
                "argon2_parallelism": h["argon2_parallelism"],
            }
        elif magic == stego.STEGO_MAGIC_V1:
            probe_bytes = stego.reveal_bytes_from_plane(arr, stego.HEADER_ENCRYPTED_BYTES, offset=0)
            h = stego.parse_stego_header(probe_bytes)
            out["stego"] = {
                "version": 1,
                "encrypted": h["encrypted"],
                "payload_bit_length": h["payload_bit_length"],
                "plaintext_sha256": h["plaintext_sha256"],
            }

    sig = Path(str(path) + ".sig")
    if sig.exists():
        out["signature"] = _signer_summary(sig)

    return out


def _flatten(d, prefix=""):
    items = []
    if isinstance(d, dict):
        for k, v in d.items():
            items.extend(_flatten(v, f"{prefix}.{k}" if prefix else k))
    else:
        items.append((prefix, d))
    return items


def diff(a, b):
    """Return a list of (key, a_value, b_value) tuples for fields that differ."""
    flat_a = dict(_flatten(a))
    flat_b = dict(_flatten(b))
    keys = sorted(set(flat_a) | set(flat_b))
    out = []
    for k in keys:
        if flat_a.get(k) != flat_b.get(k):
            out.append((k, flat_a.get(k, "<missing>"), flat_b.get(k, "<missing>")))
    return out
