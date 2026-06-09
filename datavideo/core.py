import hashlib
import json
import math
import os
import struct
from datetime import datetime, timezone
from pathlib import Path

MAGIC = b"DVF1"
VERSION = 1
CHANNELS = 3
PIXEL_FORMAT = "bgr24"
DEFAULT_WIDTH = 1920
DEFAULT_HEIGHT = 1080
DEFAULT_FPS = 30
DEFAULT_HEADER_BYTES = 65536


def frame_bytes(width, height):
    return width * height * CHANNELS


def sha256_file(path, chunk_size=8388608):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def calculate_total_frames(file_size, width, height, header_bytes):
    per_frame = frame_bytes(width, height)
    if header_bytes >= per_frame:
        raise ValueError("Header reservation must be smaller than one frame")
    first_payload = per_frame - header_bytes
    if file_size <= first_payload:
        return 1
    return 1 + math.ceil((file_size - first_payload) / per_frame)


def make_metadata(input_path, width, height, fps, header_bytes, file_hash):
    size = os.path.getsize(input_path)
    total_frames = calculate_total_frames(size, width, height, header_bytes)
    per_frame = frame_bytes(width, height)
    return {
        "magic": MAGIC.decode("ascii"),
        "version": VERSION,
        "codec": "ffv1",
        "container": "matroska",
        "pixel_format": PIXEL_FORMAT,
        "channels": CHANNELS,
        "width": width,
        "height": height,
        "fps": fps,
        "header_bytes": header_bytes,
        "frame_bytes": per_frame,
        "first_frame_payload_bytes": per_frame - header_bytes,
        "data_bytes_per_full_frame": per_frame,
        "source_file_name": Path(input_path).name,
        "file_size": size,
        "sha256": file_hash,
        "total_frames": total_frames,
        "created_utc": datetime.now(timezone.utc).isoformat()
    }


def pack_header(metadata, header_bytes):
    raw = json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
    required = len(MAGIC) + 4 + len(raw)
    if required > header_bytes:
        raise ValueError("Metadata is larger than reserved header area")
    out = MAGIC + struct.pack(">I", len(raw)) + raw
    out += b"\x00" * (header_bytes - len(out))
    return out


def parse_header(frame_data):
    if len(frame_data) < 8:
        raise ValueError("Frame is too small to contain a DataVideo header")
    if frame_data[:4] != MAGIC:
        raise ValueError("Bad DataVideo magic")
    raw_len = struct.unpack(">I", frame_data[4:8])[0]
    if raw_len <= 0 or raw_len > len(frame_data) - 8:
        raise ValueError("Invalid DataVideo metadata size")
    raw = frame_data[8:8 + raw_len]
    metadata = json.loads(raw.decode("utf-8"))
    if metadata.get("magic") != MAGIC.decode("ascii"):
        raise ValueError("Invalid DataVideo metadata magic")
    if metadata.get("version") != VERSION:
        raise ValueError("Unsupported DataVideo version")
    return metadata


def pad_frame(data, expected_size):
    if len(data) > expected_size:
        raise ValueError("Frame data is larger than frame capacity")
    if len(data) == expected_size:
        return data
    return data + b"\x00" * (expected_size - len(data))
