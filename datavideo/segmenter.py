import hashlib
import json
import math
import os
import random
import struct
import subprocess
import tempfile
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path

from . import crypto
from .core import CHANNELS, DEFAULT_FPS, DEFAULT_HEIGHT, DEFAULT_WIDTH, PIXEL_FORMAT, frame_bytes, pad_frame
from .ffmpeg_tools import ffmpeg_path

SEGMENT_MAGIC = b"\xfc\x46\x43\x02"
LEGACY_SEGMENT_MAGIC = b"DVS1"
SEGMENT_VERSION = 2
DEFAULT_SEGMENT_HEADER_BYTES = 8192


@dataclass(frozen=True)
class SegmentRange:
    index: int
    first_frame: int
    frame_count: int


@dataclass(frozen=True)
class EncodedSegment:
    index: int
    path: Path
    offset_seconds: float
    first_frame: int
    frame_count: int


def payload_capacity(width, height, header_bytes=DEFAULT_SEGMENT_HEADER_BYTES):
    capacity = frame_bytes(width, height) - header_bytes
    if capacity <= 0:
        raise ValueError("Segment header reservation must be smaller than one frame")
    return capacity


def total_data_frames(file_size, width, height, header_bytes=DEFAULT_SEGMENT_HEADER_BYTES):
    cap = payload_capacity(width, height, header_bytes)
    if file_size == 0:
        return 1
    return math.ceil(file_size / cap)


def balanced_segment_ranges(total_frames, requested_segments):
    if requested_segments <= 0:
        raise ValueError("segments must be greater than zero")
    actual_segments = max(1, min(requested_segments, max(1, total_frames)))
    base = total_frames // actual_segments
    extra = total_frames % actual_segments
    ranges = []
    cursor = 0
    for i in range(actual_segments):
        count = base + (1 if i < extra else 0)
        ranges.append(SegmentRange(i, cursor, count))
        cursor += count
    return ranges


def schedule_offsets(segment_count, cover_duration, schedule="even", seed=1337):
    if segment_count <= 0:
        return []
    duration = max(float(cover_duration), 0.0)
    if segment_count == 1:
        return [duration / 2.0]

    safe_end = max(duration, 0.001)
    if schedule == "even":
        return [(safe_end * i) / (segment_count - 1) for i in range(segment_count)]

    if schedule == "center-weighted":
        offsets = []
        for i in range(segment_count):
            x = i / (segment_count - 1)
            y = 0.5 - 0.5 * math.cos(math.pi * x)
            offsets.append(safe_end * y)
        return offsets

    if schedule == "seeded-random":
        rng = random.Random(seed)
        offsets = [rng.random() * safe_end for _ in range(segment_count)]
        offsets.sort()
        return offsets

    raise ValueError("unsupported schedule: " + str(schedule))


def sha256_file(path, chunk_size=8 * 1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def make_frame_header(base_meta, segment_range, global_frame_index, frame_index_in_segment, payload):
    header = dict(base_meta)
    header.update({
        "version": SEGMENT_VERSION,
        "segment_index": segment_range.index,
        "segment_first_global_frame": segment_range.first_frame,
        "segment_frame_count": segment_range.frame_count,
        "global_frame_index": global_frame_index,
        "frame_index_in_segment": frame_index_in_segment,
        "payload_length": len(payload),
        "payload_crc32": zlib.crc32(payload) & 0xffffffff,
    })
    raw = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    header_crc = zlib.crc32(raw) & 0xffffffff
    prefix = SEGMENT_MAGIC + struct.pack(">I", len(raw)) + struct.pack(">I", header_crc) + raw
    header_bytes = int(base_meta["header_bytes"])
    if len(prefix) > header_bytes:
        raise ValueError("Segment frame header is too large")
    return prefix + (b"\x00" * (header_bytes - len(prefix)))


def parse_segment_frame(frame):
    if len(frame) < 12:
        raise ValueError("Frame is too small for a segment header")
    magic = frame[:4]
    if magic != SEGMENT_MAGIC and magic != LEGACY_SEGMENT_MAGIC:
        raise ValueError("Bad segment magic")
    raw_len = struct.unpack(">I", frame[4:8])[0]
    expected_crc = struct.unpack(">I", frame[8:12])[0]
    if raw_len <= 0 or raw_len > len(frame) - 12:
        raise ValueError("Invalid segment header length")
    raw = frame[12:12 + raw_len]
    actual_crc = zlib.crc32(raw) & 0xffffffff
    if actual_crc != expected_crc:
        raise ValueError("Segment header CRC mismatch")
    header = json.loads(raw.decode("utf-8"))
    if int(header.get("version", -1)) not in (1, SEGMENT_VERSION):
        raise ValueError("Unsupported segment version")
    header_bytes = int(header["header_bytes"])
    payload_len = int(header["payload_length"])
    if header_bytes < 12 or header_bytes > len(frame):
        raise ValueError("Invalid segment header_bytes")
    if payload_len < 0 or header_bytes + payload_len > len(frame):
        raise ValueError("Invalid segment payload length")
    payload = frame[header_bytes:header_bytes + payload_len]
    actual_payload_crc = zlib.crc32(payload) & 0xffffffff
    if actual_payload_crc != int(header["payload_crc32"]):
        raise ValueError("Segment payload CRC mismatch")
    return header, payload


def build_segment_encode_command(output_path, width, height, fps):
    return [
        ffmpeg_path(),
        "-v", "error",
        "-y",
        "-f", "rawvideo",
        "-pix_fmt", PIXEL_FORMAT,
        "-s", f"{width}x{height}",
        "-r", str(fps),
        "-i", "pipe:0",
        "-an",
        "-c:v", "ffv1",
        "-level", "3",
        "-g", "1",
        "-slicecrc", "1",
        "-pix_fmt", PIXEL_FORMAT,
        str(output_path),
    ]


def encode_one_segment(input_stream, segment_range, base_meta, output_path, width, height, fps, progress=True):
    per_frame = frame_bytes(width, height)
    cap = payload_capacity(width, height, int(base_meta["header_bytes"]))
    cmd = build_segment_encode_command(output_path, width, height, fps)
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    try:
        for local_index in range(segment_range.frame_count):
            global_index = segment_range.first_frame + local_index
            payload = input_stream.read(cap)
            if payload is None:
                payload = b""
            header = make_frame_header(base_meta, segment_range, global_index, local_index, payload)
            process.stdin.write(pad_frame(header + payload, per_frame))
        process.stdin.close()
        code = process.wait()
        if code != 0:
            raise RuntimeError("FFmpeg segment encoder failed")
    except Exception:
        if process.stdin:
            try:
                process.stdin.close()
            except Exception:
                pass
        process.kill()
        process.wait()
        raise
    if progress:
        print(f"encoded segment {segment_range.index + 1}/{base_meta['total_segments']} frames={segment_range.frame_count}")


def encode_distributed_segments(input_path, output_dir, requested_segments=1, schedule="even", cover_duration=1.0, seed=1337, width=DEFAULT_WIDTH, height=DEFAULT_HEIGHT, fps=DEFAULT_FPS, header_bytes=DEFAULT_SEGMENT_HEADER_BYTES, password=None, progress=True):
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    file_size = os.path.getsize(input_path)
    file_hash = sha256_file(input_path)
    total_frames = total_data_frames(file_size, width, height, header_bytes)
    ranges = balanced_segment_ranges(total_frames, requested_segments)
    offsets = schedule_offsets(len(ranges), cover_duration, schedule=schedule, seed=seed)
    session_id = str(uuid.uuid4())
    file_id = file_hash[:32]
    base_meta = {
        "session_id": session_id,
        "file_id": file_id,
        "file_size": file_size,
        "sha256": file_hash,
        "total_frames": total_frames,
        "total_segments": len(ranges),
        "requested_segments": requested_segments,
        "schedule": schedule,
        "seed": seed,
        "width": width,
        "height": height,
        "fps": fps,
        "channels": CHANNELS,
        "frame_bytes": frame_bytes(width, height),
        "header_bytes": header_bytes,
        "payload_capacity": payload_capacity(width, height, header_bytes),
    }
    enc_obj = None
    if password is not None:
        salt = crypto.new_salt()
        nonce = crypto.new_nonce()
        enc_obj = crypto.encryptor(password, salt, nonce)
        base_meta.update({
            "encrypted": True,
            "kdf": crypto.KDF_NAME,
            "kdf_iterations": crypto.DEFAULT_KDF_ITERATIONS,
            "cipher": crypto.CIPHER_NAME,
            "enc_salt": crypto.b64e(salt),
            "enc_nonce": crypto.b64e(nonce),
        })
    encoded = []
    with open(input_path, "rb") as raw_stream:
        input_stream = crypto.EncryptingReader(raw_stream, enc_obj) if enc_obj else raw_stream
        for segment_range, offset in zip(ranges, offsets):
            seg_path = output_dir / f"_seg_{segment_range.index:05d}.mkv"
            encode_one_segment(input_stream, segment_range, base_meta, seg_path, width, height, fps, progress=progress)
            encoded.append(EncodedSegment(segment_range.index, seg_path, float(offset), segment_range.first_frame, segment_range.frame_count))
    return base_meta, encoded


def temporary_segment_dir(output_path):
    parent = Path(output_path).resolve().parent
    return Path(tempfile.mkdtemp(prefix="datavideo_segments_", dir=str(parent)))
