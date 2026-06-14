"""Cover quality analysis.

Rates a video's suitability as a FrameCourier cover:
  * dimensions / fps / duration / frame count
  * estimated capacity per stego mode
  * texture metric (mean local variance on the Y plane of the first frames)
  * Shannon entropy of Y-plane LSB distribution (proxy for natural noise)
  * bitrate plausibility (lossy-H.264-bitrate-per-pixel-per-second)
  * recommendation for which stego mode best suits this cover

Used by the ``cover-score`` and ``suggest-cover`` CLI commands.
"""

import json
import math
import subprocess
from pathlib import Path

import numpy as np

from . import stego
from .ffmpeg_tools import ffmpeg_path, ffprobe_path


def _probe(path):
    cmd = [
        ffprobe_path(), "-v", "error",
        "-show_format", "-show_streams",
        "-of", "json",
        str(path),
    ]
    return json.loads(subprocess.run(cmd, check=True, stdout=subprocess.PIPE).stdout.decode("utf-8"))


def _decode_first_frames(path, width, height, n):
    frame_size = width * height * 3 // 2
    cmd = [
        ffmpeg_path(), "-v", "error",
        "-i", str(path),
        "-map", "0:v:0",
        "-frames:v", str(n),
        "-f", "rawvideo",
        "-pix_fmt", "yuv420p",
        "-s", f"{width}x{height}",
        "pipe:1",
    ]
    out = subprocess.run(cmd, check=True, stdout=subprocess.PIPE).stdout
    frames = []
    for i in range(0, len(out), frame_size):
        chunk = out[i:i + frame_size]
        if len(chunk) != frame_size:
            break
        frames.append(np.frombuffer(chunk, dtype=np.uint8))
    return frames


def _block_variance(y_plane, width, height, block=8):
    rows = (height // block) * block
    cols = (width // block) * block
    if rows == 0 or cols == 0:
        return 0.0
    img = y_plane[:rows * width].reshape(rows, width)[:, :cols]
    nr = rows // block
    nc = cols // block
    blocks = img.reshape(nr, block, nc, block).swapaxes(1, 2)
    blocks = blocks.astype(np.float32)
    var = blocks.var(axis=(2, 3))
    return float(var.mean())


def _shannon_entropy(values, bits=8):
    counts = np.bincount(values, minlength=1 << bits).astype(np.float64)
    p = counts / counts.sum()
    nz = p > 0
    return float(-(p[nz] * np.log2(p[nz])).sum())


def analyse(path, sample_frames=6):
    p = _probe(path)
    fmt = p.get("format") or {}
    streams = p.get("streams") or []
    video_streams = [s for s in streams if s.get("codec_type") == "video"]
    audio_streams = [s for s in streams if s.get("codec_type") == "audio"]
    if not video_streams:
        raise RuntimeError(f"No video stream in {path}")
    v = video_streams[0]
    width = int(v["width"])
    height = int(v["height"])
    codec = v.get("codec_name")
    pix_fmt = v.get("pix_fmt")
    nb_frames = v.get("nb_frames")
    duration = float(v.get("duration") or fmt.get("duration") or 0.0)
    size_bytes = int(fmt.get("size") or 0)
    bitrate_bps = (size_bytes * 8) / duration if duration > 0 else 0.0
    try:
        num, den = v.get("r_frame_rate", "30/1").split("/")
        fps = (int(num) / int(den)) if int(den) else 30.0
    except Exception:
        fps = 30.0
    if nb_frames and str(nb_frames).isdigit():
        frame_count = int(nb_frames)
    else:
        frame_count = max(1, int(round(duration * fps)))

    frames = _decode_first_frames(path, width, height, sample_frames)
    y_size = width * height
    textures = []
    lsb_entropies = []
    for arr in frames:
        y = arr[:y_size]
        textures.append(_block_variance(y, width, height))
        lsb_entropies.append(_shannon_entropy(y & 1, bits=1))

    mean_texture = float(np.mean(textures)) if textures else 0.0
    mean_lsb_entropy = float(np.mean(lsb_entropies)) if lsb_entropies else 0.0

    cap_per_frame = stego.lsb_byte_capacity_per_frame(width, height) if (width % 2 == 0 and height % 2 == 0) else 0
    seq_capacity = cap_per_frame * frame_count
    # adaptive capacity is bounded by the fraction of bytes whose local variance exceeds threshold
    # (estimated from the texture metric we just measured)
    adaptive_fraction = min(1.0, max(0.05, mean_texture / 400.0))
    adaptive_capacity = int(seq_capacity * adaptive_fraction)

    # bitrate plausibility: typical h264 yuv420p clips run 0.05--0.2 bits per pixel per frame
    bpp_per_frame = bitrate_bps / max(1.0, width * height * fps) if width and height and fps else 0.0
    if bpp_per_frame == 0:
        plausibility = "unknown"
    elif bpp_per_frame < 0.04:
        plausibility = "low"
    elif bpp_per_frame > 0.3:
        plausibility = "very high (matches lossless-style content)"
    else:
        plausibility = "normal"

    score = _score(mean_texture, mean_lsb_entropy, frame_count, plausibility)
    recommend = _recommend_mode(mean_texture, mean_lsb_entropy, frame_count)

    return {
        "path": str(path),
        "format_name": fmt.get("format_name"),
        "width": width,
        "height": height,
        "fps": fps,
        "duration_sec": duration,
        "frame_count": frame_count,
        "size_bytes": size_bytes,
        "bitrate_mbps": bitrate_bps / 1e6,
        "video_codec": codec,
        "video_pix_fmt": pix_fmt,
        "has_audio": bool(audio_streams),
        "mean_block_variance": mean_texture,
        "mean_lsb_entropy_bits": mean_lsb_entropy,
        "bitrate_plausibility": plausibility,
        "capacity_seq_bytes": seq_capacity,
        "capacity_adaptive_bytes": adaptive_capacity,
        "score_0_100": score,
        "recommend_mode": recommend,
    }


def _score(texture, lsb_entropy, frame_count, plausibility):
    # texture: 0 (flat) .. 400+ (very busy)
    t_score = min(100.0, texture * 0.25)
    # lsb_entropy: 0 .. 1.0; we want close to 1.0 (uniform LSBs natural)
    e_score = lsb_entropy * 100
    # plausibility penalty
    plaus_penalty = 0
    if plausibility == "very high (matches lossless-style content)":
        plaus_penalty = 25
    elif plausibility == "low":
        plaus_penalty = 30
    # frame count bonus: more frames = more capacity
    fc_bonus = min(20.0, math.log10(max(1, frame_count)) * 8)
    return float(max(0.0, min(100.0, (t_score + e_score) / 2 - plaus_penalty + fc_bonus)))


def _recommend_mode(texture, lsb_entropy, frame_count):
    if frame_count < 30:
        return ("stego-seq", "Very short cover -- only sequential mode is reliable; capacity is tiny.")
    if texture >= 150 and lsb_entropy >= 0.6:
        return ("stego-adaptive", "High texture + naturally noisy LSBs: adaptive mode hides best here.")
    if lsb_entropy >= 0.4:
        return ("stego-shuffled", "Moderate naturalness; shuffled mode gives the best stealth/capacity trade.")
    return ("stego-seq", "Cover is very smooth (low texture / low LSB entropy); adaptive/shuffled won't gain much. "
                          "Sequential gives max capacity but is easier to detect.")


def rank(folder, pattern="*", sample_frames=4):
    folder = Path(folder)
    files = [p for p in folder.iterdir() if p.is_file() and p.suffix.lower() in (".mp4", ".mkv", ".mov", ".webm", ".avi")]
    rows = []
    for f in files:
        try:
            r = analyse(f, sample_frames=sample_frames)
            rows.append({
                "path": str(f),
                "width": r["width"],
                "height": r["height"],
                "frames": r["frame_count"],
                "duration_sec": r["duration_sec"],
                "bitrate_mbps": r["bitrate_mbps"],
                "texture": r["mean_block_variance"],
                "lsb_entropy": r["mean_lsb_entropy_bits"],
                "capacity_bytes_seq": r["capacity_seq_bytes"],
                "score": r["score_0_100"],
                "recommend_mode": r["recommend_mode"][0],
            })
        except Exception as exc:
            rows.append({"path": str(f), "error": str(exc)})
    rows.sort(key=lambda r: r.get("score", -1.0), reverse=True)
    return rows
