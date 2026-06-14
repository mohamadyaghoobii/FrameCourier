"""Read-only analyser. Probes a video file the way a SOC analyst would.

Returns a structured report:
  * container summary (streams, codec_name, pix_fmt, bitrate)
  * file-size vs. duration sanity (overweight ratio)
  * LSB chi-square test on the first frame's Y plane (cheap, fast, sensitive
    to plaintext LSB hides; encrypted hides typically score in the same band
    as clean covers)
  * v1 / v2 stego magic detection
  * known-FFV1-anomaly detection (distributed / legacy carriers)
"""

import json
import math
import subprocess

import numpy as np

from . import stego
from .ffmpeg_tools import ffmpeg_path, ffprobe_path


def _probe_streams(path):
    cmd = [
        ffprobe_path(), "-v", "error",
        "-show_format", "-show_streams",
        "-of", "json",
        str(path),
    ]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
    return json.loads(result.stdout.decode("utf-8"))


def _decode_first_frame(path, width, height):
    frame_size = width * height * 3 // 2
    cmd = [
        ffmpeg_path(), "-v", "error",
        "-i", str(path),
        "-map", "0:v:0",
        "-frames:v", "1",
        "-f", "rawvideo",
        "-pix_fmt", "yuv420p",
        "-s", f"{width}x{height}",
        "pipe:1",
    ]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if len(result.stdout) < frame_size:
        return None
    return np.frombuffer(result.stdout[:frame_size], dtype=np.uint8)


def chi_square_lsb(arr, sample_size=200_000):
    """Pfitzmann/Westfeld chi-square on LSB pair counts of consecutive byte values.

    For a clean natural image the count of bytes ending in 0 vs. 1 at each
    even-value pair (0/1, 2/3, ...) is heavily skewed. Repeated LSB embedding
    of random bits pushes those counts toward equality, which the chi-square
    test detects. Returns a probability in [0, 1]: higher means more likely to
    contain LSB embedding.
    """
    if sample_size and len(arr) > sample_size:
        sample = arr[:sample_size]
    else:
        sample = arr
    counts = np.bincount(sample, minlength=256)
    chi = 0.0
    df = 0
    for k in range(0, 256, 2):
        n0 = int(counts[k])
        n1 = int(counts[k + 1])
        total = n0 + n1
        if total == 0:
            continue
        expected = total / 2.0
        chi += ((n0 - expected) ** 2 + (n1 - expected) ** 2) / expected
        df += 1
    if df == 0:
        return {"chi": 0.0, "df": 0, "p_clean": 1.0, "stego_likelihood": 0.0}
    p_clean = math.erfc(math.sqrt(chi / 2.0) - math.sqrt(2.0 * df - 1.0) + 1e-12) / 2.0
    p_clean = max(0.0, min(1.0, p_clean))
    return {"chi": chi, "df": df, "p_clean": p_clean, "stego_likelihood": 1.0 - p_clean}


def _bitrate_anomaly(format_section, video_stream):
    try:
        size = int(format_section.get("size", 0))
        duration = float(format_section.get("duration", 0) or 0)
    except (TypeError, ValueError):
        return None
    if duration <= 0:
        return None
    bitrate_bps = (size * 8) / duration
    width = int(video_stream.get("width", 0) or 0)
    height = int(video_stream.get("height", 0) or 0)
    pixels = width * height
    if pixels == 0:
        return {"bitrate_mbps": bitrate_bps / 1e6}
    typical_bits_per_pixel = 0.10
    expected_bps = pixels * 30 * typical_bits_per_pixel
    overweight = bitrate_bps / max(1.0, expected_bps)
    return {
        "bitrate_mbps": bitrate_bps / 1e6,
        "expected_bitrate_mbps": expected_bps / 1e6,
        "overweight_ratio": overweight,
    }


def _detect_stego_magic(first_frame):
    if first_frame is None:
        return None
    magic = stego.reveal_bytes_from_plane(first_frame, 4, offset=0)
    if magic == stego.STEGO_MAGIC_V2:
        return "stego-v2"
    if magic == stego.STEGO_MAGIC_V1:
        return "stego-v1"
    return None


def analyse(path):
    report = {
        "path": str(path),
        "findings": [],
        "container": {},
        "anomalies": {},
    }
    probe = _probe_streams(path)
    fmt = probe.get("format") or {}
    streams = probe.get("streams") or []
    video_streams = [s for s in streams if s.get("codec_type") == "video"]
    audio_streams = [s for s in streams if s.get("codec_type") == "audio"]
    sub_streams = [s for s in streams if s.get("codec_type") == "subtitle"]

    report["container"] = {
        "format_name": fmt.get("format_name"),
        "duration": float(fmt.get("duration") or 0.0),
        "size_bytes": int(fmt.get("size") or 0),
        "video_streams": len(video_streams),
        "audio_streams": len(audio_streams),
        "subtitle_streams": len(sub_streams),
        "video_codecs": [s.get("codec_name") for s in video_streams],
        "video_pix_fmts": [s.get("pix_fmt") for s in video_streams],
    }

    if len(video_streams) > 1:
        report["findings"].append({
            "severity": "high",
            "category": "container",
            "detail": (
                f"{len(video_streams)} video streams in container. Distributed-mode "
                "carrier or unusual container layout."
            ),
        })

    ffv1_streams = [s for s in video_streams if s.get("codec_name") == "ffv1"]
    if ffv1_streams:
        report["findings"].append({
            "severity": "high",
            "category": "container",
            "detail": (
                f"{len(ffv1_streams)} FFV1 (lossless) video stream(s). FFV1 is rare in "
                "casual content. Possible FrameCourier distributed/legacy carrier."
            ),
        })

    primary_video = video_streams[0] if video_streams else None
    if primary_video:
        anomaly = _bitrate_anomaly(fmt, primary_video)
        if anomaly:
            report["anomalies"]["bitrate"] = anomaly
            if anomaly.get("overweight_ratio", 0) >= 3:
                report["findings"].append({
                    "severity": "medium",
                    "category": "bitrate",
                    "detail": (
                        f"Bitrate {anomaly['bitrate_mbps']:.1f} Mbps is {anomaly['overweight_ratio']:.1f}x "
                        "the expected H.264 envelope for this resolution. Consistent with lossless "
                        "H.264 (stego-mode carrier) or high-quality archival."
                    ),
                })

        if primary_video.get("codec_name") == "h264":
            try:
                first_frame = _decode_first_frame(path, int(primary_video["width"]), int(primary_video["height"]))
            except Exception:
                first_frame = None
            magic = _detect_stego_magic(first_frame)
            if magic:
                report["findings"].append({
                    "severity": "critical",
                    "category": "stego-magic",
                    "detail": f"First-frame LSBs start with FrameCourier {magic} magic. Carrier confirmed.",
                })
                report["anomalies"]["stego_magic"] = magic

            if first_frame is not None:
                stride = primary_video.get("width", 0) * primary_video.get("height", 0)
                if stride and stride <= len(first_frame):
                    y_plane = first_frame[:stride]
                    chi = chi_square_lsb(y_plane)
                    report["anomalies"]["chi_square_y"] = chi
                    if chi["stego_likelihood"] >= 0.85:
                        report["findings"].append({
                            "severity": "high",
                            "category": "statistical",
                            "detail": (
                                f"chi-square LSB likelihood {chi['stego_likelihood']:.2%}. "
                                "Y-plane LSBs look modified vs. natural-image baseline."
                            ),
                        })
                    elif chi["stego_likelihood"] >= 0.6:
                        report["findings"].append({
                            "severity": "low",
                            "category": "statistical",
                            "detail": (
                                f"chi-square LSB likelihood {chi['stego_likelihood']:.2%}. "
                                "Suspicious but not conclusive."
                            ),
                        })

    if not report["findings"]:
        report["findings"].append({
            "severity": "info",
            "category": "clean",
            "detail": "No obvious FrameCourier signatures or unusual container shape detected.",
        })

    return report
