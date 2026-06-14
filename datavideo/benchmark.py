"""Quality benchmarks: PSNR + SSIM of cover vs. carrier, capacity report.

We delegate the heavy lifting to FFmpeg's built-in ``psnr`` and ``ssim`` filters
because the math is well-validated there and we already require FFmpeg. The
filters write summary lines to stderr which we parse.
"""

import re
import subprocess

from . import stego
from .ffmpeg_tools import ffmpeg_path


def _run_filter(cover, carrier, filter_chain):
    cmd = [
        ffmpeg_path(),
        "-v", "info",
        "-i", str(cover),
        "-i", str(carrier),
        "-lavfi", filter_chain,
        "-f", "null", "-",
    ]
    result = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    return result.stderr.decode("utf-8", errors="replace")


_PSNR_LINE = re.compile(r"PSNR.+average:(\S+).+min:(\S+).+max:(\S+)", re.IGNORECASE)
_SSIM_LINE = re.compile(r"SSIM.+All:(\S+)", re.IGNORECASE)


def psnr(cover, carrier):
    out = _run_filter(cover, carrier, "[0:v][1:v]psnr")
    m = _PSNR_LINE.search(out)
    if not m:
        return None
    return {"average_db": _to_float(m.group(1)), "min_db": _to_float(m.group(2)), "max_db": _to_float(m.group(3))}


def ssim(cover, carrier):
    out = _run_filter(cover, carrier, "[0:v][1:v]ssim")
    m = _SSIM_LINE.search(out)
    if not m:
        return None
    return {"all": _to_float(m.group(1))}


def _to_float(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def capacity_summary(width, height, frame_count):
    per_frame_bytes = stego.lsb_byte_capacity_per_frame(width, height)
    return {
        "width": width,
        "height": height,
        "frames": frame_count,
        "per_frame_bytes": per_frame_bytes,
        "total_bytes": per_frame_bytes * frame_count,
    }


def benchmark(cover, carrier, width, height, frame_count):
    return {
        "cover": str(cover),
        "carrier": str(carrier),
        "psnr": psnr(cover, carrier),
        "ssim": ssim(cover, carrier),
        "capacity": capacity_summary(width, height, frame_count),
    }
