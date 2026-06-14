"""Built-in steganalysis suite.

Runs three classical LSB-detection algorithms against a carrier video and
reports per-test detection scores plus a verdict. None of these are state of
the art -- they're the same family of detectors a SOC analyst would reach for
first. If FrameCourier carriers pass them comfortably, you have an honest
baseline; if they don't, that's something to actually fix.

Detectors implemented:
  * chi-square LSB pair test (Pfitzmann/Westfeld 1999)
  * Sample-pair analysis (Dumitrescu/Wu/Wang 2002, simplified scalar form)
  * RS analysis-like flipping divergence (Fridrich/Goljan 2001, simplified)

The implementations are deliberately self-contained and small so they're easy
to audit and to swap out for a stronger library (aletheia, StegExpose) without
changing the rest of the codebase.
"""

import json
import math
import subprocess
from pathlib import Path

import numpy as np

from pathlib import Path

from . import stego
from .ffmpeg_tools import ffmpeg_path, ffprobe_path


# ---------------------------------------------------------------------------
# Sampling helpers
# ---------------------------------------------------------------------------


def _probe(path):
    cmd = [
        ffprobe_path(), "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height,nb_frames,duration,r_frame_rate",
        "-of", "json",
        str(path),
    ]
    out = subprocess.run(cmd, check=True, stdout=subprocess.PIPE).stdout
    s = json.loads(out.decode("utf-8"))["streams"][0]
    width = int(s["width"])
    height = int(s["height"])
    nb_frames = s.get("nb_frames")
    if nb_frames and str(nb_frames).isdigit():
        frame_count = int(nb_frames)
    else:
        try:
            num, den = s.get("r_frame_rate", "30/1").split("/")
            fps = (int(num) / int(den)) if int(den) else 30.0
        except Exception:
            fps = 30.0
        frame_count = max(1, int(round(float(s.get("duration", 0) or 0.0) * fps)))
    return width, height, frame_count


def _read_frames(path, width, height, max_frames):
    """Return up to ``max_frames`` raw yuv420p frames as a list of numpy uint8 arrays."""
    frame_size = width * height * 3 // 2
    cmd = [
        ffmpeg_path(), "-v", "error",
        "-i", str(path),
        "-map", "0:v:0",
        "-frames:v", str(max_frames),
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


# ---------------------------------------------------------------------------
# Detector 1: chi-square LSB pair (Pfitzmann/Westfeld)
# ---------------------------------------------------------------------------


def chi_square(plane):
    """Return (chi, df, stego_likelihood) for one 1-D numpy uint8 array.

    Counts byte values pair-wise (0/1, 2/3, ...). For natural images, count[2k] >>
    count[2k+1] is the norm. LSB embedding pushes the two counts toward equality
    inside each pair, which the chi-square test detects."""
    counts = np.bincount(plane, minlength=256)
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
        return chi, df, 0.0
    p_clean = math.erfc(math.sqrt(chi / 2.0) - math.sqrt(2.0 * df - 1.0) + 1e-12) / 2.0
    p_clean = max(0.0, min(1.0, p_clean))
    return chi, df, 1.0 - p_clean


# ---------------------------------------------------------------------------
# Detector 2: sample-pair analysis (simplified scalar form)
# ---------------------------------------------------------------------------


def sample_pair(plane):
    """Simplified sample-pair: count adjacent pairs (a,b) and split into four
    relations depending on whether (a,b) are "close" (|a-b| <= 1) and the
    parity of a. For a clean image the ratios are stable; LSB hiding biases
    them. Returns a probability-like score in [0, 1]."""
    if len(plane) < 4:
        return 0.0
    a = plane[:-1].astype(np.int16)
    b = plane[1:].astype(np.int16)
    diff = b - a

    # P: |b-a| == 1 and a is even (transitions consistent with LSB flips)
    p_mask = (np.abs(diff) == 1) & ((a & 1) == 0)
    p = int(p_mask.sum())

    # Q: |b-a| == 1 and a is odd
    q_mask = (np.abs(diff) == 1) & ((a & 1) == 1)
    q = int(q_mask.sum())

    # X: b-a == 0
    x = int((diff == 0).sum())

    # Y: a == b in upper bits and not equal in LSB (|diff|==1 already in P+Q)
    y = p + q

    total = max(1, x + y + 1)
    if y == 0:
        return 0.0

    # Heuristic embedding-rate estimator: ratio of "mixed" pairs vs total.
    # For an unmodified natural image: y_ratio is small (most adjacent pixels are exactly equal in chunked regions).
    # LSB embedding raises y_ratio toward ~0.5 in modified regions.
    y_ratio = y / total
    # Map y_ratio to a likelihood: clean covers around 0.05--0.20; stego hides usually push past 0.30.
    score = max(0.0, min(1.0, (y_ratio - 0.20) / 0.30))
    return score


# ---------------------------------------------------------------------------
# Detector 3: RS-style flipping divergence (Fridrich/Goljan, simplified)
# ---------------------------------------------------------------------------


def rs_divergence(plane):
    """Simplified RS analysis. Compute a 'smoothness' score on small blocks of
    the plane and on the same blocks after applying an F1 LSB flip
    (val ^ 1). For natural images, smoothness DECREASES under F1 flips. For
    LSB-modified planes the two are closer, which the RS detector amplifies.

    Returns a value in [0, 1] where higher = more stego evidence."""
    block = 16
    n = (len(plane) // block) * block
    if n < block * 4:
        return 0.0
    arr = plane[:n].astype(np.int16).reshape(-1, block)
    flipped = (arr ^ 1)

    def smoothness(x):
        return np.abs(np.diff(x, axis=1)).sum(axis=1)

    s_orig = smoothness(arr)
    s_flip = smoothness(flipped)
    diff = s_orig - s_flip
    pos = int((diff > 0).sum())
    neg = int((diff < 0).sum())
    eq = int((diff == 0).sum())
    total = max(1, pos + neg + eq)
    # Clean image: pos >> neg. LSB stego: pos ~= neg.
    if pos + neg == 0:
        return 0.0
    skew = (pos - neg) / (pos + neg)
    # skew near 1 = clean; near 0 = stego.
    score = max(0.0, min(1.0, 1.0 - abs(skew)))
    return score


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyse_frames(frames, width, height):
    if not frames:
        return {"frames_tested": 0}
    y_size = width * height
    per_frame = []
    chi_scores = []
    sp_scores = []
    rs_scores = []
    for arr in frames:
        y = arr[:y_size]
        chi, df, chi_like = chi_square(y)
        sp = sample_pair(y)
        rs = rs_divergence(y)
        per_frame.append({"chi_likelihood": chi_like, "sample_pair": sp, "rs_divergence": rs})
        chi_scores.append(chi_like)
        sp_scores.append(sp)
        rs_scores.append(rs)
    return {
        "frames_tested": len(frames),
        "chi_square": {"mean": float(np.mean(chi_scores)), "max": float(np.max(chi_scores))},
        "sample_pair": {"mean": float(np.mean(sp_scores)), "max": float(np.max(sp_scores))},
        "rs_divergence": {"mean": float(np.mean(rs_scores)), "max": float(np.max(rs_scores))},
        "per_frame": per_frame,
    }


def analyse(path, max_frames=8, run_external_tools=False):
    width, height, _ = _probe(path)
    frames = _read_frames(path, width, height, max_frames)
    out = {
        "path": str(path),
        "width": width,
        "height": height,
        "results": analyse_frames(frames, width, height),
    }
    if run_external_tools:
        out["external"] = run_external(path, max_frames=min(max_frames, 4))
    return out


def verdict(results):
    """Combine the three detector means into a single 'detection probability'
    in [0, 1]. Equal weights for now."""
    if not results.get("frames_tested"):
        return 0.0
    chi = results["chi_square"]["mean"]
    sp = results["sample_pair"]["mean"]
    rs = results["rs_divergence"]["mean"]
    return float(np.mean([chi, sp, rs]))


# ---------------------------------------------------------------------------
# External tool adapters
# ---------------------------------------------------------------------------


def _which(name):
    import shutil
    return shutil.which(name)


def external_available():
    return {
        "stegdetect": _which("stegdetect"),
        "aletheia": _which("aletheia"),
    }


def run_external(path, max_frames=2):
    """Invoke any installed external steganalysis tools and capture their stdout.

    Frames are exported to PNG so the typical image-domain tools (stegdetect /
    aletheia) can chew on them. Output is a dict keyed by tool name.
    """
    import subprocess
    import tempfile
    avail = external_available()
    results = {}
    tools = {k: v for k, v in avail.items() if v}
    if not tools:
        return {"available": avail, "results": {}}
    width, height, _ = _probe(path)
    with tempfile.TemporaryDirectory() as td:
        png_pattern = Path(td) / "f%03d.png"
        cmd = [
            ffmpeg_path(), "-v", "error", "-y",
            "-i", str(path),
            "-map", "0:v:0",
            "-frames:v", str(max_frames),
            str(png_pattern),
        ]
        subprocess.run(cmd, check=True)
        pngs = sorted(Path(td).glob("f*.png"))
        if not pngs:
            return {"available": avail, "results": {}}
        for tool, exe in tools.items():
            outs = []
            for png in pngs:
                try:
                    if tool == "stegdetect":
                        proc = subprocess.run([exe, "-t", "joa", str(png)], capture_output=True, text=True, timeout=60)
                    else:  # aletheia
                        proc = subprocess.run([exe, "auto", str(png)], capture_output=True, text=True, timeout=60)
                    outs.append({"file": png.name, "rc": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()})
                except Exception as exc:
                    outs.append({"file": png.name, "error": str(exc)})
            results[tool] = outs
    return {"available": avail, "results": results}
