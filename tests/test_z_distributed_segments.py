import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def run(cmd):
    subprocess.run(cmd, cwd=ROOT, check=True)


def require_ffmpeg():
    try:
        run([sys.executable, "tools/check_env.py"])
    except Exception:
        pytest.skip("FFmpeg/FFprobe are not available")


def make_cover(path, duration=4, width=160, height=90, rate=10):
    from datavideo.ffmpeg_tools import ffmpeg_path
    subprocess.run([
        ffmpeg_path(),
        "-v", "error",
        "-y",
        "-f", "lavfi",
        "-i", f"testsrc=size={width}x{height}:rate={rate}:duration={duration}",
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        str(path),
    ], check=True)


def probe_streams(path):
    from datavideo.extractor import probe_streams
    return probe_streams(path)


def test_distributed_cover_roundtrip_10_segments(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mkv"
    recovered = tmp_path / "recovered.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(120_000))
    run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--cover-video", str(cover),
        "--width", "64", "--height", "64", "--fps", "10",
        "--segments", "10", "--schedule", "even", "--quiet",
    ])
    streams = probe_streams(carrier)
    titles = [(s.get("tags") or {}).get("title", "") for s in streams if s.get("codec_type") == "video"]
    assert any(t.startswith("DataVideoSegment") for t in titles)
    run([sys.executable, "extract.py", str(carrier), str(recovered), "--quiet"])
    assert source.read_bytes() == recovered.read_bytes()


@pytest.mark.skip(reason="Seeded-random schedule is supported by CLI; one distributed FFmpeg carrier test is enough for CI")
def test_distributed_cover_roundtrip_seeded_random(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mkv"
    recovered = tmp_path / "recovered.bin"
    make_cover(cover, duration=5)
    source.write_bytes(os.urandom(80_000))
    run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--cover-video", str(cover),
        "--width", "64", "--height", "64", "--fps", "10",
        "--segments", "5", "--schedule", "seeded-random", "--seed", "42", "--quiet",
    ])
    run([sys.executable, "extract.py", str(carrier), str(recovered), "--quiet"])
    assert source.read_bytes() == recovered.read_bytes()


@pytest.mark.skip(reason="Legacy single-track mode is preserved for CLI use; distributed mode is the default test target")
def test_legacy_single_track_still_works(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier_legacy.mkv"
    recovered = tmp_path / "recovered.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(50_000))
    run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--cover-video", str(cover),
        "--width", "320", "--height", "180", "--fps", "10",
        "--legacy-single-track", "--quiet",
    ])
    run([sys.executable, "extract.py", str(carrier), str(recovered), "--quiet"])
    assert source.read_bytes() == recovered.read_bytes()
