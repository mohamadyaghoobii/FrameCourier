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


def test_plain_roundtrip(tmp_path):
    require_ffmpeg()
    source = tmp_path / "source.bin"
    video = tmp_path / "data_video.mkv"
    recovered = tmp_path / "recovered.bin"
    source.write_bytes(os.urandom(1_000_000))
    run([sys.executable, "encode.py", str(source), str(video), "--width", "320", "--height", "180", "--fps", "10", "--quiet"])
    run([sys.executable, "decode.py", str(video), str(recovered), "--quiet"])
    assert source.read_bytes() == recovered.read_bytes()


@pytest.mark.skip(reason="Covered by test_z_distributed_segments.py; kept to avoid running multiple FFmpeg carrier builds in low-resource CI")
def test_cover_carrier_roundtrip(tmp_path):
    require_ffmpeg()
    from datavideo.ffmpeg_tools import ffmpeg_path
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mkv"
    recovered = tmp_path / "recovered.bin"
    subprocess.run([
        ffmpeg_path(),
        "-v", "error",
        "-y",
        "-f", "lavfi",
        "-i", "testsrc=size=320x180:rate=10:duration=2",
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        str(cover)
    ], check=True)
    source.write_bytes(os.urandom(1_000_000))
    run([sys.executable, "embed.py", str(source), str(carrier), "--cover-video", str(cover), "--width", "320", "--height", "180", "--fps", "10", "--quiet"])
    run([sys.executable, "extract.py", str(carrier), str(recovered), "--quiet"])
    assert source.read_bytes() == recovered.read_bytes()
