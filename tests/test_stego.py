import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def run(cmd, env=None):
    subprocess.run(cmd, cwd=ROOT, check=True, env=env)


def require_ffmpeg():
    try:
        run([sys.executable, "tools/check_env.py"])
    except Exception:
        pytest.skip("FFmpeg/FFprobe are not available")


def make_cover(path, duration=4, width=320, height=240, rate=15):
    from datavideo.ffmpeg_tools import ffmpeg_path
    subprocess.run([
        ffmpeg_path(),
        "-v", "error", "-y",
        "-f", "lavfi",
        "-i", f"testsrc2=size={width}x{height}:rate={rate}:duration={duration}",
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        str(path),
    ], check=True)


def probe_streams(path):
    from datavideo.ffmpeg_tools import ffprobe_path
    result = subprocess.run(
        [ffprobe_path(), "-v", "error", "-show_streams", "-of", "json", str(path)],
        check=True, stdout=subprocess.PIPE,
    )
    return json.loads(result.stdout.decode("utf-8")).get("streams") or []


def test_stego_plain_roundtrip(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mp4"
    recovered = tmp_path / "recovered.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(20_000))
    run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--mode", "stego",
        "--cover-video", str(cover),
        "--quiet",
    ])
    run([sys.executable, "extract.py", str(carrier), str(recovered), "--quiet"])
    assert source.read_bytes() == recovered.read_bytes()


def test_stego_encrypted_roundtrip(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mp4"
    recovered = tmp_path / "recovered.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(15_000))
    env = os.environ.copy()
    env["FC_STEGO_PASS"] = "stego-roundtrip-pass"
    run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--mode", "stego",
        "--cover-video", str(cover),
        "--password-env", "FC_STEGO_PASS",
        "--quiet",
    ], env=env)
    run([
        sys.executable, "extract.py", str(carrier), str(recovered),
        "--password-env", "FC_STEGO_PASS",
        "--quiet",
    ], env=env)
    assert source.read_bytes() == recovered.read_bytes()


def test_stego_carrier_looks_like_normal_h264(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mp4"
    make_cover(cover)
    source.write_bytes(os.urandom(10_000))
    run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--mode", "stego",
        "--cover-video", str(cover),
        "--quiet",
    ])
    streams = probe_streams(carrier)
    video_streams = [s for s in streams if s.get("codec_type") == "video"]
    assert len(video_streams) == 1, f"Stego carrier must have exactly one video stream, got {len(video_streams)}"
    vs = video_streams[0]
    assert vs.get("codec_name") == "h264", f"Stego carrier must use H.264, got {vs.get('codec_name')}"
    assert vs.get("pix_fmt") == "yuv420p", f"Stego carrier must use yuv420p, got {vs.get('pix_fmt')}"
    all_tags = {}
    for s in streams:
        for k, v in (s.get("tags") or {}).items():
            all_tags[k.lower()] = str(v).lower()
    flat = " ".join(f"{k}={v}" for k, v in all_tags.items())
    assert "datavideo" not in flat
    assert "dvs_" not in flat
    assert "framecourier" not in flat


def test_stego_wrong_password_fails(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mp4"
    recovered = tmp_path / "recovered.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(5_000))
    env = os.environ.copy()
    env["FC_PASS_GOOD"] = "right-password"
    env["FC_PASS_BAD"] = "wrong-password"
    run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--mode", "stego",
        "--cover-video", str(cover),
        "--password-env", "FC_PASS_GOOD",
        "--quiet",
    ], env=env)
    result = subprocess.run([
        sys.executable, "extract.py", str(carrier), str(recovered),
        "--password-env", "FC_PASS_BAD",
        "--quiet",
    ], cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode != 0
    combined = (result.stdout + result.stderr).lower()
    assert "sha256" in combined or "wrong password" in combined


def test_stego_capacity_check(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mp4"
    make_cover(cover, duration=1, width=160, height=120, rate=10)
    source.write_bytes(os.urandom(200_000))
    result = subprocess.run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--mode", "stego",
        "--cover-video", str(cover),
        "--quiet",
    ], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0, "Embedding a too-large payload should fail"
    combined = (result.stdout + result.stderr).lower()
    assert "capacity" in combined or "too large" in combined
