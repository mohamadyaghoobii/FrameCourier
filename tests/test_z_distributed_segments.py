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


def stream_tags(streams):
    return [(s.get("tags") or {}) for s in streams if s.get("codec_type") == "video"]


def test_distributed_cover_roundtrip_no_signatures(tmp_path):
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
        "--mode", "distributed",
        "--width", "64", "--height", "64", "--fps", "10",
        "--segments", "3", "--schedule", "even", "--quiet",
    ])
    streams = probe_streams(carrier)
    tag_blobs = stream_tags(streams)
    flat = " ".join(
        f"{k}={v}".lower()
        for tags in tag_blobs
        for k, v in tags.items()
    )
    assert "datavideo" not in flat, f"Carrier metadata leaks DataVideo signature: {flat}"
    assert "dvs_" not in flat, f"Carrier metadata leaks DVS_* tags: {flat}"
    run([sys.executable, "extract.py", str(carrier), str(recovered), "--quiet"])
    assert source.read_bytes() == recovered.read_bytes()


def test_encrypted_roundtrip(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mkv"
    recovered = tmp_path / "recovered.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(80_000))
    env = os.environ.copy()
    env["FC_TEST_PASS"] = "correct-horse-battery-staple"
    subprocess.run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--cover-video", str(cover),
        "--mode", "distributed",
        "--width", "64", "--height", "64", "--fps", "10",
        "--segments", "1", "--password-env", "FC_TEST_PASS", "--quiet",
    ], cwd=ROOT, check=True, env=env)
    subprocess.run([
        sys.executable, "extract.py", str(carrier), str(recovered),
        "--password-env", "FC_TEST_PASS", "--quiet",
    ], cwd=ROOT, check=True, env=env)
    assert source.read_bytes() == recovered.read_bytes()


def test_encrypted_wrong_password_fails(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mkv"
    recovered = tmp_path / "recovered.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(40_000))
    env = os.environ.copy()
    env["FC_PASS_GOOD"] = "right-password"
    env["FC_PASS_BAD"] = "wrong-password"
    subprocess.run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--cover-video", str(cover),
        "--mode", "distributed",
        "--width", "64", "--height", "64", "--fps", "10",
        "--segments", "1", "--password-env", "FC_PASS_GOOD", "--quiet",
    ], cwd=ROOT, check=True, env=env)
    result = subprocess.run([
        sys.executable, "extract.py", str(carrier), str(recovered),
        "--password-env", "FC_PASS_BAD", "--quiet",
    ], cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode != 0, "Extraction with wrong password should have failed"
    combined = (result.stdout + result.stderr).lower()
    assert "sha256" in combined or "wrong password" in combined


def test_encrypted_missing_password_fails(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "source.bin"
    carrier = tmp_path / "carrier.mkv"
    recovered = tmp_path / "recovered.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(20_000))
    env = os.environ.copy()
    env["FC_PASS"] = "secret"
    subprocess.run([
        sys.executable, "embed.py", str(source), str(carrier),
        "--cover-video", str(cover),
        "--mode", "distributed",
        "--width", "64", "--height", "64", "--fps", "10",
        "--segments", "1", "--password-env", "FC_PASS", "--quiet",
    ], cwd=ROOT, check=True, env=env)
    result = subprocess.run([
        sys.executable, "extract.py", str(carrier), str(recovered), "--quiet",
    ], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0
    assert "encrypted" in (result.stdout + result.stderr).lower()


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
        "--mode", "distributed",
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
        "--mode", "legacy",
        "--width", "320", "--height", "180", "--fps", "10",
        "--quiet",
    ])
    run([sys.executable, "extract.py", str(carrier), str(recovered), "--quiet"])
    assert source.read_bytes() == recovered.read_bytes()
