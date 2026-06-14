"""Phase 9 tests: bulk-embed / bulk-extract, why, make-cover."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def require_ffmpeg():
    try:
        subprocess.run([sys.executable, "tools/check_env.py"], cwd=ROOT, check=True)
    except Exception:
        pytest.skip("FFmpeg/FFprobe are not available")


def test_make_cover_writes_valid_video(tmp_path):
    require_ffmpeg()
    out = tmp_path / "cover.mp4"
    subprocess.run([sys.executable, "framecourier.py", "make-cover", str(out),
                    "--filter", "testsrc2",
                    "--width", "320", "--height", "240", "--fps", "10", "--duration", "2"],
                   cwd=ROOT, check=True)
    assert out.exists() and out.stat().st_size > 0

    # ffprobe should report one h264 yuv420p stream.
    from datavideo.ffmpeg_tools import ffprobe_path
    import json as _json
    info = subprocess.run([ffprobe_path(), "-v", "error", "-show_streams", "-of", "json", str(out)],
                          capture_output=True, check=True).stdout
    data = _json.loads(info.decode("utf-8"))
    video_streams = [s for s in data["streams"] if s.get("codec_type") == "video"]
    assert len(video_streams) == 1
    assert video_streams[0]["codec_name"] == "h264"
    assert video_streams[0]["pix_fmt"] == "yuv420p"


def test_make_cover_refuses_overwrite_without_force(tmp_path):
    require_ffmpeg()
    out = tmp_path / "cover.mp4"
    out.write_text("not a video")  # placeholder
    result = subprocess.run([sys.executable, "framecourier.py", "make-cover", str(out)],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0
    assert "exists" in (result.stdout + result.stderr).lower()


def test_why_lists_all_when_no_arg():
    out = subprocess.run([sys.executable, "framecourier.py", "why"],
                         cwd=ROOT, capture_output=True, check=True).stdout
    text = out.decode("utf-8")
    for key in ("SHA-256 mismatch", "Payload too large", "FFmpeg encoder failed"):
        assert key in text


def test_why_explains_specific_error():
    out = subprocess.run([sys.executable, "framecourier.py", "why", "SHA-256 mismatch"],
                         cwd=ROOT, capture_output=True, check=True).stdout
    text = out.decode("utf-8")
    assert "SHA-256 mismatch" in text
    assert "Fix:" in text
    assert "passphrase" in text.lower() or "password" in text.lower()


def test_why_unknown_query_exits_nonzero():
    result = subprocess.run([sys.executable, "framecourier.py", "why", "this-string-is-not-a-known-error-key-x9y8z7"],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0


def test_bulk_embed_and_extract_round_trip(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    subprocess.run([sys.executable, "framecourier.py", "make-cover", str(cover),
                    "--width", "320", "--height", "240", "--fps", "10", "--duration", "2",
                    "--force"], cwd=ROOT, check=True)
    in_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    rec_dir = tmp_path / "rec"
    in_dir.mkdir(); out_dir.mkdir(); rec_dir.mkdir()
    for i in range(3):
        (in_dir / f"payload{i}.bin").write_bytes(os.urandom(800))
    env = os.environ.copy()
    env["FC_BULK"] = "bulk-pass"
    subprocess.run([sys.executable, "framecourier.py", "bulk-embed",
                    str(in_dir), str(out_dir),
                    "--cover-video", str(cover),
                    "--password-env", "FC_BULK"],
                   cwd=ROOT, check=True, env=env)
    carriers = sorted(out_dir.glob("*.mp4"))
    assert len(carriers) == 3
    subprocess.run([sys.executable, "framecourier.py", "bulk-extract",
                    str(out_dir), str(rec_dir),
                    "--password-env", "FC_BULK"],
                   cwd=ROOT, check=True, env=env)
    recovered = sorted(rec_dir.glob("*.bin"))
    assert len(recovered) == 3
    for i in range(3):
        original = (in_dir / f"payload{i}.bin").read_bytes()
        rec = (rec_dir / f"payload{i}.bin").read_bytes()
        assert original == rec, f"bulk roundtrip mismatch on payload{i}"


def test_bulk_embed_reports_failures(tmp_path):
    """A bulk run with one too-large file should still process the others."""
    require_ffmpeg()
    cover = tmp_path / "tiny.mp4"
    # Tiny 1-second cover: capacity ~ 38 KiB total at 320x240
    subprocess.run([sys.executable, "framecourier.py", "make-cover", str(cover),
                    "--width", "160", "--height", "120", "--fps", "10", "--duration", "1",
                    "--force"], cwd=ROOT, check=True)
    in_dir = tmp_path / "in"; out_dir = tmp_path / "out"
    in_dir.mkdir(); out_dir.mkdir()
    (in_dir / "small.bin").write_bytes(os.urandom(200))   # fits
    (in_dir / "huge.bin").write_bytes(os.urandom(200_000)) # too big
    result = subprocess.run([sys.executable, "framecourier.py", "bulk-embed",
                             str(in_dir), str(out_dir),
                             "--cover-video", str(cover),
                             "--crypto", "none"],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0  # bulk does not abort on per-file errors
    assert "Embedded" in result.stdout
    assert "failures=1" in result.stdout
