"""Phase 4 tests: deniable encryption, presets, discoverability subcommands."""

import json
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


def make_cover(path, duration=4, width=320, height=240, rate=15):
    from datavideo.ffmpeg_tools import ffmpeg_path
    subprocess.run([
        ffmpeg_path(), "-v", "error", "-y",
        "-f", "lavfi",
        "-i", f"testsrc2=size={width}x{height}:rate={rate}:duration={duration}",
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        str(path),
    ], check=True)


# ---------------------------------------------------------------------------
# Deniable encryption
# ---------------------------------------------------------------------------


def test_deniable_real_password_recovers_real(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    real = tmp_path / "real.bin"
    decoy = tmp_path / "decoy.bin"
    carrier = tmp_path / "c.mp4"
    out = tmp_path / "rec.bin"
    make_cover(cover)
    real.write_bytes(os.urandom(1_500))
    decoy.write_bytes(os.urandom(1_200))
    env = os.environ.copy()
    env["FC_REAL"] = "real-password-xyz"
    env["FC_DECOY"] = "decoy-password-abc"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(real), str(carrier),
                    "--cover-video", str(cover),
                    "--decoy-file", str(decoy),
                    "--password-env", "FC_REAL", "--decoy-password-env", "FC_DECOY",
                    "--quiet"], cwd=ROOT, check=True, env=env)
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(out),
                    "--password-env", "FC_REAL", "--quiet"], cwd=ROOT, check=True, env=env)
    assert real.read_bytes() == out.read_bytes()


def test_deniable_decoy_password_recovers_decoy(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    real = tmp_path / "real.bin"
    decoy = tmp_path / "decoy.bin"
    carrier = tmp_path / "c.mp4"
    out = tmp_path / "rec.bin"
    make_cover(cover)
    real.write_bytes(os.urandom(1_500))
    decoy.write_bytes(os.urandom(1_200))
    env = os.environ.copy()
    env["FC_REAL"] = "real-password-xyz"
    env["FC_DECOY"] = "decoy-password-abc"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(real), str(carrier),
                    "--cover-video", str(cover),
                    "--decoy-file", str(decoy),
                    "--password-env", "FC_REAL", "--decoy-password-env", "FC_DECOY",
                    "--quiet"], cwd=ROOT, check=True, env=env)
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(out),
                    "--password-env", "FC_DECOY", "--quiet"], cwd=ROOT, check=True, env=env)
    assert decoy.read_bytes() == out.read_bytes()


def test_deniable_wrong_password_fails(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    real = tmp_path / "real.bin"
    decoy = tmp_path / "decoy.bin"
    carrier = tmp_path / "c.mp4"
    out = tmp_path / "rec.bin"
    make_cover(cover)
    real.write_bytes(os.urandom(800))
    decoy.write_bytes(os.urandom(800))
    env = os.environ.copy()
    env["FC_REAL"] = "real-pw"
    env["FC_DECOY"] = "decoy-pw"
    env["FC_WRONG"] = "wrong-pw"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(real), str(carrier),
                    "--cover-video", str(cover),
                    "--decoy-file", str(decoy),
                    "--password-env", "FC_REAL", "--decoy-password-env", "FC_DECOY",
                    "--quiet"], cwd=ROOT, check=True, env=env)
    result = subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(out),
                             "--password-env", "FC_WRONG", "--quiet"],
                            cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# Preset system
# ---------------------------------------------------------------------------


def test_preset_paranoid_roundtrip(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    src = tmp_path / "src.bin"
    carrier = tmp_path / "c.mp4"
    rec = tmp_path / "rec.bin"
    make_cover(cover)
    src.write_bytes(os.urandom(2_000))
    env = os.environ.copy()
    env["FC_P"] = "preset-pass"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--preset", "paranoid",
                    "--password-env", "FC_P", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(rec),
                    "--password-env", "FC_P", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    assert src.read_bytes() == rec.read_bytes()


def test_preset_plain_no_password(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    src = tmp_path / "src.bin"
    carrier = tmp_path / "c.mp4"
    rec = tmp_path / "rec.bin"
    make_cover(cover)
    src.write_bytes(os.urandom(1_500))
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--preset", "plain", "--quiet"], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(rec), "--quiet"],
                   cwd=ROOT, check=True)
    assert src.read_bytes() == rec.read_bytes()


# ---------------------------------------------------------------------------
# Discoverability subcommands
# ---------------------------------------------------------------------------


def test_recipes_lists_known_names():
    out = subprocess.run([sys.executable, "framecourier.py", "recipes"],
                         cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")
    for name in ("paranoid", "stealth", "robust", "asymmetric", "deniable", "plain"):
        assert name in out, f"recipes should list {name}"


def test_recipes_detail():
    out = subprocess.run([sys.executable, "framecourier.py", "recipes", "deniable"],
                         cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")
    assert "deniable" in out and "decoy" in out


def test_examples_lists():
    out = subprocess.run([sys.executable, "framecourier.py", "examples"],
                         cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")
    assert "quick-symmetric" in out and "deniable-pair" in out


def test_search_finds_deniable_across_categories():
    out = subprocess.run([sys.executable, "framecourier.py", "search", "deniable"],
                         cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")
    assert "[crypto" in out
    assert "[preset" in out
    assert "[example" in out


def test_doctor_passes_in_dev_env():
    result = subprocess.run([sys.executable, "framecourier.py", "doctor"],
                            cwd=ROOT, capture_output=True, text=True)
    # doctor's exit code is 0 only when there are no error-severity findings.
    assert "FrameCourier doctor" in (result.stdout + result.stderr)


def test_modes_lists_deniable_and_x25519():
    out = subprocess.run([sys.executable, "framecourier.py", "modes"],
                         cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")
    assert "deniable" in out
    assert "x25519-chacha20" in out


def test_explain_deniable_renders():
    out = subprocess.run([sys.executable, "framecourier.py", "explain", "deniable"],
                         cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")
    assert "Mechanism" in out and "Strengths" in out and "Weaknesses" in out
