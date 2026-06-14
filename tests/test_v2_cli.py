"""Smoke tests for the v2 stego carrier and the new ``framecourier`` CLI."""

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
        ffmpeg_path(),
        "-v", "error", "-y",
        "-f", "lavfi",
        "-i", f"testsrc2=size={width}x{height}:rate={rate}:duration={duration}",
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        str(path),
    ], check=True)


def _embed_extract_roundtrip(tmp_path, mode, crypto_layer, kdf, ecc_layer, password=None):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "src.bin"
    carrier = tmp_path / "carrier.mp4"
    recovered = tmp_path / "rec.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(8_000))

    env = os.environ.copy()
    embed_cmd = [sys.executable, "framecourier.py", "embed", str(source), str(carrier),
                 "--cover-video", str(cover),
                 "--mode", mode, "--crypto", crypto_layer, "--kdf", kdf, "--ecc", ecc_layer,
                 "--quiet"]
    extract_cmd = [sys.executable, "framecourier.py", "extract", str(carrier), str(recovered), "--quiet"]
    if password is not None:
        env["FC_TESTPASS"] = password
        embed_cmd.extend(["--password-env", "FC_TESTPASS"])
        extract_cmd.extend(["--password-env", "FC_TESTPASS"])
    subprocess.run(embed_cmd, cwd=ROOT, check=True, env=env)
    subprocess.run(extract_cmd, cwd=ROOT, check=True, env=env)
    assert source.read_bytes() == recovered.read_bytes()


def test_v2_seq_aes_gcm_argon2id(tmp_path):
    _embed_extract_roundtrip(tmp_path, "stego-seq", "aes-gcm", "argon2id", "none", password="pass-seq")


def test_v2_shuffled_chacha_poly(tmp_path):
    _embed_extract_roundtrip(tmp_path, "stego-shuffled", "chacha-poly", "argon2id", "none", password="pass-shuf")


def test_v2_adaptive_aes_gcm_with_rs_ecc(tmp_path):
    _embed_extract_roundtrip(tmp_path, "stego-adaptive", "aes-gcm", "argon2id", "rs-255-223", password="pass-adp")


def test_v2_seq_plain_no_crypto_no_ecc(tmp_path):
    _embed_extract_roundtrip(tmp_path, "stego-seq", "none", "none", "none", password=None)


def test_v2_carrier_passes_ffprobe_as_single_h264(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "src.bin"
    carrier = tmp_path / "carrier.mp4"
    make_cover(cover)
    source.write_bytes(os.urandom(4_000))
    env = os.environ.copy()
    env["FC_P"] = "x"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(source), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-shuffled", "--password-env", "FC_P", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    from datavideo.ffmpeg_tools import ffprobe_path
    out = subprocess.run([ffprobe_path(), "-v", "error", "-show_streams", "-of", "json", str(carrier)],
                         capture_output=True, check=True).stdout
    data = json.loads(out.decode("utf-8"))
    video = [s for s in data["streams"] if s.get("codec_type") == "video"]
    assert len(video) == 1
    assert video[0]["codec_name"] == "h264"
    assert video[0]["pix_fmt"] == "yuv420p"


def test_cli_modes_lists_everything():
    out = subprocess.run([sys.executable, "framecourier.py", "modes"], cwd=ROOT, capture_output=True, check=True).stdout
    text = out.decode("utf-8")
    for name in ("stego-seq", "stego-shuffled", "stego-adaptive", "distributed", "legacy",
                 "none", "aes-ctr", "aes-gcm", "chacha-poly", "rs-255-223"):
        assert name in text, f"'{name}' missing from 'framecourier modes' output"


def test_cli_explain_each_mode():
    for name in ("stego-seq", "stego-shuffled", "stego-adaptive",
                 "aes-gcm", "chacha-poly", "rs-255-223"):
        out = subprocess.run([sys.executable, "framecourier.py", "explain", name],
                             cwd=ROOT, capture_output=True, check=True).stdout
        text = out.decode("utf-8")
        assert "Mechanism" in text
        assert "Strengths" in text
        assert "Weaknesses" in text


def test_cli_probe_detects_v2_carrier(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "src.bin"
    carrier = tmp_path / "carrier.mp4"
    make_cover(cover)
    source.write_bytes(os.urandom(2_000))
    env = os.environ.copy()
    env["FC_P"] = "pp"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(source), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-seq", "--password-env", "FC_P", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    out = subprocess.run([sys.executable, "framecourier.py", "probe", str(carrier), "--json"],
                         cwd=ROOT, capture_output=True, check=True).stdout
    report = json.loads(out.decode("utf-8"))
    severities = [f["severity"] for f in report["findings"]]
    assert "critical" in severities, f"probe should flag v2 magic but findings={report['findings']}"


def test_cli_info_round_trip(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "src.bin"
    carrier = tmp_path / "carrier.mp4"
    make_cover(cover)
    source.write_bytes(os.urandom(2_000))
    env = os.environ.copy()
    env["FC_P"] = "p"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(source), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-shuffled", "--ecc", "rs-255-223",
                    "--password-env", "FC_P", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    out = subprocess.run([sys.executable, "framecourier.py", "info", str(carrier)],
                         cwd=ROOT, capture_output=True, check=True).stdout
    text = out.decode("utf-8")
    assert "stego-shuffled" in text
    assert "aes-gcm" in text
    assert "argon2id" in text
    assert "rs-255-223" in text


def test_wrong_password_aead_fails(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "src.bin"
    carrier = tmp_path / "carrier.mp4"
    recovered = tmp_path / "rec.bin"
    make_cover(cover)
    source.write_bytes(os.urandom(3_000))
    env = os.environ.copy()
    env["FC_GOOD"] = "right-one"
    env["FC_BAD"] = "wrong-one"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(source), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-seq", "--crypto", "aes-gcm",
                    "--password-env", "FC_GOOD", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    result = subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(recovered),
                             "--password-env", "FC_BAD", "--quiet"],
                            cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode != 0
    combined = (result.stdout + result.stderr).lower()
    assert "decryption" in combined or "sha" in combined or "wrong" in combined
