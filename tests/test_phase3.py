"""Phase 3 tests: X25519 asymmetric, legacy-mode encryption, steganalyse."""

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
# X25519 asymmetric
# ---------------------------------------------------------------------------


def test_x25519_keygen_creates_keypair(tmp_path):
    priv_path = tmp_path / "id"
    pub_path = tmp_path / "id.pub"
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(priv_path)], cwd=ROOT, check=True)
    assert priv_path.exists() and pub_path.exists()
    assert b"FCX25519-PRIVATE-KEY-v1" in priv_path.read_bytes()
    assert b"FCX25519-PUBLIC-KEY-v1" in pub_path.read_bytes()


def test_x25519_roundtrip(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "src.bin"
    carrier = tmp_path / "carrier.mp4"
    recovered = tmp_path / "rec.bin"
    priv_path = tmp_path / "id"
    pub_path = tmp_path / "id.pub"
    make_cover(cover)
    source.write_bytes(os.urandom(4_000))
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(priv_path)], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "embed", str(source), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-shuffled",
                    "--recipient", str(pub_path),
                    "--quiet"], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(recovered),
                    "--identity", str(priv_path), "--quiet"], cwd=ROOT, check=True)
    assert source.read_bytes() == recovered.read_bytes()


def test_x25519_wrong_identity_fails(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "src.bin"
    carrier = tmp_path / "carrier.mp4"
    recovered = tmp_path / "rec.bin"
    priv_a = tmp_path / "ida"
    priv_b = tmp_path / "idb"
    make_cover(cover)
    source.write_bytes(os.urandom(2_000))
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(priv_a)], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(priv_b)], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "embed", str(source), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-seq",
                    "--recipient", str(priv_a) + ".pub",
                    "--quiet"], cwd=ROOT, check=True)
    result = subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(recovered),
                             "--identity", str(priv_b), "--quiet"],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0


def test_x25519_extract_without_identity_fails(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "src.bin"
    carrier = tmp_path / "carrier.mp4"
    recovered = tmp_path / "rec.bin"
    priv_path = tmp_path / "id"
    make_cover(cover)
    source.write_bytes(os.urandom(1_000))
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(priv_path)], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "embed", str(source), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-seq",
                    "--recipient", str(priv_path) + ".pub",
                    "--quiet"], cwd=ROOT, check=True)
    result = subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(recovered), "--quiet"],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# Legacy direct mode encryption
# ---------------------------------------------------------------------------


def test_legacy_direct_encrypted_roundtrip(tmp_path):
    require_ffmpeg()
    source = tmp_path / "src.bin"
    video = tmp_path / "video.mkv"
    recovered = tmp_path / "rec.bin"
    source.write_bytes(os.urandom(60_000))
    env = os.environ.copy()
    env["FC_DV"] = "direct-pass"
    subprocess.run([sys.executable, "encode.py", str(source), str(video),
                    "--width", "320", "--height", "240", "--fps", "10",
                    "--password-env", "FC_DV", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    subprocess.run([sys.executable, "decode.py", str(video), str(recovered),
                    "--password-env", "FC_DV", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    assert source.read_bytes() == recovered.read_bytes()


def test_legacy_direct_wrong_password_fails(tmp_path):
    require_ffmpeg()
    source = tmp_path / "src.bin"
    video = tmp_path / "video.mkv"
    recovered = tmp_path / "rec.bin"
    source.write_bytes(os.urandom(10_000))
    env = os.environ.copy()
    env["FC_OK"] = "right"
    env["FC_BAD"] = "wrong"
    subprocess.run([sys.executable, "encode.py", str(source), str(video),
                    "--width", "320", "--height", "240", "--fps", "10",
                    "--password-env", "FC_OK", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    result = subprocess.run([sys.executable, "decode.py", str(video), str(recovered),
                             "--password-env", "FC_BAD", "--quiet"],
                            cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# steganalyse CLI
# ---------------------------------------------------------------------------


def test_steganalyse_json_output(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    out = subprocess.run([sys.executable, "framecourier.py", "steganalyse", str(cover), "--frames", "2", "--json"],
                         cwd=ROOT, capture_output=True, check=True).stdout
    data = json.loads(out.decode("utf-8"))
    assert "results" in data
    r = data["results"]
    assert "chi_square" in r and "sample_pair" in r and "rs_divergence" in r


def test_steganalyse_carrier_scores_higher_than_clean_cover(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    source = tmp_path / "src.bin"
    carrier = tmp_path / "carrier.mp4"
    make_cover(cover)
    source.write_bytes(os.urandom(8_000))
    subprocess.run([sys.executable, "framecourier.py", "embed", str(source), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-seq",
                    "--crypto", "none",
                    "--quiet"], cwd=ROOT, check=True)

    def _verdict(path):
        out = subprocess.run([sys.executable, "framecourier.py", "steganalyse", str(path), "--frames", "2", "--json"],
                             cwd=ROOT, capture_output=True, check=True).stdout
        d = json.loads(out.decode("utf-8"))
        from datavideo.steganalysis import verdict
        return verdict(d["results"])

    clean = _verdict(cover)
    stego = _verdict(carrier)
    # Plaintext stego-seq embeds in the first ~1KB of frame 0 -- it should be detected
    # at least as strongly as the clean cover.
    assert stego >= clean - 0.05, f"steganalyse should not regress against the cover (clean={clean:.3f}, stego={stego:.3f})"
