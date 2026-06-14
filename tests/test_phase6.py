"""Phase 6 tests: Ed25519 sign/verify, embed --sign-with / extract --verify-with,
dummy slot padding, config file overrides.
"""

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
# Ed25519 signatures (sign/verify CLI)
# ---------------------------------------------------------------------------


def test_ed25519_keygen_and_sign_verify(tmp_path):
    key = tmp_path / "sig"
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(key), "--type", "ed25519"],
                   cwd=ROOT, check=True)
    target = tmp_path / "data.bin"
    target.write_bytes(os.urandom(2_000))
    subprocess.run([sys.executable, "framecourier.py", "sign", str(target), "--key", str(key)],
                   cwd=ROOT, check=True)
    sig = target.with_suffix(target.suffix + ".sig")
    assert sig.exists()
    record = json.loads(sig.read_text(encoding="utf-8"))
    assert record["alg"] == "ed25519"
    # Valid signature passes
    subprocess.run([sys.executable, "framecourier.py", "verify", str(target), str(sig),
                    "--pubkey", str(key) + ".pub"], cwd=ROOT, check=True)


def test_ed25519_verify_detects_tamper(tmp_path):
    key = tmp_path / "sig"
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(key), "--type", "ed25519"],
                   cwd=ROOT, check=True)
    target = tmp_path / "data.bin"
    target.write_bytes(b"hello world")
    subprocess.run([sys.executable, "framecourier.py", "sign", str(target), "--key", str(key)],
                   cwd=ROOT, check=True)
    sig = tmp_path / "data.bin.sig"
    target.write_bytes(b"hello tampered!")
    result = subprocess.run([sys.executable, "framecourier.py", "verify", str(target), str(sig)],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0


def test_embed_sign_with_and_extract_verify_with(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(800))
    carrier = tmp_path / "c.mp4"
    rec = tmp_path / "r.bin"
    key = tmp_path / "sig"
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(key), "--type", "ed25519"],
                   cwd=ROOT, check=True)
    env = os.environ.copy()
    env["FC_P"] = "phase6-pass"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-seq",
                    "--password-env", "FC_P",
                    "--sign-with", str(key),
                    "--quiet"], cwd=ROOT, check=True, env=env)
    assert (Path(str(carrier) + ".sig")).exists()
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(rec),
                    "--password-env", "FC_P",
                    "--verify-with", str(key) + ".pub",
                    "--quiet"], cwd=ROOT, check=True, env=env)
    assert src.read_bytes() == rec.read_bytes()


def test_extract_verify_with_rejects_wrong_pubkey(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(500))
    carrier = tmp_path / "c.mp4"
    rec = tmp_path / "r.bin"
    key_a = tmp_path / "siga"
    key_b = tmp_path / "sigb"
    for k in (key_a, key_b):
        subprocess.run([sys.executable, "framecourier.py", "keygen", str(k), "--type", "ed25519"],
                       cwd=ROOT, check=True)
    env = os.environ.copy()
    env["FC_P"] = "p"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-seq",
                    "--password-env", "FC_P",
                    "--sign-with", str(key_a),
                    "--quiet"], cwd=ROOT, check=True, env=env)
    result = subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(rec),
                             "--password-env", "FC_P",
                             "--verify-with", str(key_b) + ".pub",
                             "--quiet"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# Dummy slot padding for multi-recipient
# ---------------------------------------------------------------------------


def test_pad_recipients_does_not_break_real_recipients(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(600))
    alice = tmp_path / "alice"
    bob = tmp_path / "bob"
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(alice)], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(bob)], cwd=ROOT, check=True)
    carrier = tmp_path / "c.mp4"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--recipient", str(alice) + ".pub",
                    "--recipient", str(bob) + ".pub",
                    "--pad-recipients", "20",
                    "--quiet"], cwd=ROOT, check=True)
    out_a = tmp_path / "a.bin"
    out_b = tmp_path / "b.bin"
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(out_a),
                    "--identity", str(alice), "--quiet"], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(out_b),
                    "--identity", str(bob), "--quiet"], cwd=ROOT, check=True)
    assert src.read_bytes() == out_a.read_bytes() == out_b.read_bytes()


# ---------------------------------------------------------------------------
# Config file
# ---------------------------------------------------------------------------


def test_config_set_get_show(tmp_path):
    cfg = tmp_path / "config.json"
    env = os.environ.copy()
    env["FRAMECOURIER_CONFIG"] = str(cfg)
    subprocess.run([sys.executable, "framecourier.py", "config", "set", "default_mode", "stego-adaptive"],
                   cwd=ROOT, check=True, env=env)
    out = subprocess.run([sys.executable, "framecourier.py", "config", "get", "default_mode"],
                         cwd=ROOT, check=True, env=env, capture_output=True, text=True).stdout
    assert "stego-adaptive" in out
    assert cfg.exists()
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data.get("default_mode") == "stego-adaptive"


def test_config_overrides_embed_default(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(500))
    carrier = tmp_path / "c.mp4"
    cfg = tmp_path / "config.json"
    env = os.environ.copy()
    env["FRAMECOURIER_CONFIG"] = str(cfg)
    # Set the default crypto to 'none' via config, so we don't need a passphrase.
    subprocess.run([sys.executable, "framecourier.py", "config", "set", "default_crypto", "none"],
                   cwd=ROOT, check=True, env=env)
    # Set the default mode to stego-seq via config.
    subprocess.run([sys.executable, "framecourier.py", "config", "set", "default_mode", "stego-seq"],
                   cwd=ROOT, check=True, env=env)
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover), "--quiet"], cwd=ROOT, check=True, env=env)
    info_out = subprocess.run([sys.executable, "framecourier.py", "info", str(carrier)],
                              cwd=ROOT, check=True, env=env, capture_output=True, text=True).stdout
    assert "stego-seq" in info_out


def test_config_unset(tmp_path):
    cfg = tmp_path / "config.json"
    env = os.environ.copy()
    env["FRAMECOURIER_CONFIG"] = str(cfg)
    subprocess.run([sys.executable, "framecourier.py", "config", "set", "default_mode", "stego-adaptive"],
                   cwd=ROOT, check=True, env=env)
    subprocess.run([sys.executable, "framecourier.py", "config", "unset", "default_mode"],
                   cwd=ROOT, check=True, env=env)
    out = subprocess.run([sys.executable, "framecourier.py", "config", "get", "default_mode"],
                         cwd=ROOT, check=True, env=env, capture_output=True, text=True).stdout
    assert out.strip() == ""
