"""Phase 5 tests: cover-score, suggest-cover, multi-recipient X25519, audit log."""

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
# Cover score / suggest cover
# ---------------------------------------------------------------------------


def test_cover_score_json_has_recommend(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    out = subprocess.run([sys.executable, "framecourier.py", "cover-score", str(cover), "--frames", "2", "--json"],
                         cwd=ROOT, capture_output=True, check=True).stdout
    data = json.loads(out.decode("utf-8"))
    assert "score_0_100" in data
    assert "recommend_mode" in data
    mode, _ = data["recommend_mode"]
    assert mode in ("stego-seq", "stego-shuffled", "stego-adaptive")


def test_suggest_cover_ranks_multiple(tmp_path):
    require_ffmpeg()
    make_cover(tmp_path / "a.mp4", duration=3, width=320, height=240, rate=10)
    make_cover(tmp_path / "b.mp4", duration=4, width=640, height=360, rate=15)
    out = subprocess.run([sys.executable, "framecourier.py", "suggest-cover", str(tmp_path), "--frames", "2", "--json"],
                         cwd=ROOT, capture_output=True, check=True).stdout
    rows = json.loads(out.decode("utf-8"))
    assert len(rows) == 2
    valid = [r for r in rows if "error" not in r]
    assert len(valid) == 2
    # Sort by score should give the higher-resolution / bigger-capacity cover first.
    assert valid[0]["score"] >= valid[1]["score"]


# ---------------------------------------------------------------------------
# Multi-recipient X25519
# ---------------------------------------------------------------------------


def test_multi_recipient_roundtrip_for_both(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(1_500))
    alice = tmp_path / "alice"
    bob = tmp_path / "bob"
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(alice)], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(bob)], cwd=ROOT, check=True)
    carrier = tmp_path / "multi.mp4"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--recipient", str(alice) + ".pub",
                    "--recipient", str(bob) + ".pub",
                    "--quiet"], cwd=ROOT, check=True)
    out_a = tmp_path / "rec_a.bin"
    out_b = tmp_path / "rec_b.bin"
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(out_a),
                    "--identity", str(alice), "--quiet"], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(out_b),
                    "--identity", str(bob), "--quiet"], cwd=ROOT, check=True)
    assert src.read_bytes() == out_a.read_bytes() == out_b.read_bytes()


def test_multi_recipient_non_member_fails(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(800))
    alice = tmp_path / "alice"
    bob = tmp_path / "bob"
    eve = tmp_path / "eve"
    for k in (alice, bob, eve):
        subprocess.run([sys.executable, "framecourier.py", "keygen", str(k)], cwd=ROOT, check=True)
    carrier = tmp_path / "m.mp4"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--recipient", str(alice) + ".pub",
                    "--recipient", str(bob) + ".pub",
                    "--quiet"], cwd=ROOT, check=True)
    result = subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(tmp_path / "out.bin"),
                             "--identity", str(eve), "--quiet"],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def test_audit_log_records_embed_and_extract(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(800))
    carrier = tmp_path / "c.mp4"
    rec = tmp_path / "r.bin"
    audit_log = tmp_path / "audit.log"
    env = os.environ.copy()
    env["FRAMECOURIER_AUDIT_LOG"] = str(audit_log)
    secret_pass = "audit-test-secret-passphrase-DO-NOT-LEAK-99887766"
    env["FC_P"] = secret_pass
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-seq", "--password-env", "FC_P", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(rec),
                    "--password-env", "FC_P", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    assert audit_log.exists()
    raw = audit_log.read_text(encoding="utf-8")
    lines = [json.loads(ln) for ln in raw.splitlines() if ln.strip()]
    ops = [ln["op"] for ln in lines]
    assert "embed" in ops and "extract" in ops
    # Make sure the passphrase itself is never recorded
    assert secret_pass not in raw, "audit log must never include the passphrase"
    # Make sure the plaintext-payload bytes are never recorded (the src is random; pick a unique slice)
    src_bytes = src.read_bytes()
    if len(src_bytes) >= 32:
        unique = src_bytes[:32].hex()
        assert unique not in raw, "audit log must never include plaintext payload bytes"


def test_audit_log_disabled_when_env_unset(tmp_path):
    out = subprocess.run([sys.executable, "framecourier.py", "audit"],
                         cwd=ROOT, capture_output=True, check=False)
    text = (out.stdout + out.stderr).decode("utf-8")
    assert "disabled" in text.lower() or "FRAMECOURIER_AUDIT_LOG" in text


def test_audit_cli_reads_log(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(400))
    carrier = tmp_path / "c.mp4"
    audit_log = tmp_path / "audit.log"
    env = os.environ.copy()
    env["FRAMECOURIER_AUDIT_LOG"] = str(audit_log)
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--mode", "stego-seq", "--crypto", "none", "--quiet"],
                   cwd=ROOT, check=True, env=env)
    out = subprocess.run([sys.executable, "framecourier.py", "audit", "--json"],
                         cwd=ROOT, env=env, capture_output=True, check=True).stdout
    rows = json.loads(out.decode("utf-8"))
    assert any(r["op"] == "embed" for r in rows)


# ---------------------------------------------------------------------------
# explain entry for x25519-multi
# ---------------------------------------------------------------------------


def test_explain_x25519_multi():
    out = subprocess.run([sys.executable, "framecourier.py", "explain", "x25519-multi-chacha20"],
                         cwd=ROOT, capture_output=True, check=True).stdout
    text = out.decode("utf-8")
    assert "Mechanism" in text
    assert "wrapped" in text.lower() or "envelope" in text.lower()
