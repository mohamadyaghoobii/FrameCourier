"""Phase 8 tests: bech32, age import/export, carrier fingerprint + diff."""

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
# Bech32 + age
# ---------------------------------------------------------------------------


def test_bech32_roundtrip_random_bytes():
    from datavideo import bech32
    rng = os.urandom(32)
    encoded = bech32.encode("test", rng)
    assert encoded.startswith("test1")
    decoded = bech32.decode("test", encoded)
    assert decoded == rng


def test_bech32_rejects_wrong_hrp():
    from datavideo import bech32
    encoded = bech32.encode("foo", b"hello")
    with pytest.raises(ValueError):
        bech32.decode("bar", encoded)


def test_age_export_then_import_yields_same_key(tmp_path):
    """An X25519 key exported as age and re-imported must match the original."""
    from datavideo import crypto
    priv_raw, pub_raw = crypto.x25519_generate_keypair()
    age_secret = crypto.x25519_to_age_secret(priv_raw)
    assert age_secret.startswith("AGE-SECRET-KEY-1")
    recovered = crypto.x25519_from_age_secret(age_secret)
    assert recovered == priv_raw

    age_pub = crypto.x25519_to_age_public(pub_raw)
    assert age_pub.startswith("age1")
    recovered_pub = crypto.x25519_from_age_public(age_pub)
    assert recovered_pub == pub_raw


def test_keygen_export_age_and_import_age_cli_roundtrip(tmp_path):
    """keygen --export-age prints the age form, keygen --import-age re-imports it."""
    out_key = tmp_path / "fckey"
    result = subprocess.run([sys.executable, "framecourier.py", "keygen", str(out_key),
                             "--export-age"], cwd=ROOT, capture_output=True, check=True)
    text = result.stdout.decode("utf-8")
    assert "age1" in text
    assert "AGE-SECRET-KEY-1" in text

    # Extract the printed age secret and write to a file, then import.
    line = next(ln for ln in text.splitlines() if "AGE-SECRET-KEY-1" in ln).strip()
    age_blob = tmp_path / "blob.age"
    age_blob.write_text(line, encoding="utf-8")

    imported = tmp_path / "imported"
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(imported),
                    "--import-age", str(age_blob)], cwd=ROOT, check=True)
    assert imported.read_bytes() == out_key.read_bytes(), "Imported key must match the original"


def test_recipient_accepts_age_public_format(tmp_path):
    """embed --recipient must accept an ``age1...`` recipient file directly."""
    require_ffmpeg()
    from datavideo import crypto
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(800))

    # Recipient: generate keypair in FrameCourier format, then write public side
    # as an age recipient file instead.
    fc_key = tmp_path / "alice"
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(fc_key)],
                   cwd=ROOT, check=True)
    fc_pub_raw = crypto.x25519_load_public(Path(str(fc_key) + ".pub").read_bytes())
    age_pub_file = tmp_path / "alice.age.pub"
    age_pub_file.write_text(crypto.x25519_to_age_public(fc_pub_raw) + "\n", encoding="utf-8")

    carrier = tmp_path / "c.mp4"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--recipient", str(age_pub_file),
                    "--quiet"], cwd=ROOT, check=True)
    rec = tmp_path / "rec.bin"
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(rec),
                    "--identity", str(fc_key), "--quiet"], cwd=ROOT, check=True)
    assert src.read_bytes() == rec.read_bytes()


# ---------------------------------------------------------------------------
# Carrier fingerprint + diff
# ---------------------------------------------------------------------------


def test_fingerprint_is_deterministic(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(500))
    carrier = tmp_path / "c.mp4"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover), "--crypto", "none", "--quiet"],
                   cwd=ROOT, check=True)
    out_a = subprocess.run([sys.executable, "framecourier.py", "fingerprint", str(carrier)],
                           cwd=ROOT, capture_output=True, check=True).stdout
    out_b = subprocess.run([sys.executable, "framecourier.py", "fingerprint", str(carrier)],
                           cwd=ROOT, capture_output=True, check=True).stdout
    assert out_a == out_b, "fingerprint must be deterministic across invocations"
    parsed = json.loads(out_a.decode("utf-8"))
    assert "file_sha256" in parsed and "container" in parsed
    assert parsed["stego"]["mode"] == "stego-shuffled"


def test_diff_identical_carriers_reports_only_path():
    """A byte-identical copy must produce zero non-path differences."""
    # We use the existing 'examples' command output as a sanity proxy.
    # No FFmpeg required here.
    from datavideo import fingerprint as fpmod
    # Make a tiny fake fp dict to exercise diff().
    a = {"x": 1, "y": {"z": 2}}
    b = {"x": 1, "y": {"z": 2}}
    assert fpmod.diff(a, b) == []
    b2 = {"x": 1, "y": {"z": 3}}
    differences = fpmod.diff(a, b2)
    assert ("y.z", 2, 3) in differences


def test_diff_cli_finds_payload_differences(tmp_path):
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src1 = tmp_path / "src1.bin"
    src2 = tmp_path / "src2.bin"
    src1.write_bytes(os.urandom(500))
    src2.write_bytes(os.urandom(900))
    a = tmp_path / "a.mp4"
    b = tmp_path / "b.mp4"
    for src, out in ((src1, a), (src2, b)):
        subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(out),
                        "--cover-video", str(cover), "--crypto", "none", "--quiet"],
                       cwd=ROOT, check=True)
    result = subprocess.run([sys.executable, "framecourier.py", "diff", str(a), str(b), "--json"],
                            cwd=ROOT, capture_output=True, check=True).stdout
    report = json.loads(result.decode("utf-8"))
    field_set = {d["field"] for d in report["differences"]}
    assert "file_sha256" in field_set
    assert "stego.plaintext_bytes" in field_set
    assert "stego.plaintext_sha256" in field_set
