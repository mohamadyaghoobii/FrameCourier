"""Phase 7 tests: slot-binding MAC + 'version' subcommand + 'doctor' polish."""

import json
import os
import struct
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


def test_multi_recipient_with_padding_still_round_trips(tmp_path):
    """Sanity check that the new slot-binding MAC does not break the happy path."""
    require_ffmpeg()
    cover = tmp_path / "cover.mp4"
    make_cover(cover)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(800))
    alice = tmp_path / "alice"
    bob = tmp_path / "bob"
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(alice)], cwd=ROOT, check=True)
    subprocess.run([sys.executable, "framecourier.py", "keygen", str(bob)], cwd=ROOT, check=True)
    carrier = tmp_path / "c.mp4"
    subprocess.run([sys.executable, "framecourier.py", "embed", str(src), str(carrier),
                    "--cover-video", str(cover),
                    "--recipient", str(alice) + ".pub",
                    "--recipient", str(bob) + ".pub",
                    "--pad-recipients", "10",
                    "--quiet"], cwd=ROOT, check=True)
    out_a = tmp_path / "a.bin"
    subprocess.run([sys.executable, "framecourier.py", "extract", str(carrier), str(out_a),
                    "--identity", str(alice), "--quiet"], cwd=ROOT, check=True)
    assert src.read_bytes() == out_a.read_bytes()


def test_slot_binding_detects_tampered_slot_table(tmp_path):
    """If an attacker swaps any wrapped slot byte, the binding MAC must fire."""
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
                    "--mode", "stego-seq",
                    "--recipient", str(alice) + ".pub",
                    "--recipient", str(bob) + ".pub",
                    "--pad-recipients", "4",
                    "--quiet"], cwd=ROOT, check=True)

    # Tamper with the stored payload by flipping bits in the slot region.
    # In stego-seq the LSB-position for payload byte N starts at HEADER_SIZE*8 + N*8.
    # We achieve this surgically via the carrier's own header internals.
    from datavideo.stego_carrier import _read_first_frame_bytes, _probe_video
    from datavideo import stego, crypto, ecc
    import numpy as np
    info = _probe_video(carrier)
    fsize = stego.yuv420p_frame_bytes(info["width"], info["height"])
    first = _read_first_frame_bytes(carrier, info["width"], info["height"], fsize)
    arr = np.frombuffer(first, dtype=np.uint8).copy()
    header_bytes = stego.reveal_bytes_from_plane(arr, stego.HEADER_SIZE, offset=0)
    header = stego.parse_stego_header_v2(header_bytes)
    # The first payload byte is the slot_count -- but tampering the count
    # changes interpretation too aggressively. Tamper a slot byte instead.
    payload_offset_bits = stego.HEADER_SIZE * 8
    # Flip a bit deep inside one of the wrapped slots.
    target_byte = payload_offset_bits + (1 + 48) * 8 + 17  # well inside the 2nd slot
    if target_byte < len(arr):
        arr[target_byte] ^= 1
    # Re-encode just this first frame back into the video.
    raw_path = tmp_path / "tampered.yuv"
    enc_path = tmp_path / "tampered.mp4"
    decoded_path = tmp_path / "all_raw.yuv"
    # Read all frames out
    from datavideo.ffmpeg_tools import ffmpeg_path
    subprocess.run([ffmpeg_path(), "-v", "error", "-y", "-i", str(carrier),
                    "-map", "0:v:0", "-f", "rawvideo", "-pix_fmt", "yuv420p",
                    "-s", f"{info['width']}x{info['height']}", str(decoded_path)],
                   check=True)
    all_raw = bytearray(decoded_path.read_bytes())
    all_raw[:fsize] = bytes(arr)
    raw_path.write_bytes(bytes(all_raw))
    subprocess.run([ffmpeg_path(), "-v", "error", "-y",
                    "-f", "rawvideo", "-pix_fmt", "yuv420p",
                    "-s", f"{info['width']}x{info['height']}", "-r", str(info['fps']),
                    "-i", str(raw_path),
                    "-c:v", "libx264", "-qp", "0", "-pix_fmt", "yuv420p",
                    str(enc_path)], check=True)

    out = tmp_path / "out.bin"
    result = subprocess.run([sys.executable, "framecourier.py", "extract", str(enc_path), str(out),
                             "--identity", str(alice), "--quiet"],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0, "Tampered carrier should not extract successfully"
    combined = (result.stdout + result.stderr).lower()
    # Either the wrapped slot itself fails to decrypt, OR the binding MAC fires.
    assert ("binding" in combined or "wrapped" in combined or "decryption" in combined or "match" in combined)


def test_version_command_lists_versions():
    out = subprocess.run([sys.executable, "framecourier.py", "version"],
                         cwd=ROOT, capture_output=True, check=True).stdout
    text = out.decode("utf-8")
    assert "FrameCourier" in text
    assert "Python" in text
    assert "FFmpeg" in text
    for dep in ("numpy", "cryptography", "argon2", "reedsolo"):
        assert dep in text


def test_doctor_shows_config_and_audit_status():
    out = subprocess.run([sys.executable, "framecourier.py", "doctor"],
                         cwd=ROOT, capture_output=True).stdout.decode("utf-8")
    assert "Config file:" in out
    assert "Audit log:" in out


def test_explain_stego_robust_documents_empirical_data():
    out = subprocess.run([sys.executable, "framecourier.py", "explain", "stego-robust"],
                         cwd=ROOT, capture_output=True, check=True).stdout.decode("utf-8")
    # The explain entry includes the actual measured survival numbers.
    assert "100%" in out or "100 %" in out
    assert "16%" in out or "17%" in out or "19%" in out
