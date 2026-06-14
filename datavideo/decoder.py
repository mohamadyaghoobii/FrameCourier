import hashlib
import subprocess

from . import crypto as _crypto
from .core import PIXEL_FORMAT, frame_bytes, parse_header
from .ffmpeg_tools import ffmpeg_path, probe_video


def build_decode_command(video_path):
    return [
        ffmpeg_path(),
        "-v", "error",
        "-i", str(video_path),
        "-f", "rawvideo",
        "-pix_fmt", PIXEL_FORMAT,
        "pipe:1"
    ]


def read_exact(stream, size):
    parts = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    if remaining != 0:
        return b"".join(parts)
    return b"".join(parts)


def _decryptor_from_metadata(metadata, password):
    layer = metadata.get("enc_layer")
    kdf = metadata.get("enc_kdf")
    salt = _crypto.b64d(metadata["enc_salt"])
    nonce = _crypto.b64d(metadata["enc_nonce"])
    if kdf == _crypto.KDF_PBKDF2:
        iterations = int(metadata.get("enc_pbkdf2_iterations", _crypto.DEFAULT_PBKDF2_ITERATIONS))
        key = _crypto.derive_key_pbkdf2(password, salt, iterations=iterations)
    elif kdf == _crypto.KDF_ARGON2ID:
        key = _crypto.derive_key_argon2id(
            password, salt,
            time_cost=int(metadata.get("enc_argon2_time", _crypto.DEFAULT_ARGON2_TIME)),
            memory_kb=int(metadata.get("enc_argon2_memory_kb", _crypto.DEFAULT_ARGON2_MEMORY_KB)),
            parallelism=int(metadata.get("enc_argon2_parallelism", _crypto.DEFAULT_ARGON2_PARALLELISM)),
        )
    else:
        raise RuntimeError(f"Unsupported KDF in carrier metadata: {kdf}")
    if layer != _crypto.LAYER_AES_CTR:
        raise RuntimeError(f"Direct DataVideo mode only supports {_crypto.LAYER_AES_CTR}; got {layer}")
    return _crypto.aes_ctr_decryptor(key, nonce)


def decode_video(video_path, output_path, password=None, progress=True):
    stream = probe_video(video_path)
    width = int(stream["width"])
    height = int(stream["height"])
    per_frame = frame_bytes(width, height)
    cmd = build_decode_command(video_path)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    try:
        first_frame = read_exact(process.stdout, per_frame)
        if len(first_frame) != per_frame:
            raise RuntimeError("Could not read the first video frame")
        metadata = parse_header(first_frame)
        expected_width = int(metadata["width"])
        expected_height = int(metadata["height"])
        if expected_width != width or expected_height != height:
            raise RuntimeError("Video dimensions do not match embedded DataVideo metadata")
        header_bytes = int(metadata["header_bytes"])
        file_size = int(metadata["file_size"])
        total_frames = int(metadata["total_frames"])
        expected_hash = metadata["sha256"]

        decryptor = None
        if metadata.get("encrypted"):
            if password is None:
                raise RuntimeError("Carrier is encrypted; --password is required.")
            decryptor = _decryptor_from_metadata(metadata, password)
        elif password is not None:
            # carrier wasn't encrypted, ignore the password silently
            pass

        def _decrypt(chunk):
            return decryptor.update(chunk) if decryptor is not None else chunk

        written = 0
        digest = hashlib.sha256()
        with open(output_path, "wb") as out:
            first_payload = first_frame[header_bytes:]
            take = min(len(first_payload), file_size - written)
            if take > 0:
                plain = _decrypt(bytes(first_payload[:take]))
                out.write(plain)
                digest.update(plain)
                written += take
            if progress:
                print(f"decoded frame 1/{total_frames}")
            for frame_id in range(1, total_frames):
                frame = read_exact(process.stdout, per_frame)
                if len(frame) != per_frame:
                    raise RuntimeError(f"Missing or truncated frame {frame_id}")
                take = min(per_frame, file_size - written)
                if take > 0:
                    plain = _decrypt(bytes(frame[:take]))
                    out.write(plain)
                    digest.update(plain)
                    written += take
                if progress and ((frame_id + 1) % 25 == 0 or frame_id + 1 == total_frames):
                    print(f"decoded frame {frame_id + 1}/{total_frames}")
        process.stdout.close()
        code = process.wait()
        if code != 0:
            raise RuntimeError("FFmpeg decoder failed")
        if written != file_size:
            raise RuntimeError("Decoded file size does not match metadata")
        actual_hash = digest.hexdigest()
        if actual_hash != expected_hash:
            if decryptor is not None:
                raise RuntimeError("SHA256 mismatch. Wrong password or carrier corrupted.")
            raise RuntimeError("SHA256 mismatch. The video was changed or decoded incorrectly.")
        return metadata
    except Exception:
        if process.stdout:
            try:
                process.stdout.close()
            except Exception:
                pass
        process.kill()
        process.wait()
        raise
