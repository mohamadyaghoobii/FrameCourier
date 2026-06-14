import subprocess

from . import crypto as _crypto
from .core import DEFAULT_FPS, DEFAULT_HEADER_BYTES, DEFAULT_HEIGHT, DEFAULT_WIDTH, PIXEL_FORMAT, frame_bytes, make_metadata, pack_header, pad_frame, sha256_file
from .ffmpeg_tools import ffmpeg_path


def build_encode_command(output_path, width, height, fps):
    return [
        ffmpeg_path(),
        "-v", "error",
        "-y",
        "-f", "rawvideo",
        "-pix_fmt", PIXEL_FORMAT,
        "-s", f"{width}x{height}",
        "-r", str(fps),
        "-i", "pipe:0",
        "-an",
        "-c:v", "ffv1",
        "-level", "3",
        "-g", "1",
        "-slicecrc", "1",
        "-pix_fmt", PIXEL_FORMAT,
        str(output_path)
    ]


def _build_encryption_meta(password, layer, kdf):
    salt = _crypto.new_salt()
    nonce = _crypto.new_nonce()
    if kdf == _crypto.KDF_PBKDF2:
        key = _crypto.derive_key_pbkdf2(password, salt)
    elif kdf == _crypto.KDF_ARGON2ID:
        key = _crypto.derive_key_argon2id(password, salt)
    else:
        raise ValueError(f"Unsupported KDF for direct mode: {kdf}")
    meta = {
        "layer": layer,
        "kdf": kdf,
        "salt_b64": _crypto.b64e(salt),
        "nonce_b64": _crypto.b64e(nonce),
    }
    if kdf == _crypto.KDF_PBKDF2:
        meta["pbkdf2_iterations"] = _crypto.DEFAULT_PBKDF2_ITERATIONS
    elif kdf == _crypto.KDF_ARGON2ID:
        meta["argon2_time"] = _crypto.DEFAULT_ARGON2_TIME
        meta["argon2_memory_kb"] = _crypto.DEFAULT_ARGON2_MEMORY_KB
        meta["argon2_parallelism"] = _crypto.DEFAULT_ARGON2_PARALLELISM
    return key, salt, nonce, meta


def encode_file(input_path, output_path, width=DEFAULT_WIDTH, height=DEFAULT_HEIGHT, fps=DEFAULT_FPS, header_bytes=DEFAULT_HEADER_BYTES, password=None, layer=None, kdf=None, progress=True):
    per_frame = frame_bytes(width, height)
    file_hash = sha256_file(input_path)
    encryption_meta = None
    encryptor = None
    if password is not None:
        if layer is None:
            layer = _crypto.LAYER_AES_CTR
        if kdf is None:
            kdf = _crypto.KDF_ARGON2ID if layer in (_crypto.LAYER_AES_GCM, _crypto.LAYER_CHACHA_POLY) else _crypto.KDF_PBKDF2
        if layer in (_crypto.LAYER_AES_GCM, _crypto.LAYER_CHACHA_POLY, _crypto.LAYER_X25519_CHACHA):
            raise ValueError(
                f"Direct DataVideo mode supports only stream ciphers (aes-ctr). "
                f"For {layer} use the stego or distributed carrier mode instead."
            )
        key, salt, nonce, encryption_meta = _build_encryption_meta(password, layer, kdf)
        encryptor = _crypto.aes_ctr_encryptor(key, nonce)

    metadata = make_metadata(input_path, width, height, fps, header_bytes, file_hash, encryption=encryption_meta)
    header = pack_header(metadata, header_bytes)
    first_payload_size = per_frame - header_bytes
    cmd = build_encode_command(output_path, width, height, fps)
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    frame_id = 0

    def _encrypt_chunk(chunk):
        if encryptor is None:
            return chunk
        return encryptor.update(chunk)

    try:
        with open(input_path, "rb") as f:
            first_payload = _encrypt_chunk(f.read(first_payload_size))
            process.stdin.write(pad_frame(header + first_payload, per_frame))
            frame_id += 1
            if progress:
                print(f"encoded frame {frame_id}/{metadata['total_frames']}")
            while True:
                chunk = f.read(per_frame)
                if not chunk:
                    break
                process.stdin.write(pad_frame(_encrypt_chunk(chunk), per_frame))
                frame_id += 1
                if progress and (frame_id % 25 == 0 or frame_id == metadata["total_frames"]):
                    print(f"encoded frame {frame_id}/{metadata['total_frames']}")
        process.stdin.close()
        code = process.wait()
        if code != 0:
            raise RuntimeError("FFmpeg encoder failed")
    except Exception:
        if process.stdin:
            try:
                process.stdin.close()
            except Exception:
                pass
        process.kill()
        process.wait()
        raise
    return metadata
