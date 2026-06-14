"""Multi-mode LSB stego carrier for FrameCourier (v2).

``embed_stego`` always writes a v2 header. The header carries the mode (seq,
shuffled, adaptive), crypto layer (none, aes-ctr, aes-gcm, chacha-poly), KDF
(none, pbkdf2, argon2id), ECC (none, rs-255-223), and all the per-carrier
parameters (salt, base nonce, position seed, adaptive threshold). ``extract_stego``
reads the header, reconstructs the same configuration, and decodes the payload.

``is_stego_carrier`` and ``extract_stego`` both also recognise v1 carriers so
existing files keep working.
"""

import hashlib
import hmac
import json
import os
import struct
import subprocess
from pathlib import Path

MULTI_BINDING_INFO = b"framecourier-slots-binding-v1"
MULTI_BINDING_BYTES = 32

import numpy as np

from . import crypto, ecc, stego
from .core import sha256_file
from .cover import find_default_cover
from .decoder import read_exact
from .ffmpeg_tools import ffmpeg_path, ffprobe_path

DENIABLE_LEN_PREFIX = 4  # uint32 plaintext length per slot


READ_CHUNK = 1 << 20
HEADER_BIT_COUNT = stego.HEADER_SIZE * 8


def _probe_video(path):
    cmd = [
        ffprobe_path(), "-v", "error",
        "-show_entries", "stream=index,codec_type,codec_name,width,height,r_frame_rate,nb_frames,duration",
        "-of", "json",
        str(path),
    ]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
    data = json.loads(result.stdout.decode("utf-8"))
    streams = data.get("streams") or []
    video_streams = [s for s in streams if s.get("codec_type") == "video"]
    audio_streams = [s for s in streams if s.get("codec_type") == "audio"]
    if not video_streams:
        raise RuntimeError(f"No video stream in {path}")
    v = video_streams[0]
    width = int(v["width"])
    height = int(v["height"])
    num, den = v.get("r_frame_rate", "30/1").split("/")
    fps = (int(num) / int(den)) if int(den) else 30.0
    nb_frames = v.get("nb_frames")
    if nb_frames and str(nb_frames).isdigit():
        frame_count = int(nb_frames)
    else:
        duration = float(v.get("duration") or 0.0)
        frame_count = max(1, int(round(duration * fps)))
    return {
        "width": width,
        "height": height,
        "fps": fps,
        "frame_count": frame_count,
        "has_audio": bool(audio_streams),
    }


def _decode_pipe(video_path, width, height):
    cmd = [
        ffmpeg_path(), "-v", "error",
        "-i", str(video_path),
        "-map", "0:v:0",
        "-f", "rawvideo",
        "-pix_fmt", "yuv420p",
        "-s", f"{width}x{height}",
        "pipe:1",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _encode_pipe(output_path, width, height, fps, cover_path=None, has_audio=False, preset="veryfast"):
    cmd = [
        ffmpeg_path(), "-v", "error", "-y",
        "-f", "rawvideo",
        "-pix_fmt", "yuv420p",
        "-s", f"{width}x{height}",
        "-r", str(fps),
        "-i", "pipe:0",
    ]
    if has_audio and cover_path is not None:
        cmd.extend(["-i", str(cover_path)])
        cmd.extend(["-map", "0:v:0", "-map", "1:a:0?"])
        cmd.extend(["-c:a", "copy"])
    else:
        cmd.extend(["-map", "0:v:0"])
    cmd.extend([
        "-c:v", "libx264",
        "-preset", preset,
        "-qp", "0",
        "-pix_fmt", "yuv420p",
        "-shortest",
        str(output_path),
    ])
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)


def _read_first_frame_bytes(video_path, width, height, count):
    frame_size = stego.yuv420p_frame_bytes(width, height)
    cmd = [
        ffmpeg_path(), "-v", "error",
        "-i", str(video_path),
        "-map", "0:v:0",
        "-frames:v", "1",
        "-f", "rawvideo",
        "-pix_fmt", "yuv420p",
        "-s", f"{width}x{height}",
        "pipe:1",
    ]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if len(result.stdout) < frame_size:
        raise RuntimeError("Could not decode first frame")
    return result.stdout[:frame_size]


def estimate_capacity(width, height, frame_count):
    return stego.lsb_byte_capacity_per_frame(width, height) * frame_count


# ---------------------------------------------------------------------------
# Position selectors (one per mode)
# ---------------------------------------------------------------------------


def _seed_for_frame(base_seed, frame_idx):
    digest = hashlib.sha256(base_seed + frame_idx.to_bytes(8, "big")).digest()
    return int.from_bytes(digest[:8], "big")


def _positions_seq(frame_arr, frame_idx, exclude_header):
    size = len(frame_arr)
    if frame_idx == 0 and exclude_header:
        return np.arange(HEADER_BIT_COUNT, size, dtype=np.int64)
    return np.arange(size, dtype=np.int64)


def _positions_shuffled(frame_arr, frame_idx, base_seed, exclude_header):
    size = len(frame_arr)
    rng = np.random.default_rng(_seed_for_frame(base_seed, frame_idx))
    if frame_idx == 0 and exclude_header:
        available = np.arange(HEADER_BIT_COUNT, size, dtype=np.int64)
    else:
        available = np.arange(size, dtype=np.int64)
    rng.shuffle(available)
    return available


def _positions_adaptive(frame_arr, frame_idx, base_seed, threshold, exclude_header):
    """Adaptive selector based on neighbour-pair absolute difference of the upper 7 bits.

    Pixel byte ``i`` is considered when ``|((byte_i - byte_{i-1}) >> 1)|`` is at least
    ``threshold``. This is computed on the upper 7 bits so that LSB embedding cannot
    change which positions get selected on the receiving side. Positions are then
    shuffled with a per-frame PRNG so the modification pattern is not spatially
    contiguous even within the high-variance set.
    """
    size = len(frame_arr)
    upper = (frame_arr >> 1).astype(np.int16)
    diff = np.empty(size, dtype=np.int16)
    diff[0] = 0
    diff[1:] = np.abs(upper[1:] - upper[:-1])
    mask = diff >= max(1, threshold)
    if frame_idx == 0 and exclude_header:
        mask[:HEADER_BIT_COUNT] = False
    candidates = np.where(mask)[0].astype(np.int64)
    if base_seed is not None:
        rng = np.random.default_rng(_seed_for_frame(base_seed, frame_idx))
        rng.shuffle(candidates)
    return candidates


def _select_positions(mode_id, frame_arr, frame_idx, *, position_seed, adaptive_threshold, exclude_header):
    if mode_id == stego.MODE_IDS[stego.MODE_SEQ]:
        return _positions_seq(frame_arr, frame_idx, exclude_header)
    if mode_id == stego.MODE_IDS[stego.MODE_SHUFFLED]:
        return _positions_shuffled(frame_arr, frame_idx, position_seed, exclude_header)
    if mode_id == stego.MODE_IDS[stego.MODE_ADAPTIVE]:
        return _positions_adaptive(frame_arr, frame_idx, position_seed, adaptive_threshold, exclude_header)
    raise ValueError(f"Unknown mode_id {mode_id}")


# ---------------------------------------------------------------------------
# Pre-processing payload: optional ECC + optional crypto
# ---------------------------------------------------------------------------


def _build_deniable_slot(plaintext_bytes, slot_size, password, salt, nonce):
    if len(plaintext_bytes) > slot_size - DENIABLE_LEN_PREFIX:
        raise ValueError("Slot payload larger than slot capacity")
    pad_len = slot_size - DENIABLE_LEN_PREFIX - len(plaintext_bytes)
    body = struct.pack(">I", len(plaintext_bytes)) + plaintext_bytes + os.urandom(pad_len)
    key = crypto.derive_key_argon2id(password, salt)
    enc = crypto.chacha_poly_encryptor(key, nonce)
    return enc.update(body) + enc.finalize()


def _try_deniable_slot(ciphertext, password, salt, nonce):
    try:
        key = crypto.derive_key_argon2id(password, salt)
        dec = crypto.chacha_poly_decryptor(key, nonce)
        plain = dec.update(ciphertext) + dec.finalize()
        if len(plain) < DENIABLE_LEN_PREFIX:
            return None
        real_len = struct.unpack(">I", plain[:DENIABLE_LEN_PREFIX])[0]
        if real_len > len(plain) - DENIABLE_LEN_PREFIX:
            return None
        return plain[DENIABLE_LEN_PREFIX:DENIABLE_LEN_PREFIX + real_len]
    except Exception:
        return None


def _process_outgoing_payload(input_path, *, ecc_layer, crypto_layer, kdf, password, recipient_pubkey=None, recipient_pubkeys=None, decoy_path=None, decoy_password=None, pad_recipients=0):
    with open(input_path, "rb") as f:
        data = f.read()

    if ecc_layer == ecc.ECC_RS_255_223:
        data = ecc.encode_rs(data)

    salt = b"\x00" * 16
    base_nonce = b"\x00" * 12
    pbkdf2_iter = 0
    argon2_time = 0
    argon2_mem = 0
    argon2_par = 0
    ephemeral_pub = b"\x00" * 32
    slot1_salt = b"\x00" * 16
    slot1_nonce = b"\x00" * 12

    if crypto_layer == crypto.LAYER_DENIABLE:
        if password is None or decoy_path is None or decoy_password is None:
            raise ValueError("deniable layer requires both passwords and a decoy payload")
        with open(decoy_path, "rb") as df:
            decoy_bytes = df.read()
        slot_plain_size = DENIABLE_LEN_PREFIX + max(len(data), len(decoy_bytes))
        salt = crypto.new_salt()
        base_nonce = crypto.new_nonce()
        slot1_salt = crypto.new_salt()
        slot1_nonce = crypto.new_nonce()
        slot0_ct = _build_deniable_slot(data, slot_plain_size, password, salt, base_nonce)
        slot1_ct = _build_deniable_slot(decoy_bytes, slot_plain_size, decoy_password, slot1_salt, slot1_nonce)
        # Pad both slot ciphertexts to the same length to avoid any length tell.
        target = max(len(slot0_ct), len(slot1_ct))
        if len(slot0_ct) != len(slot1_ct):
            # Should not happen because slot plaintexts are equal-size, but keep belt-and-braces.
            raise RuntimeError("deniable slot ciphertexts differ in length unexpectedly")
        data = slot0_ct + slot1_ct
        argon2_time = crypto.DEFAULT_ARGON2_TIME
        argon2_mem = crypto.DEFAULT_ARGON2_MEMORY_KB
        argon2_par = crypto.DEFAULT_ARGON2_PARALLELISM
    elif crypto_layer == crypto.LAYER_X25519_CHACHA:
        if recipient_pubkey is None:
            raise ValueError("recipient_pubkey is required for x25519-chacha20")
        salt = crypto.new_salt()
        base_nonce = crypto.new_nonce()
        ephemeral_pub, enc = crypto.x25519_sender_encryptor(recipient_pubkey, salt, base_nonce)
        data = enc.update(data) + enc.finalize()
    elif crypto_layer == crypto.LAYER_X25519_MULTI:
        if not recipient_pubkeys:
            raise ValueError("recipient_pubkeys list is required for x25519-multi-chacha20")
        if len(recipient_pubkeys) + pad_recipients > 255:
            raise ValueError("recipient_pubkeys + pad_recipients must be <= 255")
        salt = crypto.new_salt()
        base_nonce = crypto.new_nonce()
        ephemeral_pub, wrapped_deks, dek = crypto.x25519_multi_envelope_seal(recipient_pubkeys, salt)
        # Pad the slot table with indistinguishable random blobs so analysts cannot count real recipients.
        slots = list(wrapped_deks)
        for _ in range(pad_recipients):
            slots.append(os.urandom(crypto.X25519_WRAPPED_DEK_BYTES))
        # Shuffle so real slots are not always first.
        import random as _random
        rng = _random.SystemRandom()
        rng.shuffle(slots)
        slot_table = struct.pack("B", len(slots)) + b"".join(slots)
        # Bind the slot table (real + dummy slots together) to the DEK so an
        # attacker cannot strip dummies or swap slots without invalidating the
        # MAC. The attacker has no way to recompute this MAC because they do
        # not know the DEK.
        binding_mac = hmac.new(dek, MULTI_BINDING_INFO + ephemeral_pub + slot_table, hashlib.sha256).digest()
        body_enc = crypto.chacha_poly_encryptor(dek, base_nonce)
        body_ct = body_enc.update(data) + body_enc.finalize()
        data = slot_table + binding_mac + body_ct
    elif crypto_layer != crypto.LAYER_NONE:
        if password is None:
            raise ValueError("password is required when crypto layer is enabled")
        salt = crypto.new_salt()
        base_nonce = crypto.new_nonce()
        if kdf == crypto.KDF_PBKDF2:
            key = crypto.derive_key_pbkdf2(password, salt)
            pbkdf2_iter = crypto.DEFAULT_PBKDF2_ITERATIONS
        elif kdf == crypto.KDF_ARGON2ID:
            key = crypto.derive_key_argon2id(password, salt)
            argon2_time = crypto.DEFAULT_ARGON2_TIME
            argon2_mem = crypto.DEFAULT_ARGON2_MEMORY_KB
            argon2_par = crypto.DEFAULT_ARGON2_PARALLELISM
        else:
            raise ValueError(f"Crypto layer {crypto_layer} requires a KDF")
        enc = crypto.make_encryptor(crypto_layer, key, base_nonce)
        data = enc.update(data) + enc.finalize()

    return {
        "stored": data,
        "salt": salt,
        "base_nonce": base_nonce,
        "pbkdf2_iter": pbkdf2_iter,
        "argon2_time": argon2_time,
        "argon2_mem": argon2_mem,
        "argon2_par": argon2_par,
        "ephemeral_pub": ephemeral_pub,
        "slot1_salt": slot1_salt,
        "slot1_nonce": slot1_nonce,
    }


def _process_incoming_payload(stored, *, ecc_layer, crypto_layer, kdf, password, header, identity_privkey=None):
    if crypto_layer == crypto.LAYER_DENIABLE:
        if password is None:
            raise RuntimeError("Carrier uses deniable encryption; provide a passphrase.")
        if len(stored) % 2 != 0:
            raise RuntimeError("Deniable carrier has an odd stored length; cannot split slots.")
        half = len(stored) // 2
        slot0 = stored[:half]
        slot1 = stored[half:]
        recovered = _try_deniable_slot(slot0, password, header["salt"], header["base_nonce"])
        if recovered is None:
            recovered = _try_deniable_slot(slot1, password, header["deniable_slot1_salt"], header["deniable_slot1_nonce"])
        if recovered is None:
            raise RuntimeError("Neither deniable slot decrypts with the supplied passphrase.")
        stored = recovered
    elif crypto_layer == crypto.LAYER_X25519_CHACHA:
        if identity_privkey is None:
            raise RuntimeError("Carrier is asymmetrically encrypted; recipient private key required")
        salt = header["salt"]
        base_nonce = header["base_nonce"]
        ephemeral_pub = header["x25519_ephemeral_pubkey"]
        if ephemeral_pub == b"\x00" * 32:
            raise RuntimeError("Carrier missing ephemeral public key in header")
        dec = crypto.x25519_recipient_decryptor(identity_privkey, ephemeral_pub, salt, base_nonce)
        try:
            stored = dec.update(stored) + dec.finalize()
        except Exception as exc:
            raise RuntimeError(f"Decryption failed (wrong private key or corrupt carrier): {exc}")
    elif crypto_layer == crypto.LAYER_X25519_MULTI:
        if identity_privkey is None:
            raise RuntimeError("Carrier is multi-recipient asymmetrically encrypted; provide --identity")
        salt = header["salt"]
        base_nonce = header["base_nonce"]
        ephemeral_pub = header["x25519_ephemeral_pubkey"]
        if ephemeral_pub == b"\x00" * 32:
            raise RuntimeError("Carrier missing ephemeral public key in header")
        if len(stored) < 1 + crypto.X25519_WRAPPED_DEK_BYTES + MULTI_BINDING_BYTES:
            raise RuntimeError("Multi-recipient carrier payload too short")
        slot_count = stored[0]
        slot_table_size = 1 + slot_count * crypto.X25519_WRAPPED_DEK_BYTES
        if len(stored) < slot_table_size + MULTI_BINDING_BYTES:
            raise RuntimeError("Multi-recipient carrier: slot table truncated")
        slot_table = stored[:slot_table_size]
        binding_mac_stored = stored[slot_table_size : slot_table_size + MULTI_BINDING_BYTES]
        body_ct = stored[slot_table_size + MULTI_BINDING_BYTES:]
        wrapped_list = [
            stored[1 + i * crypto.X25519_WRAPPED_DEK_BYTES : 1 + (i + 1) * crypto.X25519_WRAPPED_DEK_BYTES]
            for i in range(slot_count)
        ]
        dek = crypto.x25519_multi_envelope_open(identity_privkey, ephemeral_pub, wrapped_list, salt)
        if dek is None:
            raise RuntimeError("None of the wrapped slots match this private key. Are you a listed recipient?")
        binding_mac_expected = hmac.new(dek, MULTI_BINDING_INFO + ephemeral_pub + slot_table, hashlib.sha256).digest()
        if not hmac.compare_digest(binding_mac_stored, binding_mac_expected):
            raise RuntimeError("Slot-set binding MAC mismatch -- the recipient slot table has been tampered with.")
        try:
            body_dec = crypto.chacha_poly_decryptor(dek, base_nonce)
            stored = body_dec.update(body_ct) + body_dec.finalize()
        except Exception as exc:
            raise RuntimeError(f"Multi-recipient body decryption failed: {exc}")
    elif crypto_layer != crypto.LAYER_NONE:
        if password is None:
            raise RuntimeError("Carrier is encrypted; password required")
        salt = header["salt"]
        base_nonce = header["base_nonce"]
        if kdf == crypto.KDF_PBKDF2:
            key = crypto.derive_key_pbkdf2(password, salt, iterations=header["pbkdf2_iterations"] or crypto.DEFAULT_PBKDF2_ITERATIONS)
        elif kdf == crypto.KDF_ARGON2ID:
            key = crypto.derive_key_argon2id(
                password, salt,
                time_cost=header["argon2_time"] or crypto.DEFAULT_ARGON2_TIME,
                memory_kb=header["argon2_memory_kb"] or crypto.DEFAULT_ARGON2_MEMORY_KB,
                parallelism=header["argon2_parallelism"] or crypto.DEFAULT_ARGON2_PARALLELISM,
            )
        else:
            raise RuntimeError(f"Unsupported KDF id {header['kdf_id']}")
        dec = crypto.make_decryptor(crypto_layer, key, base_nonce)
        try:
            stored = dec.update(stored) + dec.finalize()
        except Exception as exc:
            raise RuntimeError(f"Decryption failed (wrong password or corrupt carrier): {exc}")

    if ecc_layer == ecc.ECC_RS_255_223:
        try:
            stored = ecc.decode_rs(stored)
        except ecc.ReedSolomonError as exc:
            raise RuntimeError(f"Reed-Solomon decoding failed (too many errors): {exc}")

    return stored


# ---------------------------------------------------------------------------
# Public embed
# ---------------------------------------------------------------------------


def embed_stego(
    input_path,
    output_path,
    *,
    mode=stego.MODE_SEQ,
    crypto_layer=crypto.LAYER_AES_GCM,
    kdf=crypto.KDF_ARGON2ID,
    ecc_layer=ecc.ECC_NONE,
    cover_video=None,
    default_dir="default",
    password=None,
    recipient_pubkey=None,
    recipient_pubkeys=None,
    decoy_path=None,
    decoy_password=None,
    pad_recipients=0,
    preset="veryfast",
    adaptive_threshold=4,
    progress=True,
):
    if mode not in stego.MODE_IDS:
        raise ValueError(f"Unknown mode: {mode}")
    if crypto_layer not in crypto.LAYER_IDS:
        raise ValueError(f"Unknown crypto layer: {crypto_layer}")
    if crypto_layer == crypto.LAYER_NONE:
        kdf = "none"
    elif crypto_layer == crypto.LAYER_X25519_CHACHA:
        kdf = crypto.KDF_HKDF_SHA256
    elif crypto_layer == crypto.LAYER_X25519_MULTI:
        kdf = crypto.KDF_HKDF_SHA256
    elif crypto_layer == crypto.LAYER_DENIABLE:
        kdf = crypto.KDF_ARGON2ID
    if kdf not in crypto.KDF_IDS:
        raise ValueError(f"Unknown KDF: {kdf}")
    if ecc_layer not in ecc.ECC_IDS:
        raise ValueError(f"Unknown ECC layer: {ecc_layer}")

    cover = Path(cover_video) if cover_video else find_default_cover(default_dir)
    info = _probe_video(cover)
    width, height = info["width"], info["height"]
    if width % 2 or height % 2:
        raise RuntimeError(f"Cover video dimensions must be even for yuv420p (got {width}x{height})")
    fps = info["fps"]
    frame_size = stego.yuv420p_frame_bytes(width, height)

    file_size = os.path.getsize(input_path)
    plaintext_sha256 = sha256_file(input_path)
    if crypto_layer == crypto.LAYER_DENIABLE:
        # Deniable carriers must not reveal which slot is real, so the
        # plaintext-level SHA and size are zeroed in the header. Per-slot AEAD
        # tags already provide integrity.
        plaintext_sha256 = "0" * 64
        file_size = 0

    processed = _process_outgoing_payload(
        input_path,
        ecc_layer=ecc_layer,
        crypto_layer=crypto_layer,
        kdf=kdf,
        password=password,
        recipient_pubkey=recipient_pubkey,
        recipient_pubkeys=recipient_pubkeys,
        decoy_path=decoy_path,
        decoy_password=decoy_password,
        pad_recipients=pad_recipients,
    )
    stored_bytes = processed["stored"]
    stored_len = len(stored_bytes)

    position_seed = b"\x00" * 16
    if mode in (stego.MODE_SHUFFLED, stego.MODE_ADAPTIVE):
        position_seed = os.urandom(16)

    header = stego.build_stego_header_v2(
        mode_id=stego.MODE_IDS[mode],
        crypto_id=crypto.LAYER_IDS[crypto_layer],
        kdf_id=crypto.KDF_IDS[kdf],
        ecc_id=ecc.ECC_IDS[ecc_layer],
        plaintext_len=file_size,
        stored_len=stored_len,
        plaintext_sha256_hex=plaintext_sha256,
        salt=processed["salt"],
        base_nonce=processed["base_nonce"],
        pbkdf2_iterations=processed["pbkdf2_iter"],
        argon2_time=processed["argon2_time"],
        argon2_memory_kb=processed["argon2_mem"],
        argon2_parallelism=processed["argon2_par"],
        position_seed=position_seed,
        adaptive_threshold_x1000=int(adaptive_threshold * 1000),
        x25519_ephemeral_pubkey=processed["ephemeral_pub"],
        deniable_slot1_salt=processed["slot1_salt"],
        deniable_slot1_nonce=processed["slot1_nonce"],
    )

    total_bits_needed = HEADER_BIT_COUNT + stored_len * 8
    capacity_bits = frame_size * info["frame_count"]

    if progress:
        print(f"cover:                  {cover}")
        print(f"cover dimensions:       {width}x{height} @ {fps} fps")
        print(f"cover frames:           {info['frame_count']}")
        print(f"mode:                   {mode}")
        print(f"crypto:                 {crypto_layer}")
        print(f"kdf:                    {kdf}")
        print(f"ecc:                    {ecc_layer}")
        print(f"plaintext bytes:        {file_size:,}")
        print(f"stored bytes (post-ecc/crypto): {stored_len:,}")
        print(f"capacity bytes (1-bit/byte):     {capacity_bits//8:,}")

    if total_bits_needed > capacity_bits:
        raise RuntimeError(
            f"Payload too large for this cover. Need {total_bits_needed//8:,} bytes total "
            f"(header+ecc+crypto), cover gives {capacity_bits//8:,} bytes of LSB capacity. "
            f"Use a longer/higher-resolution cover or drop ECC."
        )

    header_bits = np.unpackbits(np.frombuffer(header, dtype=np.uint8))
    payload_bits = np.unpackbits(np.frombuffer(stored_bytes, dtype=np.uint8))

    decoder = _decode_pipe(cover, width, height)
    encoder = _encode_pipe(output_path, width, height, fps,
                           cover_path=cover, has_audio=info["has_audio"], preset=preset)

    bits_cursor = 0
    frames_processed = 0
    total_payload_bits = len(payload_bits)
    mode_id = stego.MODE_IDS[mode]

    try:
        while True:
            raw_frame = read_exact(decoder.stdout, frame_size)
            if not raw_frame:
                break
            if len(raw_frame) != frame_size:
                raise RuntimeError(f"Truncated cover frame at index {frames_processed}")
            frame_arr = np.frombuffer(raw_frame, dtype=np.uint8).copy()

            if frames_processed == 0:
                # Header bits ALWAYS go in fixed positions 0..HEADER_BIT_COUNT-1.
                stego.hide_bytes_in_plane(frame_arr, header, offset=0)

            payload_bits_remaining = total_payload_bits - bits_cursor
            if payload_bits_remaining > 0:
                positions = _select_positions(
                    mode_id, frame_arr, frames_processed,
                    position_seed=position_seed,
                    adaptive_threshold=adaptive_threshold,
                    exclude_header=True,
                )
                if len(positions) > 0:
                    take = min(payload_bits_remaining, len(positions))
                    used = positions[:take]
                    bits_to_hide = payload_bits[bits_cursor:bits_cursor + take]
                    frame_arr[used] = (frame_arr[used] & 0xFE) | bits_to_hide
                    bits_cursor += take

            encoder.stdin.write(frame_arr.tobytes())
            frames_processed += 1

            if progress and frames_processed % 30 == 0:
                pct = 100.0 * frames_processed / max(1, info["frame_count"])
                print(f"  frame {frames_processed}/{info['frame_count']} ({pct:.1f}%)")

        encoder.stdin.close()
        enc_rc = encoder.wait()
        decoder.wait()
        if enc_rc != 0:
            err = encoder.stderr.read().decode("utf-8", errors="replace") if encoder.stderr else ""
            raise RuntimeError(f"Encoder failed (rc={enc_rc}): {err}")
    except Exception:
        for proc in (decoder, encoder):
            try:
                proc.kill()
            except Exception:
                pass
        raise

    if bits_cursor < total_payload_bits:
        raise RuntimeError(
            f"Cover ran out of viable positions before payload fully embedded "
            f"(hidden {bits_cursor}/{total_payload_bits} bits). "
            f"Use a longer cover, lower --adaptive-threshold, or switch to stego-seq."
        )

    return {
        "cover_video": str(cover),
        "output": str(output_path),
        "payload_size": file_size,
        "stored_size": stored_len,
        "mode": mode,
        "crypto": crypto_layer,
        "kdf": kdf,
        "ecc": ecc_layer,
        "encrypted": crypto_layer != crypto.LAYER_NONE,
        "sha256": plaintext_sha256,
        "frames_processed": frames_processed,
        "capacity_bytes": capacity_bits // 8,
    }


# ---------------------------------------------------------------------------
# Public extract
# ---------------------------------------------------------------------------


def is_stego_carrier(video_path):
    try:
        info = _probe_video(video_path)
    except Exception:
        return False
    try:
        frame_bytes = _read_first_frame_bytes(video_path, info["width"], info["height"], 4)
    except Exception:
        return False
    arr = np.frombuffer(frame_bytes, dtype=np.uint8)
    magic = stego.reveal_bytes_from_plane(arr, 4, offset=0)
    return magic in (stego.STEGO_MAGIC_V2, stego.STEGO_MAGIC_V1)


def extract_stego(input_path, output_path, password=None, identity_privkey=None, progress=True):
    info = _probe_video(input_path)
    width, height = info["width"], info["height"]
    frame_size = stego.yuv420p_frame_bytes(width, height)

    first_raw = _read_first_frame_bytes(input_path, width, height, frame_size)
    first_arr = np.frombuffer(first_raw, dtype=np.uint8).copy()

    # Peek at magic to decide v1 vs v2 path.
    magic = stego.reveal_bytes_from_plane(first_arr, 4, offset=0)
    if magic == stego.STEGO_MAGIC_V1:
        return _extract_stego_v1(input_path, output_path, password=password, progress=progress)
    if magic != stego.STEGO_MAGIC_V2:
        raise RuntimeError("Not a FrameCourier stego carrier (magic mismatch)")

    header_bytes = stego.reveal_bytes_from_plane(first_arr, stego.HEADER_SIZE, offset=0)
    header = stego.parse_stego_header_v2(header_bytes)

    mode_id = header["mode_id"]
    crypto_id = header["crypto_id"]
    kdf_id = header["kdf_id"]
    ecc_id = header["ecc_id"]
    mode = stego.MODE_NAMES[mode_id]
    crypto_layer = crypto.LAYER_NAMES.get(crypto_id, "?")
    kdf = crypto.KDF_NAMES.get(kdf_id, "?")
    ecc_layer = ecc.ECC_NAMES.get(ecc_id, "?")
    if crypto_layer == "?" or kdf == "?" or ecc_layer == "?":
        raise RuntimeError(f"Unknown crypto/kdf/ecc id in header: {crypto_id}/{kdf_id}/{ecc_id}")
    stored_len = header["stored_len"]
    plaintext_len = header["plaintext_len"]
    plaintext_sha256_expected = header["plaintext_sha256"]
    position_seed = header["position_seed"]
    adaptive_threshold = header["adaptive_threshold_x1000"] / 1000.0
    if adaptive_threshold <= 0:
        adaptive_threshold = 4

    if progress:
        print(f"v2 carrier detected")
        print(f"  mode:   {mode}")
        print(f"  crypto: {crypto_layer}")
        print(f"  kdf:    {kdf}")
        print(f"  ecc:    {ecc_layer}")
        print(f"  stored bytes: {stored_len:,}")
        print(f"  plaintext bytes: {plaintext_len:,}")

    if crypto_layer in (crypto.LAYER_X25519_CHACHA, crypto.LAYER_X25519_MULTI):
        if identity_privkey is None:
            raise RuntimeError("This carrier was encrypted to an X25519 public key. Provide --identity.")
    elif crypto_layer != crypto.LAYER_NONE and password is None:
        raise RuntimeError("This carrier is encrypted. Provide --password.")

    payload_bits_needed = stored_len * 8
    collected_bits = []
    decoder = _decode_pipe(input_path, width, height)
    try:
        # First frame already in memory.
        positions = _select_positions(
            mode_id, first_arr, 0,
            position_seed=position_seed,
            adaptive_threshold=adaptive_threshold,
            exclude_header=True,
        )
        take = min(len(positions), payload_bits_needed)
        if take > 0:
            collected_bits.append(first_arr[positions[:take]] & 1)
        bits_collected = take

        # Consume the first frame from the decoder pipe so subsequent reads line up.
        _ = read_exact(decoder.stdout, frame_size)

        frame_idx = 1
        while bits_collected < payload_bits_needed:
            raw_frame = read_exact(decoder.stdout, frame_size)
            if not raw_frame:
                raise RuntimeError(
                    f"Frames exhausted while extracting (got {bits_collected}/{payload_bits_needed} bits)"
                )
            if len(raw_frame) != frame_size:
                raise RuntimeError(f"Truncated frame at index {frame_idx}")
            frame_arr = np.frombuffer(raw_frame, dtype=np.uint8).copy()
            positions = _select_positions(
                mode_id, frame_arr, frame_idx,
                position_seed=position_seed,
                adaptive_threshold=adaptive_threshold,
                exclude_header=False,
            )
            if len(positions) > 0:
                remaining = payload_bits_needed - bits_collected
                take = min(remaining, len(positions))
                collected_bits.append(frame_arr[positions[:take]] & 1)
                bits_collected += take
            frame_idx += 1
            if progress and frame_idx % 30 == 0:
                pct = 100.0 * bits_collected / max(1, payload_bits_needed)
                print(f"  recovered {pct:.1f}% of stored payload")

        decoder.terminate()
        try:
            decoder.wait(timeout=5)
        except Exception:
            decoder.kill()
    except Exception:
        try:
            decoder.kill()
        except Exception:
            pass
        raise

    all_bits = np.concatenate(collected_bits)[:payload_bits_needed]
    stored_recovered = bytes(np.packbits(all_bits))[:stored_len]

    plaintext = _process_incoming_payload(
        stored_recovered,
        ecc_layer=ecc_layer,
        crypto_layer=crypto_layer,
        kdf=kdf,
        password=password,
        header=header,
        identity_privkey=identity_privkey,
    )

    actual_sha = hashlib.sha256(plaintext).hexdigest()
    if crypto_layer != crypto.LAYER_DENIABLE:
        if len(plaintext) != plaintext_len:
            raise RuntimeError(f"Recovered {len(plaintext)} bytes, expected {plaintext_len}")

        if actual_sha != plaintext_sha256_expected:
            if crypto_layer != crypto.LAYER_NONE:
                raise RuntimeError("SHA-256 mismatch. Wrong password or carrier modified.")
            raise RuntimeError("SHA-256 mismatch. Carrier was changed or corrupted.")

    Path(output_path).write_bytes(plaintext)

    return {
        "output": str(output_path),
        "payload_size": len(plaintext),
        "stored_size": stored_len,
        "mode": mode,
        "crypto": crypto_layer,
        "kdf": kdf,
        "ecc": ecc_layer,
        "encrypted": crypto_layer != crypto.LAYER_NONE,
        "sha256": actual_sha,
    }


# ---------------------------------------------------------------------------
# v1 backwards-compatible reader (used by old stego-seq carriers).
# ---------------------------------------------------------------------------


def _extract_stego_v1(input_path, output_path, password=None, progress=True):
    info = _probe_video(input_path)
    width, height = info["width"], info["height"]
    frame_size = stego.yuv420p_frame_bytes(width, height)

    first_raw = _read_first_frame_bytes(input_path, width, height, frame_size)
    first_arr = np.frombuffer(first_raw, dtype=np.uint8).copy()

    probe_bytes = stego.reveal_bytes_from_plane(first_arr, stego.HEADER_ENCRYPTED_BYTES, offset=0)
    header = stego.parse_stego_header(probe_bytes)
    header_byte_count = header["header_byte_count"]
    payload_bit_length = header["payload_bit_length"]
    payload_byte_length = (payload_bit_length + 7) // 8
    encrypted = header["encrypted"]

    if progress:
        print("v1 carrier detected (stego-seq)")
        print(f"  payload size: {payload_byte_length:,} bytes")
        print(f"  encryption:   {'on' if encrypted else 'off'}")

    if encrypted and password is None:
        raise RuntimeError("This carrier is encrypted. Provide --password to extract.")

    dec_obj = None
    if encrypted:
        iterations = crypto.DEFAULT_KDF_ITERATIONS
        dec_obj = crypto.decryptor(password, header["salt"], header["nonce"], iterations=iterations)

    digest = hashlib.sha256()
    written = 0
    decoder = _decode_pipe(input_path, width, height)
    out_file = open(output_path, "wb")
    try:
        # Consume the first frame from the pipe.
        _ = read_exact(decoder.stdout, frame_size)

        payload_bits_pending = payload_bit_length
        bits_in_first_frame = min(payload_bits_pending, frame_size - header_byte_count * 8)
        bytes_in_first = bits_in_first_frame // 8
        leftover_bits = bits_in_first_frame - bytes_in_first * 8
        carry_bits = np.empty(0, dtype=np.uint8)

        if bytes_in_first > 0:
            chunk = stego.reveal_bytes_from_plane(first_arr, bytes_in_first, offset=header_byte_count * 8)
            plain = dec_obj.update(chunk) if dec_obj else chunk
            limit = min(payload_byte_length - written, len(plain))
            if limit > 0:
                out_file.write(plain[:limit])
                digest.update(plain[:limit])
                written += limit
            payload_bits_pending -= bits_in_first_frame

        if leftover_bits > 0:
            offset = header_byte_count * 8 + bytes_in_first * 8
            carry_bits = first_arr[offset:offset + leftover_bits] & 1

        frame_idx = 1
        while payload_bits_pending > 0:
            raw_frame = read_exact(decoder.stdout, frame_size)
            if not raw_frame:
                raise RuntimeError(f"Frames exhausted at frame {frame_idx}")
            if len(raw_frame) != frame_size:
                raise RuntimeError(f"Truncated frame at index {frame_idx}")
            frame = np.frombuffer(raw_frame, dtype=np.uint8).copy()
            available_bits = min(payload_bits_pending, frame_size)
            usable_bits = len(carry_bits) + available_bits
            full_bytes = usable_bits // 8
            byte_bits_from_frame = max(0, full_bytes * 8 - len(carry_bits))
            new_carry = available_bits - byte_bits_from_frame

            if full_bytes > 0:
                frame_bits = frame[:byte_bits_from_frame] & 1
                combined = np.concatenate([carry_bits, frame_bits])
                chunk = bytes(np.packbits(combined))
                plain = dec_obj.update(chunk) if dec_obj else chunk
                limit = min(payload_byte_length - written, len(plain))
                if limit > 0:
                    out_file.write(plain[:limit])
                    digest.update(plain[:limit])
                    written += limit

            carry_bits = (frame[byte_bits_from_frame:byte_bits_from_frame + new_carry] & 1) if new_carry > 0 else np.empty(0, dtype=np.uint8)
            payload_bits_pending -= available_bits
            frame_idx += 1

        if len(carry_bits) > 0:
            padded = np.concatenate([carry_bits, np.zeros(8 - len(carry_bits), dtype=np.uint8)])
            tail = bytes(np.packbits(padded))
            plain = dec_obj.update(tail) if dec_obj else tail
            limit = min(payload_byte_length - written, len(plain))
            if limit > 0:
                out_file.write(plain[:limit])
                digest.update(plain[:limit])
                written += limit

        decoder.terminate()
        try:
            decoder.wait(timeout=5)
        except Exception:
            decoder.kill()
    except Exception:
        try:
            decoder.kill()
        except Exception:
            pass
        raise
    finally:
        out_file.close()

    if written != payload_byte_length:
        raise RuntimeError(f"Recovered {written} bytes, expected {payload_byte_length}")
    if digest.hexdigest() != header["plaintext_sha256"]:
        if encrypted:
            raise RuntimeError("SHA-256 mismatch. Wrong password or carrier modified.")
        raise RuntimeError("SHA-256 mismatch. Carrier corrupted.")

    return {
        "output": str(output_path),
        "payload_size": payload_byte_length,
        "encrypted": encrypted,
        "sha256": header["plaintext_sha256"],
        "mode": "stego-seq (v1)",
        "crypto": "aes-ctr" if encrypted else "none",
        "kdf": "pbkdf2-hmac-sha256" if encrypted else "none",
        "ecc": "none",
    }
