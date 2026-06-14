"""Stego header v2 + LSB packing helpers.

The header is the very first ``header_size`` bytes recovered from the LSBs of
the first stego frame. v2 carries the full configuration of the carrier so
``extract`` doesn't need any user input beyond the passphrase: mode, crypto
layer, KDF parameters, ECC layer, plaintext SHA-256, salt, base nonce, and the
mode-specific PRNG seed all live inside.

Layout (big-endian, all integers, total 192 bytes, zero-padded at the tail):

  offset  size  field
  ------  ----  -------------------------------------------------
  0       4     magic = b"\\xfc\\x46\\x43\\xa2"
  4       2     version = 2
  6       2     header_size (always 192 for v2)
  8       1     mode_id (0=seq, 1=shuffled, 2=adaptive)
  9       1     crypto_id (see crypto.LAYER_IDS)
  10      1     kdf_id   (see crypto.KDF_IDS)
  11      1     ecc_id   (see ecc.ECC_IDS)
  12      8     plaintext_len (uint64)
  20      8     stored_len    (uint64; after ECC+crypto, this is what's hidden)
  28      32    plaintext_sha256
  60      16    salt (zero if no KDF)
  76      12    base_nonce (zero if no crypto)
  88      4     pbkdf2_iterations (uint32)
  92      4     argon2_time_cost  (uint32)
  96      4     argon2_memory_kb  (uint32)
  100     1     argon2_parallelism
  101     1     reserved
  102     16    position_seed (zero if mode_id == seq)
  118     4     adaptive_threshold_x1000 (uint32)
  122     32    x25519_ephemeral_pubkey (zero unless crypto_id == x25519-chacha20)
  154     16    deniable_slot1_salt    (zero unless crypto_id == deniable)
  170     12    deniable_slot1_nonce   (zero unless crypto_id == deniable)
  182     10    reserved / zero pad

v1 carriers (magic ``\\xfc\\x46\\x43\\xa1``) are still recognised by
``parse_stego_header_v1`` which the old single-mode extractor used.
"""

import struct

import numpy as np

STEGO_MAGIC_V2 = b"\xfc\x46\x43\xa2"
STEGO_MAGIC_V1 = b"\xfc\x46\x43\xa1"
STEGO_VERSION = 2
HEADER_SIZE = 192

MODE_SEQ = "stego-seq"
MODE_SHUFFLED = "stego-shuffled"
MODE_ADAPTIVE = "stego-adaptive"

MODE_IDS = {
    MODE_SEQ: 0,
    MODE_SHUFFLED: 1,
    MODE_ADAPTIVE: 2,
}
MODE_NAMES = {v: k for k, v in MODE_IDS.items()}

# v1 legacy
FLAG_ENCRYPTED = 1 << 0
HEADER_PLAIN_BYTES = 48
HEADER_ENCRYPTED_BYTES = 76
# Kept so legacy imports continue to work.
STEGO_MAGIC = STEGO_MAGIC_V1


def build_stego_header_v2(
    *,
    mode_id,
    crypto_id,
    kdf_id,
    ecc_id,
    plaintext_len,
    stored_len,
    plaintext_sha256_hex,
    salt=b"\x00" * 16,
    base_nonce=b"\x00" * 12,
    pbkdf2_iterations=0,
    argon2_time=0,
    argon2_memory_kb=0,
    argon2_parallelism=0,
    position_seed=b"\x00" * 16,
    adaptive_threshold_x1000=0,
    x25519_ephemeral_pubkey=b"\x00" * 32,
    deniable_slot1_salt=b"\x00" * 16,
    deniable_slot1_nonce=b"\x00" * 12,
):
    if len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    if len(base_nonce) != 12:
        raise ValueError("base_nonce must be 12 bytes")
    if len(position_seed) != 16:
        raise ValueError("position_seed must be 16 bytes")
    if len(x25519_ephemeral_pubkey) != 32:
        raise ValueError("x25519_ephemeral_pubkey must be 32 bytes")
    if len(deniable_slot1_salt) != 16:
        raise ValueError("deniable_slot1_salt must be 16 bytes")
    if len(deniable_slot1_nonce) != 12:
        raise ValueError("deniable_slot1_nonce must be 12 bytes")
    sha = bytes.fromhex(plaintext_sha256_hex)
    if len(sha) != 32:
        raise ValueError("plaintext_sha256_hex must be 64 hex chars")
    parts = bytearray()
    parts.extend(STEGO_MAGIC_V2)
    parts.extend(struct.pack(">H", STEGO_VERSION))
    parts.extend(struct.pack(">H", HEADER_SIZE))
    parts.append(mode_id & 0xFF)
    parts.append(crypto_id & 0xFF)
    parts.append(kdf_id & 0xFF)
    parts.append(ecc_id & 0xFF)
    parts.extend(struct.pack(">Q", plaintext_len))
    parts.extend(struct.pack(">Q", stored_len))
    parts.extend(sha)
    parts.extend(salt)
    parts.extend(base_nonce)
    parts.extend(struct.pack(">I", pbkdf2_iterations))
    parts.extend(struct.pack(">I", argon2_time))
    parts.extend(struct.pack(">I", argon2_memory_kb))
    parts.append(argon2_parallelism & 0xFF)
    parts.append(0)
    parts.extend(position_seed)
    parts.extend(struct.pack(">I", adaptive_threshold_x1000))
    parts.extend(x25519_ephemeral_pubkey)
    parts.extend(deniable_slot1_salt)
    parts.extend(deniable_slot1_nonce)
    if len(parts) > HEADER_SIZE:
        raise RuntimeError(f"Stego header overflow ({len(parts)} > {HEADER_SIZE})")
    parts.extend(b"\x00" * (HEADER_SIZE - len(parts)))
    return bytes(parts)


def parse_stego_header_v2(header_bytes):
    if len(header_bytes) < 8:
        raise ValueError("Header too short")
    if header_bytes[:4] != STEGO_MAGIC_V2:
        raise ValueError("Not a v2 stego carrier (magic mismatch)")
    version = struct.unpack(">H", header_bytes[4:6])[0]
    header_size = struct.unpack(">H", header_bytes[6:8])[0]
    if version != STEGO_VERSION:
        raise ValueError(f"Unsupported stego v2 sub-version: {version}")
    if header_size != HEADER_SIZE:
        raise ValueError(f"Unexpected header_size: {header_size}")
    if len(header_bytes) < header_size:
        raise ValueError("Truncated header")
    h = header_bytes
    return {
        "version": version,
        "header_size": header_size,
        "mode_id": h[8],
        "crypto_id": h[9],
        "kdf_id": h[10],
        "ecc_id": h[11],
        "plaintext_len": struct.unpack(">Q", h[12:20])[0],
        "stored_len": struct.unpack(">Q", h[20:28])[0],
        "plaintext_sha256": h[28:60].hex(),
        "salt": bytes(h[60:76]),
        "base_nonce": bytes(h[76:88]),
        "pbkdf2_iterations": struct.unpack(">I", h[88:92])[0],
        "argon2_time": struct.unpack(">I", h[92:96])[0],
        "argon2_memory_kb": struct.unpack(">I", h[96:100])[0],
        "argon2_parallelism": h[100],
        "position_seed": bytes(h[102:118]),
        "adaptive_threshold_x1000": struct.unpack(">I", h[118:122])[0],
        "x25519_ephemeral_pubkey": bytes(h[122:154]),
        "deniable_slot1_salt": bytes(h[154:170]),
        "deniable_slot1_nonce": bytes(h[170:182]),
    }


# ---------------------------------------------------------------------------
# v1 backwards compatibility (existing stego-seq carriers).
# ---------------------------------------------------------------------------


def build_stego_header(payload_bit_length, plaintext_sha256_hex, encrypted=False, salt=b"", nonce=b""):
    """Legacy v1 header builder (kept for the original stego-seq carrier code path)."""
    if payload_bit_length < 0:
        raise ValueError("payload_bit_length must be non-negative")
    flags = FLAG_ENCRYPTED if encrypted else 0
    sha_bytes = bytes.fromhex(plaintext_sha256_hex)
    if len(sha_bytes) != 32:
        raise ValueError("plaintext_sha256_hex must be a 32-byte (64 hex char) SHA-256")
    parts = [
        STEGO_MAGIC_V1,
        struct.pack(">H", 1),
        struct.pack(">H", flags),
        struct.pack(">Q", payload_bit_length),
        sha_bytes,
    ]
    if encrypted:
        if len(salt) != 16:
            raise ValueError("salt must be 16 bytes when encrypted")
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes when encrypted")
        parts.append(salt)
        parts.append(nonce)
    blob = b"".join(parts)
    expected = HEADER_ENCRYPTED_BYTES if encrypted else HEADER_PLAIN_BYTES
    if len(blob) != expected:
        raise RuntimeError(f"Stego v1 header size mismatch: {len(blob)} != {expected}")
    return blob


def parse_stego_header(header_bytes):
    """Legacy v1 header parser."""
    if len(header_bytes) < HEADER_PLAIN_BYTES:
        raise ValueError("Header too short")
    if header_bytes[:4] != STEGO_MAGIC_V1:
        raise ValueError("Not a v1 stego carrier (magic mismatch)")
    version = struct.unpack(">H", header_bytes[4:6])[0]
    if version != 1:
        raise ValueError(f"Unsupported stego v1 version: {version}")
    flags = struct.unpack(">H", header_bytes[6:8])[0]
    payload_bit_length = struct.unpack(">Q", header_bytes[8:16])[0]
    plaintext_sha256_hex = header_bytes[16:48].hex()
    encrypted = bool(flags & FLAG_ENCRYPTED)
    salt = b""
    nonce = b""
    header_byte_count = HEADER_PLAIN_BYTES
    if encrypted:
        if len(header_bytes) < HEADER_ENCRYPTED_BYTES:
            raise ValueError("Encrypted v1 header missing salt/nonce")
        salt = bytes(header_bytes[48:64])
        nonce = bytes(header_bytes[64:76])
        header_byte_count = HEADER_ENCRYPTED_BYTES
    return {
        "version": version,
        "encrypted": encrypted,
        "payload_bit_length": payload_bit_length,
        "plaintext_sha256": plaintext_sha256_hex,
        "salt": salt,
        "nonce": nonce,
        "header_byte_count": header_byte_count,
    }


# ---------------------------------------------------------------------------
# LSB packing primitives (shared by all modes).
# ---------------------------------------------------------------------------


def hide_bytes_in_plane(plane, data, offset=0):
    """Replace LSB of ``plane[offset:offset+len(data)*8]`` with bits of ``data``."""
    if not data:
        return 0
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    end = offset + len(bits)
    if end > len(plane):
        raise ValueError(f"Plane too small to hide {len(data)} bytes at offset {offset}")
    plane[offset:end] = (plane[offset:end] & 0xFE) | bits
    return len(bits)


def reveal_bytes_from_plane(plane, byte_count, offset=0):
    if byte_count <= 0:
        return b""
    bit_count = byte_count * 8
    end = offset + bit_count
    if end > len(plane):
        raise ValueError(f"Plane too small to reveal {byte_count} bytes at offset {offset}")
    bits = plane[offset:end] & 1
    return bytes(np.packbits(bits))


def hide_bits_at_positions(plane, positions, bits):
    """Hide ``bits`` (uint8 array of 0/1) at the LSB of ``plane[positions]``."""
    if len(bits) == 0:
        return
    if len(bits) > len(positions):
        raise ValueError("Not enough positions for the bits to hide")
    used = positions[:len(bits)]
    plane[used] = (plane[used] & 0xFE) | bits


def reveal_bits_at_positions(plane, positions):
    return plane[positions] & 1


def yuv420p_frame_bytes(width, height):
    if width % 2 or height % 2:
        raise ValueError("yuv420p requires even dimensions")
    return width * height * 3 // 2


def lsb_byte_capacity_per_frame(width, height):
    return yuv420p_frame_bytes(width, height) // 8
