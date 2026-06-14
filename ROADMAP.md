DataVideo roadmap
=================

Version 0.2 (current, DVF2)
---------------------------

Status: implemented in this package.

Done:

```text
DVF2 format: manifest frame + per-frame header
Per-frame magic, version, frame_index, payload_len
Per-frame CRC32 (payload) + header CRC32
Lossless-codec validation on decode with clear errors
FFmpeg/ffprobe pre-flight validation (ensure_ffmpeg)
Non-MKV output warning on the encode CLI
Streaming encode/decode, no temp image files
SHA256 verification on decode
unittest suite: metadata, edge cases, full roundtrip
```

Still open (moved toward later versions): byte-based progress, output-size
estimate, block manifest / repair, compression, encryption.

Version 0.1
-----------

Status: superseded by 0.2.

Features:

```text
File to FFV1 MKV
FFV1 MKV to file
Streaming encode
Streaming decode
Embedded metadata
SHA256 verification
No third-party Python dependencies
```

Version 0.2
-----------

Target: better diagnostics and usability.

Tasks:

```text
Add benchmark script
Add output size estimate before encoding
Add progress based on bytes instead of frames only
Add automatic output filename suggestion
Add strict extension warning for non-MKV output
Add better Windows FFmpeg setup guide
```

Version 0.3
-----------

Target: block-level integrity.

Tasks:

```text
Add block manifest
Add block CRC32
Add decoder corruption report
Add missing block list
Add repair-video generation mode
```

Version 0.4
-----------

Target: compression.

Tasks:

```text
Add optional zstd compression
Store compression mode in metadata
Decode compressed payload back to original file
Benchmark compressed and uncompressed modes
```

Version 0.5
-----------

Status: landed in v0.3.0.

Done:

```text
AES-256-CTR + PBKDF2 (legacy compatibility)
AES-256-GCM in 64 KiB chunks + Argon2id KDF (default)
XChaCha20-Poly1305 + Argon2id (ARM / no-AES-NI hosts)
Reed-Solomon (255, 223) optional ECC layer
v2 stego carrier: header carries mode/crypto/kdf/ecc + parameters
Plaintext SHA-256 catches wrong passwords on every layer
Carrier metadata stripped of DataVideoSegment-* and DVS_* signatures
```

Open:

```text
Per-frame manifest encryption (header itself becomes opaque)
Deniable encryption (decoy passphrase reveals an innocent payload)
```

v0.4.0 (Phase 3) additions:

```text
X25519 + ChaCha20-Poly1305 asymmetric layer (no shared passphrase)
HKDF-SHA256 key derivation for asymmetric layer
framecourier keygen subcommand
AES-CTR + Argon2id encryption for the legacy direct DataVideo mode
Built-in steganalysis (chi-square + sample-pair + RS-style)
framecourier steganalyse and framecourier evaluate subcommands
GitHub Actions matrix CI (ubuntu/windows x py3.10/3.11/3.12)
```

v0.5.0 (Phase 4) additions:

```text
deniable crypto layer (two-slot AEAD: real + decoy payloads share one carrier)
embed --preset paranoid|stealth|robust|asymmetric|deniable|plain
framecourier recipes (named bundles, with 'when to reach for this')
framecourier examples (real-world workflows)
framecourier search <query> (search modes/crypto/ECC/recipes/examples)
framecourier doctor (environment validation)
steganalyse --external (invoke stegdetect / aletheia if installed)
explain entries for deniable + recipes
```

v0.6.0 (Phase 5) additions:

```text
Multi-recipient X25519 (envelope encryption, --recipient repeatable)
framecourier cover-score: rate a video as a stego cover (texture, LSB entropy, capacity, recommended mode)
framecourier suggest-cover: rank video files in a folder for stego use
framecourier audit + opt-in FRAMECOURIER_AUDIT_LOG (sha-only, never stores passphrases or plaintext)
explain entry for x25519-multi-chacha20
```

v0.7.0 (Phase 6) additions:

```text
Ed25519 digital signatures (FrameCourier-format keys, .sig JSON blobs)
framecourier keygen --type ed25519, framecourier sign, framecourier verify
embed --sign-with: auto-sign the produced carrier
extract --verify-with: refuse to extract unless the signature matches
embed --pad-recipients N: append N indistinguishable dummy slots so the real
    recipient count of a multi-recipient carrier is hidden
~/.framecourier/config.json: per-user defaults for mode/crypto/kdf/ecc/cover/
    audit_log/x264_preset/adaptive_threshold
framecourier config show / get / set / unset / path / keys
```

v0.8.0 (Phase 7) additions:

```text
Slot-binding HMAC for x25519-multi-chacha20: the slot table (real + dummy)
    is bound to the DEK so an attacker cannot strip dummies or substitute slots
framecourier version: FrameCourier + Python + FFmpeg + dep versions
framecourier doctor: now also reports config-file presence, audit-log target,
    and free disk space
explain stego-robust: documents the empirical LSB-survival result
    (CRF 14..28 ~16-19% survival vs. CRF 0 100%) and explains why the LSB
    family of techniques is not the right place to look for re-encode robustness
```

v0.9.0 (Phase 8) additions:

```text
Bech32 codec (datavideo/bech32.py): BIP-0173-style encode/decode
age interop:
    framecourier keygen --export-age  (also print age recipient + secret key)
    framecourier keygen --import-age <path> (import age key as FrameCourier key)
    --recipient now accepts age1... recipient files transparently
    --identity now accepts AGE-SECRET-KEY-1... files transparently
framecourier fingerprint <carrier>: deterministic JSON fingerprint
framecourier diff <a> <b>: field-by-field carrier comparison
```

v1.0.0 (Phase 9) additions:

```text
framecourier bulk-embed / bulk-extract: process whole folders in one command,
    per-file status reporting, continues past per-file errors
framecourier make-cover: one-line test-cover generator (testsrc2, mandelbrot,
    smptebars, noise, gradient filters)
framecourier why <error>: looks up a common error message and prints the cause
    plus a concrete fix recipe
```

Open for v1.1+:

```text
DCT-domain hiding (F5 / nsF5; research-level engineering work)
GUI front-end (Tk or Electron)
Per-message X25519 ratchet for forward secrecy
PGP key import (RSA + Ed25519)
OpenSSH ed25519 key import for signing
```

Version 0.6
-----------

Target: stego maturity and detection awareness.

Status: partial.

Done:

```text
stego-seq: LSB sequential mode
stego-shuffled: PRNG-keyed per-frame LSB permutation
stego-adaptive: edge-strength-gated LSB embedding
framecourier probe: chi-square + magic + bitrate analyser
framecourier explain: per-mode detection-vector briefings
framecourier benchmark: PSNR / SSIM cover-vs-carrier
framecourier interactive: menu-driven walkthrough
Subcommand-based CLI with pyproject.toml + console_scripts entry
```

Open:

```text
stego-robust: lossy H.264 + RS-tuned, designed to survive YouTube re-encode
DCT-domain hiding (research-level)
Steganalysis evaluation harness (stegdetect / aletheia regression)
GUI front-end (Tk or Electron)
GitHub Actions matrix CI (Windows / Linux / macOS)
Performance benchmark suite for large payloads
```

Version 0.6
-----------

Target: production-friendly packaging.

Tasks:

```text
Add GUI
Add portable Windows bundle
Add automated tests
Add GitHub Actions test matrix
Add binary release packaging
```
