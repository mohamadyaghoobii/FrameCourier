# FrameCourier

> **Hide arbitrary binary files inside ordinary-looking H.264 video carriers.**
> Lossless, AEAD-encrypted, signature-verifiable, multi-recipient, plausibly
> deniable, with a 28-subcommand professional CLI.

FrameCourier is a Python + FFmpeg toolchain for *carrier* steganography. The
default pipeline takes an arbitrary binary file, optionally encrypts it with a
modern AEAD scheme, optionally protects it with Reed-Solomon ECC, and hides
the resulting bytes in the least-significant bits of a cover video's pixels.
The carrier is re-encoded with **lossless H.264** at `yuv420p` so the LSBs
survive the roundtrip bit-exactly, and the resulting `.mp4` is
indistinguishable from any other 720p / 1080p H.264 video to `ffprobe`,
`MediaInfo`, or a SOC-level analyst.

```
+---------------+   embed    +-----------+   extract   +---------------+
| payload.bin   | ---------> | carrier   | ----------> | recovered.bin |
| (any file)    |  + cover   |   .mp4    |             | (byte-exact)  |
+---------------+            +-----------+             +---------------+
```

This README is the long-form reference. For a one-line summary of every
command, run `framecourier modes` and `framecourier --help`. For an
in-depth explanation of any technique (including detection vectors), run
`framecourier explain <name>`.

---

## Table of contents

* [1. What FrameCourier is, in one minute](#1-what-framecourier-is-in-one-minute)
* [2. Quick start](#2-quick-start)
* [3. Architecture](#3-architecture)
* [4. Complete CLI reference](#4-complete-cli-reference)
* [5. Carrier modes](#5-carrier-modes)
* [6. Crypto layers](#6-crypto-layers)
* [7. ECC layers](#7-ecc-layers)
* [8. Presets](#8-presets)
* [9. Real-world workflows](#9-real-world-workflows)
* [10. Threat model and detection](#10-threat-model-and-detection)
* [11. Configuration](#11-configuration)
* [12. Tests](#12-tests)
* [13. Project layout](#13-project-layout)
* [14. Honest limits](#14-honest-limits)
* [15. Roadmap](#15-roadmap)
* [16. License](#16-license)

---

## 1. What FrameCourier is, in one minute

* **Carrier steganography**, not container steganography. The payload lives
  in pixel LSBs of a real H.264 video stream, not in a side stream or a magic
  comment field.
* **Lossless H.264 yuv420p**. The encode/decode roundtrip is bit-exact, so the
  modified LSBs survive cleanly. The carrier still reports as ordinary
  `codec_name=h264 pix_fmt=yuv420p` to every tool.
* **Pluggable security stack**: pick a *mode* (where to put bits), a *crypto
  layer* (how to encrypt them), an *ECC layer* (how robust the bits are), and
  optionally a *signature* (who produced the carrier).
* **Professional CLI**: 28 subcommands covering embed / extract, key
  management, signature, asymmetric and multi-recipient delivery, plausible
  deniability, environment validation, steganalysis, recommendations,
  fingerprints, audit log, bulk operations, configuration, and a built-in
  error-diagnosis catalogue.
* **Honest about its limits**: the empirical LSB-survival rate under lossy
  re-encode is documented from real measurements. `framecourier explain
  stego-robust` prints the actual numbers.

Result: a single `.mp4` that plays in any media player, looks like ordinary
H.264 to every analysis tool, and carries up to ~50 MiB of payload per second
of cover at 1080p.

## 2. Quick start

### 2.1 Install (Windows / Linux / macOS)

```bash
python -m venv .venv
. .venv/bin/activate          # or .\.venv\Scripts\Activate.ps1 on PowerShell
python -m pip install -r requirements.txt
```

You also need `ffmpeg` and `ffprobe` on PATH. On Windows, dropping
`ffmpeg.exe` and `ffprobe.exe` into `./bin/` is enough -- FrameCourier
searches that folder first.

Verify with:

```bash
python tools/check_env.py
```

### 2.2 Hello, FrameCourier

```bash
# 1. Make a cover (one line; ffmpeg flags are baked in)
python framecourier.py make-cover default/default.mp4

# 2. Hide a file in it, with a passphrase
python framecourier.py embed secret.zip carrier.mp4 --prompt-password

# 3. Recover the file
python framecourier.py extract carrier.mp4 recovered.zip --prompt-password
```

`carrier.mp4` is a normal H.264 video; it plays in any media player, and
`ffprobe` shows nothing unusual.

### 2.3 Asymmetric, no shared passphrase

```bash
# Recipient generates a keypair once
python framecourier.py keygen alice.key
# Sends alice.key.pub through any channel

# Sender hides a file using just alice's public key
python framecourier.py embed secret.zip carrier.mp4 --recipient alice.key.pub

# Recipient recovers it
python framecourier.py extract carrier.mp4 out.zip --identity alice.key
```

### 2.4 Investigate any carrier

```bash
python framecourier.py probe carrier.mp4         # high-level scan
python framecourier.py info carrier.mp4          # header metadata
python framecourier.py fingerprint carrier.mp4   # deterministic JSON
python framecourier.py steganalyse carrier.mp4   # built-in detectors
```

## 3. Architecture

FrameCourier is organised as a Python package (`datavideo/`) plus an
entry-point script (`framecourier.py`). Each concern is in its own module so
the code is small and auditable.

```
+-------------------+     +-----------------+     +------------------+
| user payload      | ->  | optional        | ->  | optional crypto  |
| (any file)        |     | Reed-Solomon    |     | (none / AES-CTR  |
+-------------------+     | ECC             |     |  / AES-GCM / CC- |
                          +-----------------+     |  Poly / X25519 / |
                                                  |  X25519-multi /  |
                                                  |  deniable)       |
                                                  +--------+---------+
                                                           |
                                                           v
+-------------------+     +-----------------+     +------------------+
| H.264 -qp 0       | <-  | yuv420p frames  | <-  | LSB embed:       |
| yuv420p .mp4      |     | with modified   |     | seq / shuffled / |
| carrier           |     | LSBs            |     | adaptive         |
+-------------------+     +-----------------+     +------------------+
```

Carrier header (always the very first 192 bytes of the LSBs of frame 0):

```
v2 stego header
+----------+----------+--------------------------------------------------+
| offset   | size     | field                                            |
+----------+----------+--------------------------------------------------+
| 0..3     |  4       | magic = \xfc\x46\x43\xa2                         |
| 4..7     |  4       | version + header_size                            |
| 8..11    |  4       | mode_id, crypto_id, kdf_id, ecc_id               |
| 12..27   | 16       | plaintext_len, stored_len (uint64 each)          |
| 28..59   | 32       | plaintext SHA-256                                |
| 60..75   | 16       | KDF salt                                         |
| 76..87   | 12       | cipher base nonce                                |
| 88..100  | 13       | KDF parameters (pbkdf2 iters / argon2 t,m,p)     |
| 101      |  1       | reserved                                         |
| 102..117 | 16       | position seed (mode-shuffled / adaptive)         |
| 118..121 |  4       | adaptive threshold x1000                         |
| 122..153 | 32       | X25519 ephemeral pubkey (asymmetric only)        |
| 154..181 | 28       | deniable slot-1 salt + nonce                     |
| 182..191 | 10       | reserved / zero pad                              |
+----------+----------+--------------------------------------------------+
```

Everything the extractor needs is in the header. The only thing the operator
supplies is the passphrase or `--identity` private key (and the carrier file
itself).

## 4. Complete CLI reference

Every subcommand has its own `--help`. The high-level list:

### Carrier operations

| Command | What it does |
|---|---|
| `embed <in> <out>` | Hide a payload into a cover. Picks mode / crypto / ECC. Supports `--preset`. |
| `extract <carrier> <out>` | Auto-detect carrier type and recover the payload. |
| `bulk-embed <in-dir> <out-dir>` | Embed every file in a folder, same cover and options. |
| `bulk-extract <in-dir> <out-dir>` | Extract every carrier in a folder. |
| `info <carrier>` | Read the v2 header metadata of a stego carrier. |
| `fingerprint <carrier>` | Deterministic JSON fingerprint (sha256 + container + header + .sig). |
| `diff <a> <b>` | Field-by-field comparison of two fingerprints. |
| `probe <video>` | Scan a video for FrameCourier signatures and stego hints. |
| `benchmark <cover> <carrier>` | PSNR / SSIM of cover vs. carrier + capacity report. |

### Keys & signatures

| Command | What it does |
|---|---|
| `keygen <out>` | X25519 (default) or Ed25519 keypair. `--export-age`, `--import-age` for age interop. |
| `sign <file> --key K` | Produce an Ed25519 detached signature (JSON `.sig` file). |
| `verify <file> <sig>` | Verify an Ed25519 detached signature. Optional `--pubkey` for signer pinning. |

### Steganalysis

| Command | What it does |
|---|---|
| `steganalyse <video>` | Chi-square / sample-pair / RS-divergence detectors. `--external` calls `stegdetect` / `aletheia` if installed. |
| `evaluate --cover-video V` | Batch-generate carriers across modes and measure detection. |

### Cover selection

| Command | What it does |
|---|---|
| `cover-score <video>` | Rate a video as a stego cover (texture, entropy, capacity, recommended mode). |
| `suggest-cover <folder>` | Rank every video in a folder by stego suitability. |
| `make-cover <path>` | Generate a quick test cover (testsrc2 / mandelbrot / smptebars / noise / gradient). |

### Discoverability

| Command | What it does |
|---|---|
| `modes` | One-line summary of every mode, crypto layer, and ECC layer. |
| `explain <name>` | Deep briefing on a specific technique (mechanism, strengths, weaknesses, detection vectors). |
| `recipes [name]` | Named bundles of mode + crypto + kdf + ecc, used by `--preset`. |
| `examples [name]` | Real-world workflow examples. |
| `search <query>` | Keyword search across modes / crypto / ECC / recipes / examples. |
| `interactive` | Menu-driven walkthrough for embed / extract. |

### Environment

| Command | What it does |
|---|---|
| `doctor` | Validate Python, FFmpeg, codecs, optional tools, config file, audit log, disk space. |
| `version` | FrameCourier + Python + FFmpeg + dependency versions. |
| `config` | View / edit `~/.framecourier/config.json` defaults. |
| `audit` | Show the local audit log (opt-in via env var `FRAMECOURIER_AUDIT_LOG`). |
| `why <error>` | Explain a common FrameCourier error and give a concrete fix recipe. |

## 5. Carrier modes

| Mode | Output stream shape | Detection cost vs. SOC analyst | Notes |
|---|---|---|---|
| `stego-seq` | Single h264 yuv420p stream | Lowest, but sequential modification region is visible to chi-square | Fastest, simplest. Use for tiny payloads. |
| `stego-shuffled` (default) | Single h264 yuv420p stream | Defeats clustering attacks; encrypted bits look uniform | Recommended general default. |
| `stego-adaptive` | Single h264 yuv420p stream | Modifications hide inside natural texture noise | Best against blind steganalysis; capacity depends on cover texture. |
| `distributed` | h264 cover + extra FFV1 streams | Trivially visible to `ffprobe` (FFV1 is rare) | Cover is byte-exact unchanged. Research/integrity use. |
| `legacy` | h264 cover + 1 FFV1 stream at midpoint | Same as distributed | Old FrameCourier carriers, kept for compatibility only. |

Run `framecourier explain stego-shuffled` for the full briefing on any mode.

## 6. Crypto layers

| Layer | KDF | AEAD | Notes |
|---|---|---|---|
| `none` | --- | --- | No confidentiality. Payload visible to anyone who reads the LSBs. |
| `aes-ctr` | PBKDF2-HMAC-SHA256 | No | Stream cipher. Integrity only from plaintext SHA-256. Legacy compatibility. |
| `aes-gcm` (default) | Argon2id | Yes | AEAD in 64 KiB chunks. Tampering aborts decryption with a clear error. |
| `chacha-poly` | Argon2id | Yes | Software-friendly profile; preferred on ARM and other AES-NI-less hosts. |
| `x25519-chacha20` | HKDF-SHA256 over X25519 ECDH | Yes | **Asymmetric.** Sender needs only the recipient's public key. Per-carrier ephemeral keypair. |
| `x25519-multi-chacha20` | HKDF-SHA256 over X25519 ECDH | Yes | **Multi-recipient asymmetric.** One carrier addressed to N public keys via envelope encryption. Slot table is bound to the DEK with HMAC-SHA256 so dummy slots cannot be stripped. |
| `deniable` | Argon2id (per slot) | Yes (per slot) | **Plausibly deniable.** Two payloads + two passphrases share one carrier. Neither passphrase reveals the other slot's existence. |

## 7. ECC layers

| Layer | Overhead | Capability |
|---|---|---|
| `none` | 0 % | A single bit flip in storage corrupts the payload. |
| `rs-255-223` | ~13 % | Reed-Solomon. Corrects up to 16 byte errors per 255-byte block. |

ECC sits *under* the crypto layer: the byte stream is first RS-encoded, then
encrypted, then LSB-embedded. The extractor reverses the chain.

## 8. Presets

Named bundles of mode + crypto + kdf + ecc, applied with `--preset NAME`.

| Preset | Mode | Crypto | KDF | ECC | When to reach for it |
|---|---|---|---|---|---|
| `paranoid` | stego-adaptive | aes-gcm | argon2id | rs-255-223 | Strongest symmetric config. |
| `stealth` | stego-shuffled | aes-gcm | argon2id | none | Recommended general default. |
| `robust` | stego-seq | chacha-poly | argon2id | rs-255-223 | Storage that may introduce sparse bit errors. |
| `asymmetric` | stego-shuffled | x25519-chacha20 | hkdf-sha256 | none | Recipient publishes a public key. |
| `deniable` | stego-shuffled | deniable | argon2id | none | You may be compelled to reveal a passphrase. |
| `plain` | stego-shuffled | none | none | none | Demos / testing only. |

`framecourier recipes` lists them; `framecourier recipes <name>` shows the
full description and what flags it expands to.

## 9. Real-world workflows

### 9.1 Strong symmetric

```bash
python framecourier.py embed secret.zip carrier.mp4 --preset paranoid --prompt-password
python framecourier.py extract carrier.mp4 recovered.zip --prompt-password
```

### 9.2 Asymmetric to one recipient

```bash
# Recipient (once):
python framecourier.py keygen alice.key
# alice.key.pub is the recipient blob; alice.key is the private key.

# Sender:
python framecourier.py embed secret.zip carrier.mp4 --recipient alice.key.pub

# Recipient:
python framecourier.py extract carrier.mp4 out.zip --identity alice.key
```

### 9.3 Multi-recipient with dummy slots

```bash
python framecourier.py embed secret.zip carrier.mp4 \
    --recipient alice.key.pub --recipient bob.key.pub --recipient carol.key.pub \
    --pad-recipients 30
# ffprobe sees a normal H.264 video. The carrier's slot table holds 33 wrapped
# DEKs (3 real + 30 random). An analyst cannot count real recipients.
```

### 9.4 Deniable carrier

```bash
export FC_REAL="real-pass"
export FC_DECOY="decoy-pass"

python framecourier.py embed secret.zip carrier.mp4 \
    --decoy-file decoy.zip \
    --password-env FC_REAL --decoy-password-env FC_DECOY

# Real password reveals secret.zip:
python framecourier.py extract carrier.mp4 out.zip --password-env FC_REAL
# Decoy password reveals decoy.zip; the other slot is indistinguishable from random.
python framecourier.py extract carrier.mp4 out.zip --password-env FC_DECOY
```

### 9.5 Signed carrier (sender attestation)

```bash
python framecourier.py keygen sender.ed25519 --type ed25519

# Embed + sign in one step:
python framecourier.py embed in.bin carrier.mp4 --prompt-password \
    --sign-with sender.ed25519

# Verify + extract:
python framecourier.py extract carrier.mp4 out.bin --prompt-password \
    --verify-with sender.ed25519.pub
```

### 9.6 Bulk operations

```bash
python framecourier.py bulk-embed payloads/ carriers/ \
    --cover-video default/default.mp4 --prompt-password

python framecourier.py bulk-extract carriers/ recovered/ --prompt-password
```

### 9.7 Forensic + archival

```bash
python framecourier.py fingerprint carrier.mp4 > carrier.fingerprint.json
python framecourier.py diff carrier1.mp4 carrier2.mp4
```

### 9.8 age interop

```bash
# Generate a FrameCourier key AND print it in age format:
python framecourier.py keygen alice --export-age

# Import an existing age key file:
python framecourier.py keygen recovered --import-age path/to/key.age

# --recipient and --identity accept age files directly:
python framecourier.py embed in.bin out.mp4 --recipient alice.age.pub
python framecourier.py extract out.mp4 rec.bin --identity alice.age.key
```

## 10. Threat model and detection

FrameCourier's default `stego-shuffled + aes-gcm + argon2id` configuration is
designed to look like an ordinary H.264 video to a SOC-level analyst running
`ffprobe`, `MediaInfo`, or a Splunk query. Concretely:

| What an analyst sees | Result |
|---|---|
| `ffprobe -show_streams carrier.mp4` | One `codec_name=h264`, `pix_fmt=yuv420p`. Encoder tags match libx264. No second stream. No `DataVideoSegment` strings. |
| File extension / MIME | `.mp4` / `video/mp4`. Plays in any media player. |
| Audio | Cover's original audio stream is preserved (`-c:a copy`). |
| Sysmon Event 1 | Captures the `ffmpeg ... -c:v libx264 ... -qp 0` process if your SOC watches for it. |
| Bitrate vs. duration | **Anomalously high**: lossless H.264 is ~5-20x a normal MP4 of the same length. SIEM rules looking for "video file is larger than its claimed duration warrants" will flag the carrier. |

FrameCourier is **not** designed to defeat:

* **Statistical steganalysis** (chi-square, RS, sample-pair, S-UNIWARD, SRNet).
  Run `framecourier steganalyse <carrier>` to see the built-in detectors'
  scores; the encrypted-AEAD layers help on chi-square (uniform bits) but not
  on modification-position attacks.
* **Cover-source mismatch**: if the analyst already has the original cover, a
  byte-wise diff trivially reveals every modified pixel. Never re-publish the
  cover.
* **Platform re-encoding**. YouTube, Telegram, WhatsApp, Instagram all
  re-encode video. Empirical measurement (`framecourier explain stego-robust`)
  shows only ~16-19% of LSBs survive `libx264 -crf 18`. Transfer carriers as
  file attachments, not as video uploads.

`framecourier explain <name>` gives the per-mode and per-layer detection
analysis including Splunk SPL examples, Sysmon Event IDs, Windows Event
Viewer markers, statistical attacks, manual inspection, and network DLP.

## 11. Configuration

FrameCourier reads optional defaults from `~/.framecourier/config.json` (override
the path with `FRAMECOURIER_CONFIG`). All recognised keys:

| Key | Used by |
|---|---|
| `default_mode` | `embed` |
| `default_crypto` | `embed` |
| `default_kdf` | `embed` |
| `default_ecc` | `embed` |
| `default_cover` | `embed` (path to cover video) |
| `default_dir` | `embed` (folder searched when no `--cover-video`) |
| `x264_preset` | `embed` (libx264 preset, default `veryfast`) |
| `adaptive_threshold` | `embed` (`stego-adaptive` edge strength) |
| `audit_log` | `audit` (defaults to disabled; the env var still wins) |

```bash
python framecourier.py config set default_mode stego-adaptive
python framecourier.py config set default_crypto chacha-poly
python framecourier.py config set audit_log "$HOME/.framecourier/audit.log"
python framecourier.py config show
```

The audit log records one JSONL row per embed / extract: timestamp, mode,
crypto, ECC, payload SHA-256, carrier SHA-256, paths. **Passphrases and
plaintext are never recorded** -- only sha-only fingerprints.

## 12. Tests

```bash
python -m pip install pytest
python -m pytest -q
```

Expected: **76 passed, 3 skipped**. The skipped tests are intentionally
disabled CI-expensive variants.

CI runs the same suite via `.github/workflows/test.yml` on Ubuntu and Windows
across Python 3.10 / 3.11 / 3.12 on every push.

The test suite is organised by phase:

| File | Covers |
|---|---|
| `tests/test_roundtrip.py` | Plain encode / decode roundtrip. |
| `tests/test_stego.py` | Stego mode plain & encrypted roundtrips, ffprobe sanity, capacity check. |
| `tests/test_v2_cli.py` | v2 header modes (seq / shuffled / adaptive), CLI subcommands, presets. |
| `tests/test_z_distributed_segments.py` | Distributed FFV1 carrier mode. |
| `tests/test_phase3.py` | X25519 single-recipient, legacy direct-mode encryption, steganalyse. |
| `tests/test_phase4.py` | Deniable encryption, recipes, discoverability subcommands. |
| `tests/test_phase5.py` | Cover scoring, suggest-cover, multi-recipient X25519, audit log. |
| `tests/test_phase6.py` | Ed25519 sign/verify, dummy slot padding, config file overrides. |
| `tests/test_phase7.py` | Slot binding MAC, version + doctor polish, empirical stego-robust documentation. |
| `tests/test_phase8.py` | Bech32 codec, age key import/export, fingerprint + diff. |
| `tests/test_phase9.py` | Bulk-embed/extract, `why` catalogue, `make-cover`. |

## 13. Project layout

```
FrameCourier/
+- framecourier.py              # entry point
+- pyproject.toml               # packaging metadata
+- requirements.txt             # cryptography, numpy, argon2-cffi, reedsolo
+- README.md, ROADMAP.md
+- datavideo/                   # the toolbox
|  +- __init__.py
|  +- cli.py                    # argparse subparsers for every command
|  +- core.py                   # frame math, raw legacy header
|  +- crypto.py                 # AES-CTR / AES-GCM / ChaCha20 / X25519 / Ed25519 / bech32 helpers
|  +- bech32.py                 # BIP-0173 codec (used by age interop)
|  +- ecc.py                    # Reed-Solomon (255, 223)
|  +- stego.py                  # v2 stego header + LSB helpers
|  +- stego_carrier.py          # mode dispatcher (embed / extract)
|  +- segmenter.py              # distributed-mode segment encoder
|  +- carrier.py                # distributed-mode MKV mux
|  +- cover.py, encoder.py,     # legacy direct DataVideo mode
|  |  decoder.py, extractor.py
|  +- explain.py                # mode / crypto / ECC briefing content
|  +- recipes.py                # presets + canned examples
|  +- probe_analysis.py         # 'probe' command
|  +- steganalysis.py           # chi-square / sample-pair / RS detectors + external tool adapters
|  +- cover_quality.py          # 'cover-score' / 'suggest-cover'
|  +- benchmark.py              # PSNR / SSIM
|  +- audit.py                  # opt-in audit log
|  +- config.py                 # ~/.framecourier/config.json
|  +- fingerprint.py            # fingerprint + diff
|  +- why.py                    # diagnostic catalogue
|  +- ffmpeg_tools.py           # ffmpeg / ffprobe path resolution
+- tests/                       # 76 passing tests + 3 skipped
+- tools/check_env.py           # 'doctor' precursor
+- bin/                         # local ffmpeg.exe / ffprobe.exe (Windows)
+- default/                     # default cover folder (gitignored)
+- .github/workflows/test.yml   # CI matrix
```

## 14. Honest limits

* **Lossless H.264 has unusual bitrate.** The single anomaly that survives
  every other defense is "this 720p video is 15-25 MB for 10 seconds." A
  bitrate-anomaly SIEM rule will flag the carrier. Use covers whose
  high-bitrate is plausible (screen recordings, archival, professional camera
  raw exports).
* **No re-encode survival at the LSB layer.** Empirical measurement on a
  Mandelbrot cover encoded with `libx264 -crf 14..28`: only ~16-19% of LSB
  modifications survive a single re-encode (vs. 100% at `-qp 0`). The
  honest path to platform-survival is DCT-domain hiding, which is research-
  level engineering work and lives on the roadmap.
* **Statistical steganalysis is not magic-resistant.** Generic chi-square /
  sample-pair / RS detectors are largely defeated by encrypted AEAD payloads,
  but content-aware detectors (S-UNIWARD, MiPOD, SRNet) are tuned for
  content-adaptive embedding and can detect `stego-adaptive` given enough
  payload and a good analyst.
* **Cover reuse is fatal.** Never publish the original cover in any channel
  where an analyst can correlate it with the carrier. A byte-wise diff
  recovers every modified pixel instantly.
* **No forward secrecy ratchet.** A leaked X25519 private key compromises
  every past carrier ever sent to that recipient. Rotate keys.

## 15. Roadmap

Landed:

```
Phase 1: encryption layer, signature-free metadata
Phase 2: stego mode (single H.264 stream), v1 header
Phase 3: AEAD crypto stack (AES-GCM, ChaCha-Poly), Reed-Solomon, v2 header,
         stego-seq/shuffled/adaptive, full CLI, explain, probe, benchmark
Phase 4: X25519 asymmetric, steganalysis harness, CI, legacy mode encryption
Phase 5: cover scoring, multi-recipient X25519, audit log
Phase 6: deniable encryption, dummy slot padding, config file
Phase 7: Ed25519 sign/verify, recipient-set hash binding, slot tampering MAC
Phase 8: bech32 / age interop, carrier fingerprint + diff
Phase 9: bulk operations, error-diagnosis 'why' catalogue, make-cover
```

Still open:

* DCT-domain hiding (F5 / nsF5; research-level)
* GUI front-end (Tk or Electron)
* Per-message X25519 ratchet for forward secrecy
* PGP key import (RSA + Ed25519)
* OpenSSH ed25519 key import for signing

## 16. License

MIT.
