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

Target: encryption.

Tasks:

```text
Add password-based encryption
Use authenticated encryption
Store salt and KDF parameters in metadata
Never store the password
Verify decryption before writing final output
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
