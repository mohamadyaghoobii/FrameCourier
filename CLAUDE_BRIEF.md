DataVideo continuation brief
============================

STATUS UPDATE
-------------

The format described in the historical sections below as "DVF1" has been
superseded by **DVF2**, which is now implemented. DVF2 adds a dedicated manifest
frame plus a per-frame header (magic, version, flags, frame_index, payload_len,
payload_crc32, header_crc32). The encoder/decoder validate every frame and the
whole-file SHA256. The codebase was reorganized into:

```text
datavideo/core.py        frame format + integrity
datavideo/metadata.py    manifest build/serialize/parse/validate
datavideo/ffmpeg_io.py   ffmpeg/ffprobe discovery, validation, commands, probe
datavideo/encoder.py     streaming encode
datavideo/decoder.py     streaming decode
datavideo/verify.py      SHA256 helpers + verification
```

Tests are stdlib `unittest` (no pytest): `python -m unittest discover -s tests`.
See README.md for the authoritative format and usage. The sections below are
kept for historical context only.

---

This project converts arbitrary files into lossless video files and decodes those videos back into the exact original files.

The user does not want QR codes. The user wants high-volume data transfer by representing binary data as video frames. The generated video file itself is the carrier. The workflow is not screen recording and not camera scanning.

Primary goal
------------

Build a practical high-throughput binary-to-video and video-to-binary transport system.

Current version
---------------

The current version is a working proof of concept using:

```text
Python standard library
FFmpeg
FFprobe
FFV1 lossless codec
MKV container
Raw BGR24 video frames through stdin and stdout pipes
SHA256 verification
```

Current command line usage
--------------------------

Encode:

```powershell
python encode.py input.bin data_video.mkv
```

Decode:

```powershell
python decode.py data_video.mkv recovered.bin
```

Test:

```powershell
python tests/test_roundtrip.py
```

Main implementation files
-------------------------

```text
datavideo/core.py
```

Contains metadata packing, header parsing, frame size calculation, padding, and SHA256 helpers.

```text
datavideo/encoder.py
```

Streams the input file into raw frames and pipes them into FFmpeg as FFV1 MKV.

```text
datavideo/decoder.py
```

Uses FFprobe to detect dimensions, pipes FFmpeg raw frames back to Python, parses metadata, restores the file, and verifies SHA256.

```text
datavideo/ffmpeg_tools.py
```

Finds ffmpeg and ffprobe from PATH or from local project locations.

Important design constraint
---------------------------

The video must remain lossless. If the MKV is re-encoded, uploaded as a normal video, compressed by a messenger, or converted to H.264 or H.265, the data will likely be destroyed.

Good transfer channels:

```text
USB
External disk
SFTP
Network share
Cloud raw file storage
```

Bad transfer channels:

```text
WhatsApp video
Telegram compressed video
Instagram
YouTube
Any automatic video optimizer
```

Current header format
---------------------

The first frame begins with:

```text
4 bytes magic: DVF1
4 bytes big-endian JSON metadata length
JSON metadata
zero padding up to header_bytes
payload bytes
```

The remaining frames contain payload bytes and zero padding in the final frame.

Current metadata fields
-----------------------

```text
magic
version
codec
container
pixel_format
channels
width
height
fps
header_bytes
frame_bytes
first_frame_payload_bytes
data_bytes_per_full_frame
source_file_name
file_size
sha256
total_frames
created_utc
```

What to improve next
--------------------

Priority 1: block-level integrity

Add block metadata so the decoder can detect exactly which region is corrupted.

Suggested model:

```text
file -> blocks -> frames
```

Each block should have:

```text
block_id
block_offset
block_size
block_crc32
block_sha256 optional
frame range
```

Priority 2: resume and repair

Allow the decoder to report missing or corrupted blocks. Add a mode to generate a repair video containing only the missing blocks.

Priority 3: optional compression

Add a compression stage before video encoding. Use streaming compression. Zstandard is a good candidate, but it adds a third-party dependency.

Pipeline:

```text
input -> compress -> datavideo encode
```

Priority 4: optional encryption

Add encryption before frame encoding.

Pipeline:

```text
input -> compress optional -> encrypt -> datavideo encode
```

Use an authenticated encryption scheme. Avoid unauthenticated encryption.

Priority 5: stronger protocol versioning

Keep the current `DVF1` magic for this proof of concept. Use `DVF2` after changing the frame or block layout.

Priority 6: performance benchmark

Add a script that reports:

```text
input size
output size
encode time
decode time
effective MB per second
video duration
frame count
compression ratio
```

Priority 7: GUI

Add a simple GUI only after the CLI is stable.

Best next implementation task
-----------------------------

Create `DVF2` with block-level metadata and CRC. Keep the current DVF1 decoder for compatibility.

Suggested DVF2 structure:

```text
Manifest frame repeated 3 times
Data frames
Final manifest frame repeated 3 times
```

Frame payload layout:

```text
frame_magic
session_id
frame_id
total_frames
block_id
block_offset
payload_len
payload_crc32
payload
padding
```

This makes the format more resilient and easier to repair.

Potential concern
-----------------

FFmpeg may internally store BGR24 as BGR0 for FFV1, then decode back to BGR24. The included roundtrip test verifies that the current pipe format still recovers bytes exactly.

Do not replace FFV1 with lossy codecs.

Do not use MP4 for the exact-data version.

Do not remove SHA256 verification.
