# FrameCourier

FrameCourier is a Python and FFmpeg-based proof-of-concept for storing and recovering arbitrary binary files through lossless video-backed data streams.

It converts an input file into deterministic data frames, stores those frames in FFV1 lossless video streams, and reconstructs the original file byte-for-byte during extraction. FrameCourier can work as a standalone data-video encoder, or it can build an MKV carrier that keeps a normal visible cover video as the primary stream while storing binary data in additional distributed lossless streams.

FrameCourier is not QR-code transfer, not normal video compression, and not pixel-level steganography. It is an explicit, testable, lossless binary carrier built on top of video frames and MKV streams.

## What FrameCourier Does

FrameCourier supports two main workflows.

Direct DataVideo mode:

```text
input.bin -> data_video.mkv -> recovered.bin
```

Cover carrier mode:

```text
input.bin + cover video -> carrier.mkv -> recovered.bin
```

In cover carrier mode, the visible video remains the normal cover video. The binary payload is stored in additional FFV1 streams inside the MKV container.

A typical carrier looks like this:

```text
carrier.mkv
├── Stream 0: visible cover video
├── Stream 1: DataVideoSegment-00000
├── Stream 2: DataVideoSegment-00001
├── Stream 3: DataVideoSegment-00002
└── ...
```

Most media players display only the visible cover stream. FrameCourier extracts the additional DataVideo segment streams and rebuilds the original file.

## Key Features

* Byte-for-byte recovery of arbitrary binary files
* FFmpeg and FFV1 lossless video encoding
* MKV carrier support
* Optional visible cover/default video
* Distributed payload segments
* Automatic segment discovery during extraction
* SHA256 integrity verification
* Frame metadata and segment metadata
* Works with text files, archives, random binary files, and large payloads
* Designed for local/offline experimentation and controlled file transport testing

## Important Concept

FrameCourier does not hide bytes inside the visible pixels of the cover video.

The cover video and the data payload are separate streams inside the same MKV container.

The visible video is kept as the main stream. The payload is converted into lossless video frames and stored in extra FFV1 streams named like this:

```text
DataVideoSegment-00000
DataVideoSegment-00001
DataVideoSegment-00002
```

This means the carrier still looks like a normal video when opened in a regular media player, but technical tools such as FFprobe or MediaInfo can detect the additional streams.

## Project Structure

```text
FrameCourier/
├── datavideo/
│   ├── core.py
│   ├── encoder.py
│   ├── decoder.py
│   ├── metadata.py
│   ├── cover.py
│   ├── distributed.py
│   └── ...
├── tests/
├── tools/
│   └── check_env.py
├── default/
│   └── .gitkeep
├── bin/
│   ├── ffmpeg.exe
│   └── ffprobe.exe
├── encode.py
├── decode.py
├── embed.py
├── extract.py
├── requirements.txt
├── README.md
├── ROADMAP.md
└── CLAUDE_BRIEF.md
```

The `bin/` directory is used for local FFmpeg binaries on Windows. FFmpeg binaries are intentionally not meant to be committed to Git.

## Requirements

* Python 3.10 or newer
* FFmpeg
* FFprobe
* PowerShell, Bash, or any terminal capable of running Python commands

On Windows, portable FFmpeg is supported. Place these files in the project `bin/` directory:

```text
bin/ffmpeg.exe
bin/ffprobe.exe
```

## Setup on Windows

Open the project folder in VS Code:

```text
C:\Users\mo.yaghubi\Downloads\FrameCourier
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
python -m pip install pytest
```

Check FFmpeg and FFprobe:

```powershell
python tools/check_env.py
```

Expected result:

```text
Environment OK
```

## Creating a Local Test Cover Video

For local testing, you can generate a short default video:

```powershell
New-Item -ItemType Directory -Force .\default
.\bin\ffmpeg.exe -y -f lavfi -i testsrc2=size=1280x720:rate=30 -t 20 -c:v libx264 -pix_fmt yuv420p ".\default\default.mp4"
```

You can replace `default/default.mp4` with any normal video file supported by FFmpeg.

## Using a Custom Cover Video

You can either place your cover video here:

```text
default/default.mp4
```

Or pass it directly:

```powershell
python embed.py input.bin carrier.mkv --cover-video "E:\cover.mp4"
```

## Direct DataVideo Mode

Encode a binary file into a standalone lossless data video:

```powershell
python encode.py input.bin data_video.mkv
```

Decode it back:

```powershell
python decode.py data_video.mkv recovered.bin
```

Verify the result on Windows:

```powershell
certutil -hashfile input.bin SHA256
certutil -hashfile recovered.bin SHA256
```

The SHA256 hashes must match.

## Cover Carrier Mode

Embed a file into an MKV carrier using `default/default.mp4`:

```powershell
python embed.py input.bin carrier.mkv
```

Extract the file:

```powershell
python extract.py carrier.mkv recovered.bin
```

Verify integrity:

```powershell
certutil -hashfile input.bin SHA256
certutil -hashfile recovered.bin SHA256
```

## Distributed Carrier Mode

FrameCourier can split the payload into multiple DataVideo segment streams.

Example with 10 distributed segments:

```powershell
python embed.py input.bin carrier.mkv --segments 10 --schedule even
```

Extract it:

```powershell
python extract.py carrier.mkv recovered.bin
```

Supported schedules:

```text
even
center-weighted
seeded-random
```

Example using a seeded random schedule:

```powershell
python embed.py input.bin carrier.mkv --segments 10 --schedule seeded-random --seed 42
```

The extractor automatically discovers the DataVideo segment streams, decodes them, orders the frames, rebuilds the payload, and verifies the output hash.

## Real Example

Embed a RAR file into a 10-segment carrier:

```powershell
python embed.py "E:\purple.rar" "E:\purple_carrier_10.mkv" --segments 10 --schedule even
```

Extract it:

```powershell
python extract.py "E:\purple_carrier_10.mkv" "E:\purple_recovered_10.rar"
```

Verify:

```powershell
certutil -hashfile "E:\purple.rar" SHA256
certutil -hashfile "E:\purple_recovered_10.rar" SHA256
```

If both hashes match, the file was recovered byte-for-byte.

## Inspecting Carrier Streams

Use FFprobe to inspect the streams inside a carrier:

```powershell
.\bin\ffprobe.exe -v error -show_entries stream=index,codec_name,start_time,duration:stream_tags=title -of default=nw=1 carrier.mkv
```

Example output:

```text
index=0
codec_name=h264

index=1
codec_name=ffv1
TAG:title=DataVideoSegment-00000

index=2
codec_name=ffv1
TAG:title=DataVideoSegment-00001
```

This confirms that the MKV contains a visible video stream plus additional lossless data streams.

## Testing

Run the automated test suite:

```powershell
python -m pytest -q
```

Expected result for the current distributed build:

```text
2 passed, 3 skipped
```

Run a manual round-trip test:

```powershell
"hello framecourier final test" | Set-Content -Encoding UTF8 sample.txt
python embed.py sample.txt sample_carrier.mkv --segments 10 --schedule even
python extract.py sample_carrier.mkv sample_recovered.txt
certutil -hashfile sample.txt SHA256
certutil -hashfile sample_recovered.txt SHA256
```

The two SHA256 hashes must be identical.

## Why Small Files May Produce Fewer Segments

If you request 10 segments but embed a very small file, FrameCourier may produce only 1 actual segment.

Example:

```text
Requested segments: 10
Actual segments: 1
```

This is expected. A tiny input file may require only one data frame, so it cannot be split into more meaningful data segments unless empty segments are deliberately generated.

For larger files, FrameCourier can produce the requested number of segments as long as there are enough data frames.

## Capacity Model

A 1920x1080 RGB frame can theoretically carry:

```text
1920 × 1080 × 3 = 6,220,800 bytes
```

FrameCourier reserves part of each frame for metadata and integrity information, so the usable payload capacity is slightly lower.

Large files are split across multiple frames.

Example:

```text
100 MB input -> about 17 data frames at 1920x1080
4.65 GB input -> roughly hundreds of data frames
```

## Output Size Expectations

FrameCourier is lossless. It cannot magically compress already-compressed or high-entropy data.

For files such as RAR, ZIP, 7Z, encrypted data, or random binary data, the expected carrier size is roughly:

```text
cover video size + original data size + codec/container overhead
```

If the input file is already compressed, the output carrier may be larger than the input.

## Transfer Notes

Do not upload the carrier as a normal video to platforms that re-encode media.

Platforms such as YouTube, Instagram, WhatsApp, and Telegram may recompress the video, remove extra streams, or rewrite the container. That can destroy the embedded data streams.

Transfer the carrier as a file/document instead:

```text
USB drive
external disk
SFTP
cloud storage as original file
file/document upload
```

## Security Notes

FrameCourier currently provides integrity verification, not confidentiality.

It uses SHA256 to verify that the recovered output matches the original input.

If confidentiality is required, encrypt the input file before embedding it.

Recommended secure workflow:

```text
original file
-> encrypt externally
-> embed encrypted payload with FrameCourier
-> extract encrypted payload
-> decrypt externally
```

FrameCourier is not designed to make the presence of data impossible to detect. Additional streams can be inspected with standard media analysis tools.

## What FrameCourier Is Not

FrameCourier is not:

```text
a malware tool
a covert exfiltration framework
a DRM bypass tool
a steganography system designed to evade analysis
a replacement for encryption
a replacement for secure file transfer protocols
```

It is a research and engineering proof-of-concept for lossless video-backed binary transport.

## Recommended Git Ignore Rules

The repository should not include generated carriers, test payloads, virtual environments, or FFmpeg binaries.

Recommended ignored files:

```text
.venv/
__pycache__/
.pytest_cache/
*.pyc
bin/*.exe
bin/*.dll
*.mkv
*.mp4
*.bin
*.rar
*.zip
*.7z
*_carrier*
*_recovered*
random_*
sample.txt
sample_recovered.txt
datavideo_segments_*/
default/default.mp4
```

## Development Roadmap

Possible future improvements:

```text
optional encryption layer
raw packed payload mode
stronger metadata versioning
better stream scheduling
CLI subcommands
cross-platform packaging
larger integration tests
GitHub Actions test workflow
performance benchmarking
```

## License

MIT
