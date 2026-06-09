import hashlib
import subprocess

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


def decode_video(video_path, output_path, progress=True):
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
        written = 0
        digest = hashlib.sha256()
        with open(output_path, "wb") as out:
            first_payload = first_frame[header_bytes:]
            take = min(len(first_payload), file_size - written)
            if take > 0:
                out.write(first_payload[:take])
                digest.update(first_payload[:take])
                written += take
            if progress:
                print(f"decoded frame 1/{total_frames}")
            for frame_id in range(1, total_frames):
                frame = read_exact(process.stdout, per_frame)
                if len(frame) != per_frame:
                    raise RuntimeError(f"Missing or truncated frame {frame_id}")
                take = min(per_frame, file_size - written)
                if take > 0:
                    out.write(frame[:take])
                    digest.update(frame[:take])
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
