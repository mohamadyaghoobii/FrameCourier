import subprocess

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


def encode_file(input_path, output_path, width=DEFAULT_WIDTH, height=DEFAULT_HEIGHT, fps=DEFAULT_FPS, header_bytes=DEFAULT_HEADER_BYTES, progress=True):
    per_frame = frame_bytes(width, height)
    file_hash = sha256_file(input_path)
    metadata = make_metadata(input_path, width, height, fps, header_bytes, file_hash)
    header = pack_header(metadata, header_bytes)
    first_payload_size = per_frame - header_bytes
    cmd = build_encode_command(output_path, width, height, fps)
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    frame_id = 0
    try:
        with open(input_path, "rb") as f:
            first_payload = f.read(first_payload_size)
            process.stdin.write(pad_frame(header + first_payload, per_frame))
            frame_id += 1
            if progress:
                print(f"encoded frame {frame_id}/{metadata['total_frames']}")
            while True:
                chunk = f.read(per_frame)
                if not chunk:
                    break
                process.stdin.write(pad_frame(chunk, per_frame))
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
