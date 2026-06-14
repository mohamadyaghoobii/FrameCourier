import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from . import crypto
from .core import MAGIC as LEGACY_MAGIC, PIXEL_FORMAT, frame_bytes, parse_header
from .decoder import read_exact
from .ffmpeg_tools import ffmpeg_path, ffprobe_path
from .segmenter import LEGACY_SEGMENT_MAGIC, SEGMENT_MAGIC, parse_segment_frame


def probe_streams(video_path):
    cmd = [
        ffprobe_path(),
        "-v", "error",
        "-show_streams",
        "-of", "json",
        str(video_path),
    ]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return json.loads(result.stdout.decode("utf-8")).get("streams") or []


def build_stream_decode_command(video_path, stream_index, frame_limit=None):
    cmd = [
        ffmpeg_path(),
        "-v", "error",
        "-i", str(video_path),
        "-map", f"0:{stream_index}",
        "-fps_mode", "passthrough",
    ]
    if frame_limit is not None:
        cmd.extend(["-frames:v", str(frame_limit)])
    cmd.extend([
        "-f", "rawvideo",
        "-pix_fmt", PIXEL_FORMAT,
        "pipe:1",
    ])
    return cmd


def decode_first_frame(video_path, stream):
    width = int(stream["width"])
    height = int(stream["height"])
    per_frame = frame_bytes(width, height)
    cmd = build_stream_decode_command(video_path, int(stream["index"]), frame_limit=1)
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    frame = read_exact(process.stdout, per_frame)
    stderr = process.stderr.read()
    code = process.wait()
    if code != 0:
        raise RuntimeError("Could not decode first frame: " + stderr.decode("utf-8", errors="replace"))
    if len(frame) != per_frame:
        raise RuntimeError("Could not read first frame")
    return frame


def is_data_segment_stream(video_path, stream):
    if stream.get("codec_type") != "video":
        return None
    if stream.get("codec_name") != "ffv1":
        return None
    try:
        first = decode_first_frame(video_path, stream)
        if not (first.startswith(SEGMENT_MAGIC) or first.startswith(LEGACY_SEGMENT_MAGIC)):
            return None
        header, _payload = parse_segment_frame(first)
        return header
    except Exception:
        return None


def find_data_segment_streams(video_path):
    found = []
    for stream in probe_streams(video_path):
        header = is_data_segment_stream(video_path, stream)
        if header:
            found.append((stream, header))
    if not found:
        return []
    unique = {}
    for stream, header in found:
        segment_index = int(header["segment_index"])
        if segment_index not in unique:
            unique[segment_index] = (stream, header)
    return [unique[i] for i in sorted(unique)]


def validate_segment_set(segment_streams):
    if not segment_streams:
        raise RuntimeError("No data segment streams were found in the carrier")
    first_header = segment_streams[0][1]
    keys = ["session_id", "file_id", "sha256", "file_size", "total_frames", "total_segments", "width", "height", "header_bytes"]
    for _stream, header in segment_streams:
        for key in keys:
            if header.get(key) != first_header.get(key):
                raise RuntimeError(f"Segment metadata mismatch for {key}")
    total_segments = int(first_header["total_segments"])
    present = [int(header["segment_index"]) for _stream, header in segment_streams]
    missing = [i for i in range(total_segments) if i not in present]
    if missing:
        raise RuntimeError("Missing segment stream(s): " + ", ".join(str(x) for x in missing[:20]))
    return first_header


def decode_segment_stream_to_output(video_path, stream, expected_base, expected_global_frame, output, digest, written, decryptor=None, progress=True):
    width = int(stream["width"])
    height = int(stream["height"])
    per_frame = frame_bytes(width, height)
    cmd = build_stream_decode_command(video_path, int(stream["index"]))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    frames_decoded = 0
    try:
        while True:
            frame = read_exact(process.stdout, per_frame)
            if not frame:
                break
            if len(frame) != per_frame:
                raise RuntimeError("Truncated segment frame")
            header, payload = parse_segment_frame(frame)
            if header.get("session_id") != expected_base.get("session_id"):
                raise RuntimeError("Carrier session id mismatch")
            global_index = int(header["global_frame_index"])
            if global_index != expected_global_frame:
                raise RuntimeError(f"Unexpected global frame index {global_index}; expected {expected_global_frame}")
            file_size = int(expected_base["file_size"])
            take = min(len(payload), file_size - written)
            if take > 0:
                chunk = bytes(payload[:take])
                if decryptor is not None:
                    chunk = decryptor.update(chunk)
                output.write(chunk)
                digest.update(chunk)
                written += take
            expected_global_frame += 1
            frames_decoded += 1
        process.stdout.close()
        code = process.wait()
        if code != 0:
            raise RuntimeError("FFmpeg segment decoder failed")
    except Exception:
        if process.stdout:
            try:
                process.stdout.close()
            except Exception:
                pass
        process.kill()
        process.wait()
        raise
    if progress:
        segment_index = int(expected_base.get("current_segment_index", -1))
        if segment_index >= 0:
            print(f"decoded distributed segment {segment_index + 1}/{expected_base['total_segments']} frames={frames_decoded}")
    return expected_global_frame, written


def extract_distributed_segments(video_path, output_path, password=None, progress=True):
    segment_streams = find_data_segment_streams(video_path)
    base = validate_segment_set(segment_streams)
    decryptor = None
    if base.get("encrypted"):
        if password is None:
            raise RuntimeError("This carrier is encrypted. Provide --password to extract.")
        salt = crypto.b64d(base["enc_salt"])
        nonce = crypto.b64d(base["enc_nonce"])
        iterations = int(base.get("kdf_iterations", crypto.DEFAULT_KDF_ITERATIONS))
        decryptor = crypto.decryptor(password, salt, nonce, iterations=iterations)
    digest = hashlib.sha256()
    written = 0
    expected_global_frame = 0
    if progress:
        print(f"found data segments: {len(segment_streams)}")
        print("session:", base["session_id"])
        print("encryption:", "on" if base.get("encrypted") else "off")
    with open(output_path, "wb") as output:
        for stream, header in segment_streams:
            base_with_current = dict(base)
            base_with_current["current_segment_index"] = int(header["segment_index"])
            expected_global_frame, written = decode_segment_stream_to_output(
                video_path,
                stream,
                base_with_current,
                expected_global_frame,
                output,
                digest,
                written,
                decryptor=decryptor,
                progress=progress,
            )
    total_frames = int(base["total_frames"])
    if expected_global_frame != total_frames:
        raise RuntimeError(f"Missing data frames: decoded {expected_global_frame}, expected {total_frames}")
    file_size = int(base["file_size"])
    if written != file_size:
        raise RuntimeError(f"Recovered file size mismatch: wrote {written}, expected {file_size}")
    actual_hash = digest.hexdigest()
    if actual_hash != base["sha256"]:
        if base.get("encrypted"):
            raise RuntimeError("SHA256 mismatch. Wrong password or the carrier video was modified.")
        raise RuntimeError("SHA256 mismatch. The carrier video was changed or decoded incorrectly.")
    return base


def find_legacy_datavideo_stream(video_path):
    ffv1_candidates = []
    titled = []
    for stream in probe_streams(video_path):
        if stream.get("codec_type") != "video":
            continue
        tags = stream.get("tags") or {}
        title = tags.get("title") or tags.get("TITLE") or ""
        if title.lower() == "datavideo":
            titled.append(stream)
        if stream.get("codec_name") == "ffv1":
            ffv1_candidates.append(stream)
    candidates = titled or ffv1_candidates
    for stream in candidates:
        try:
            first = decode_first_frame(video_path, stream)
            if first.startswith(LEGACY_MAGIC):
                return stream
        except Exception:
            pass
    raise RuntimeError("No DataVideo track was found in the carrier video")


def extract_legacy_track(video_path, output_path, progress=True):
    stream = find_legacy_datavideo_stream(video_path)
    width = int(stream["width"])
    height = int(stream["height"])
    per_frame = frame_bytes(width, height)
    cmd = build_stream_decode_command(video_path, int(stream["index"]))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    try:
        first_frame = read_exact(process.stdout, per_frame)
        if len(first_frame) != per_frame:
            raise RuntimeError("Could not read the first DataVideo frame")
        if not first_frame.startswith(LEGACY_MAGIC):
            raise RuntimeError("Selected DataVideo track does not start with the expected magic header")
        metadata = parse_header(first_frame)
        header_bytes = int(metadata["header_bytes"])
        file_size = int(metadata["file_size"])
        total_frames = int(metadata["total_frames"])
        expected_hash = metadata["sha256"]
        digest = hashlib.sha256()
        written = 0
        with open(output_path, "wb") as out:
            payload = first_frame[header_bytes:]
            take = min(len(payload), file_size - written)
            if take > 0:
                out.write(payload[:take])
                digest.update(payload[:take])
                written += take
            if progress:
                print(f"using legacy carrier stream index: {stream['index']}")
                print(f"decoded data frame 1/{total_frames}")
            for data_frame_id in range(1, total_frames):
                frame = read_exact(process.stdout, per_frame)
                if len(frame) != per_frame:
                    raise RuntimeError(f"Missing or truncated embedded data frame {data_frame_id}")
                take = min(per_frame, file_size - written)
                if take > 0:
                    out.write(frame[:take])
                    digest.update(frame[:take])
                    written += take
                if progress and ((data_frame_id + 1) % 25 == 0 or data_frame_id + 1 == total_frames):
                    print(f"decoded data frame {data_frame_id + 1}/{total_frames}")
        process.stdout.close()
        process.kill()
        process.wait()
        if written != file_size:
            raise RuntimeError("Recovered file size does not match embedded metadata")
        actual_hash = digest.hexdigest()
        if actual_hash != expected_hash:
            raise RuntimeError("SHA256 mismatch. The carrier video was changed or decoded incorrectly.")
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


def extract_auto(video_path, output_path, password=None, identity_privkey=None, progress=True):
    from .stego_carrier import extract_stego, is_stego_carrier
    if is_stego_carrier(video_path):
        return extract_stego(video_path, output_path, password=password, identity_privkey=identity_privkey, progress=progress)
    segments = find_data_segment_streams(video_path)
    if segments:
        return extract_distributed_segments(video_path, output_path, password=password, progress=progress)
    return extract_legacy_track(video_path, output_path, progress=progress)
