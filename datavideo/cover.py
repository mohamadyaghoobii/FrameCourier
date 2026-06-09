import json
import subprocess
from pathlib import Path

from .core import MAGIC, PIXEL_FORMAT, frame_bytes, parse_header
from .decoder import read_exact
from .encoder import encode_file
from .ffmpeg_tools import ffmpeg_path, ffprobe_path

VIDEO_EXTENSIONS = (".mkv", ".mp4", ".mov", ".avi", ".webm", ".m4v")
DATA_TRACK_TITLE = "DataVideo"


def find_default_cover(default_dir="default"):
    root = Path(default_dir)
    if not root.exists():
        raise FileNotFoundError("Default video directory was not found: " + str(root))
    candidates = []
    for path in root.iterdir():
        if path.is_file() and path.suffix.lower() in VIDEO_EXTENSIONS:
            candidates.append(path)
    if not candidates:
        raise FileNotFoundError("No default video was found in " + str(root))
    candidates.sort(key=lambda p: p.name.lower())
    return candidates[0]


def probe_duration(video_path):
    cmd = [
        ffprobe_path(),
        "-v", "error",
        "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1",
        str(video_path)
    ]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    text = result.stdout.decode("utf-8", errors="replace").strip()
    try:
        duration = float(text)
    except ValueError as exc:
        raise RuntimeError("Could not read cover video duration") from exc
    if duration <= 0:
        raise RuntimeError("Cover video duration must be greater than zero")
    return duration


def default_temp_data_path(output_path):
    output = Path(output_path)
    return output.with_name(output.stem + ".datavideo_segment.tmp.mkv")


def build_mux_command(cover_video, data_video, output_path, midpoint_seconds):
    return [
        ffmpeg_path(),
        "-v", "error",
        "-y",
        "-i", str(cover_video),
        "-itsoffset", f"{midpoint_seconds:.6f}",
        "-i", str(data_video),
        "-map", "0:v:0",
        "-map", "0:a?",
        "-map", "1:v:0",
        "-c", "copy",
        "-metadata:s:v:1", f"title={DATA_TRACK_TITLE}",
        "-disposition:v:1", "0",
        str(output_path)
    ]


def mux_cover_and_data(cover_video, data_video, output_path, midpoint_seconds):
    subprocess.run(build_mux_command(cover_video, data_video, output_path, midpoint_seconds), check=True)


def embed_file_in_cover(input_path, output_path, cover_video=None, default_dir="default", width=1920, height=1080, fps=30, progress=True, keep_data_video=False, temp_data_video=None):
    cover = Path(cover_video) if cover_video else find_default_cover(default_dir)
    duration = probe_duration(cover)
    midpoint = duration / 2.0
    temp_path = Path(temp_data_video) if temp_data_video else default_temp_data_path(output_path)
    if progress:
        print("cover video:", cover)
        print("cover duration seconds:", f"{duration:.3f}")
        print("legacy single data track start seconds:", f"{midpoint:.3f}")
        print("temporary data video:", temp_path)
    metadata = encode_file(input_path, temp_path, width=width, height=height, fps=fps, progress=progress)
    metadata["cover_video"] = str(cover)
    metadata["cover_duration_seconds"] = duration
    metadata["data_track_start_seconds"] = midpoint
    if progress:
        print("muxing cover video and single data video track")
    mux_cover_and_data(cover, temp_path, output_path, midpoint)
    if not keep_data_video:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
    return metadata


def extract_file_from_cover(video_path, output_path, progress=True):
    from .extractor import extract_auto
    return extract_auto(video_path, output_path, progress=progress)
