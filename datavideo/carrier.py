import shutil
import subprocess
from pathlib import Path

from .cover import find_default_cover, probe_duration
from .ffmpeg_tools import ffmpeg_path
from .segmenter import DATA_SEGMENT_TITLE, encode_distributed_segments, temporary_segment_dir


def build_distributed_mux_command(cover_video, encoded_segments, output_path):
    cmd = [ffmpeg_path(), "-v", "error", "-y", "-i", str(cover_video)]
    for segment in encoded_segments:
        cmd.extend(["-itsoffset", f"{segment.offset_seconds:.6f}", "-i", str(segment.path)])
    cmd.extend(["-map", "0:v:0", "-map", "0:a?", "-map", "0:s?"])
    for i in range(len(encoded_segments)):
        cmd.extend(["-map", f"{i + 1}:v:0"])
    cmd.extend(["-c", "copy", "-max_interleave_delta", "0"])
    for i, segment in enumerate(encoded_segments):
        video_stream_number = i + 1
        cmd.extend(["-metadata:s:v:" + str(video_stream_number), f"title={DATA_SEGMENT_TITLE}-{segment.index:05d}"])
        cmd.extend(["-metadata:s:v:" + str(video_stream_number), f"DVS_segment_index={segment.index}"])
        cmd.extend(["-metadata:s:v:" + str(video_stream_number), f"DVS_offset_seconds={segment.offset_seconds:.6f}"])
        cmd.extend(["-disposition:v:" + str(video_stream_number), "0"])
    cmd.append(str(output_path))
    return cmd


def mux_distributed_carrier(cover_video, encoded_segments, output_path):
    cmd = build_distributed_mux_command(cover_video, encoded_segments, output_path)
    subprocess.run(cmd, check=True)


def embed_file_distributed(input_path, output_path, cover_video=None, default_dir="default", segments=100, schedule="even", seed=1337, width=1920, height=1080, fps=30, progress=True, keep_segments=False, temp_dir=None):
    cover = Path(cover_video) if cover_video else find_default_cover(default_dir)
    duration = probe_duration(cover)
    temp_root = Path(temp_dir) if temp_dir else temporary_segment_dir(output_path)
    if progress:
        print("cover video:", cover)
        print("cover duration seconds:", f"{duration:.3f}")
        print("distributed segments requested:", segments)
        print("schedule:", schedule)
        print("temporary segment directory:", temp_root)
    metadata, encoded_segments = encode_distributed_segments(
        input_path,
        temp_root,
        requested_segments=segments,
        schedule=schedule,
        cover_duration=duration,
        seed=seed,
        width=width,
        height=height,
        fps=fps,
        progress=progress,
    )
    if progress:
        print("muxing cover video with distributed data segment streams")
    mux_distributed_carrier(cover, encoded_segments, output_path)
    metadata["cover_video"] = str(cover)
    metadata["cover_duration_seconds"] = duration
    metadata["actual_segments"] = len(encoded_segments)
    metadata["segment_offsets_seconds"] = [s.offset_seconds for s in encoded_segments]
    if not keep_segments:
        shutil.rmtree(temp_root, ignore_errors=True)
    return metadata
