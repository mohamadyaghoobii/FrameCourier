import json
import shutil
import subprocess
from pathlib import Path


def candidate_names(name):
    names = [name]
    if not name.lower().endswith(".exe"):
        names.append(name + ".exe")
    return names


def local_tool(name):
    roots = [
        Path.cwd(),
        Path.cwd() / "bin",
        Path(__file__).resolve().parent.parent,
        Path(__file__).resolve().parent.parent / "bin"
    ]
    for root in roots:
        for tool_name in candidate_names(name):
            candidate = root / tool_name
            if candidate.exists():
                return str(candidate)
    for tool_name in candidate_names(name):
        found = shutil.which(tool_name)
        if found:
            return found
    raise FileNotFoundError(name + " was not found. Install FFmpeg or place it in the project bin directory.")


def ffmpeg_path():
    return local_tool("ffmpeg")


def ffprobe_path():
    return local_tool("ffprobe")


def probe_video(path):
    cmd = [
        ffprobe_path(),
        "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height,pix_fmt,codec_name,nb_frames",
        "-of", "json",
        str(path)
    ]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    data = json.loads(result.stdout.decode("utf-8"))
    streams = data.get("streams") or []
    if not streams:
        raise RuntimeError("No video stream found")
    return streams[0]
