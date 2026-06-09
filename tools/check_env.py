import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from datavideo.ffmpeg_tools import ffmpeg_path, ffprobe_path


def show_tool(label, func):
    try:
        path = func()
        print(f"{label}: {path}")
        return True
    except Exception as exc:
        print(f"error: {label} was not found")
        print(exc)
        return False


def main():
    ok1 = show_tool("ffmpeg", ffmpeg_path)
    ok2 = show_tool("ffprobe", ffprobe_path)
    if not (ok1 and ok2):
        print("Install FFmpeg and FFprobe, or drop ffmpeg.exe / ffprobe.exe into the project's bin/ folder.")
        raise SystemExit(1)
    print("Environment OK")


if __name__ == "__main__":
    main()
