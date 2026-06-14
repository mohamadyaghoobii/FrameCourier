"""FrameCourier GUI: single-window Tkinter front-end for every common task.

Runs every operation via the existing CLI as a subprocess in a background
thread, so the UI stays responsive and so the GUI cannot diverge from the
command-line behaviour. Output is streamed live into a per-tab log area.

Launch with:
    python -m datavideo.gui
or:
    python framecourier_gui.py
"""

import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"Tkinter is required for the FrameCourier GUI: {exc}")


ROOT = Path(__file__).resolve().parent.parent
CLI = [sys.executable, str(ROOT / "framecourier.py")]
FONT = ("Segoe UI", 10)
FONT_MONO = ("Consolas", 9)
FONT_HEADING = ("Segoe UI Semibold", 11)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class JobRunner:
    """Run a CLI subprocess in a background thread, stream stdout/stderr lines
    into a queue that the main thread polls and prints into a Text widget."""

    def __init__(self, log_widget, status_var, on_done=None):
        self.log = log_widget
        self.status = status_var
        self.on_done = on_done
        self.q = queue.Queue()
        self.proc = None

    def start(self, args, env=None, label="working..."):
        if self.proc is not None and self.proc.poll() is None:
            messagebox.showwarning("Busy", "Another job is still running.")
            return False
        self.status.set(label)
        self._append(f"\n$ {' '.join(_shellquote(a) for a in args)}\n")
        threading.Thread(target=self._run, args=(args, env or os.environ.copy()), daemon=True).start()
        self.log.after(50, self._drain)
        return True

    def _run(self, args, env):
        try:
            self.proc = subprocess.Popen(
                args, cwd=str(ROOT), env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                self.q.put(line)
            rc = self.proc.wait()
            self.q.put(f"\n[exit code {rc}]\n")
            self.q.put(("__done__", rc))
        except Exception as exc:
            self.q.put(f"\n[runner error] {exc}\n")
            self.q.put(("__done__", -1))

    def _drain(self):
        try:
            while True:
                item = self.q.get_nowait()
                if isinstance(item, tuple) and item[0] == "__done__":
                    self.status.set("Done")
                    if self.on_done:
                        self.on_done(item[1])
                    return
                self._append(item)
        except queue.Empty:
            pass
        self.log.after(50, self._drain)

    def _append(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")


def _shellquote(s):
    if " " in str(s) or '"' in str(s):
        return '"' + str(s).replace('"', '\\"') + '"'
    return str(s)


def make_log(parent):
    frame = ttk.LabelFrame(parent, text="Output")
    frame.grid_columnconfigure(0, weight=1)
    frame.grid_rowconfigure(0, weight=1)
    txt = scrolledtext.ScrolledText(frame, height=12, font=FONT_MONO, wrap="word", state="disabled",
                                    background="#101418", foreground="#cfd8dc", insertbackground="#cfd8dc")
    txt.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
    return frame, txt


def labelled_entry(parent, row, label, default="", show=None, width=60):
    ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=6, pady=4)
    var = tk.StringVar(value=default)
    e = ttk.Entry(parent, textvariable=var, width=width, show=show or "")
    e.grid(row=row, column=1, sticky="ew", padx=6, pady=4, columnspan=2)
    return var, e


def file_picker(parent, row, label, save=False, filetypes=None, default=""):
    var, entry = labelled_entry(parent, row, label, default=default, width=52)
    def browse():
        if save:
            path = filedialog.asksaveasfilename(filetypes=filetypes or [], parent=parent)
        else:
            path = filedialog.askopenfilename(filetypes=filetypes or [], parent=parent)
        if path:
            var.set(path)
    ttk.Button(parent, text="Browse...", command=browse).grid(row=row, column=3, padx=6, pady=4)
    return var


def folder_picker(parent, row, label, default=""):
    var, entry = labelled_entry(parent, row, label, default=default, width=52)
    def browse():
        path = filedialog.askdirectory(parent=parent)
        if path:
            var.set(path)
    ttk.Button(parent, text="Browse...", command=browse).grid(row=row, column=3, padx=6, pady=4)
    return var


def labelled_combo(parent, row, label, values, default=None):
    ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=6, pady=4)
    var = tk.StringVar(value=default or (values[0] if values else ""))
    cb = ttk.Combobox(parent, textvariable=var, values=values, state="readonly", width=24)
    cb.grid(row=row, column=1, sticky="w", padx=6, pady=4)
    return var


# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------


def build_embed_tab(notebook):
    page = ttk.Frame(notebook, padding=8)
    notebook.add(page, text="Embed")
    page.grid_columnconfigure(1, weight=1)

    ttk.Label(page, text="Hide a payload inside a cover video", font=FONT_HEADING).grid(
        row=0, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 8))

    input_var = file_picker(page, 1, "Payload file:", save=False,
                            filetypes=[("All files", "*.*")])
    output_var = file_picker(page, 2, "Output carrier:", save=True,
                             filetypes=[("MP4", "*.mp4")])
    cover_var = file_picker(page, 3, "Cover video:", save=False,
                            filetypes=[("Videos", "*.mp4 *.mkv *.mov *.webm")])

    mode_var = labelled_combo(page, 4, "Mode:",
                              ["stego-seq", "stego-shuffled", "stego-adaptive",
                               "distributed", "legacy"],
                              default="stego-shuffled")
    crypto_var = labelled_combo(page, 5, "Crypto layer:",
                                ["none", "aes-ctr", "aes-gcm", "chacha-poly",
                                 "x25519-chacha20", "deniable"],
                                default="aes-gcm")
    kdf_var = labelled_combo(page, 6, "KDF:",
                             ["none", "pbkdf2-hmac-sha256", "argon2id", "hkdf-sha256"],
                             default="argon2id")
    ecc_var = labelled_combo(page, 7, "ECC:",
                             ["none", "rs-255-223"], default="none")
    preset_var = labelled_combo(page, 8, "Preset (overrides above):",
                                ["(none)", "paranoid", "stealth", "robust",
                                 "asymmetric", "deniable", "plain"],
                                default="(none)")

    pwd_var, _ = labelled_entry(page, 9, "Passphrase (real):", show="*")
    decoy_var = file_picker(page, 10, "Decoy file (deniable only):", save=False,
                            filetypes=[("All files", "*.*")])
    decoy_pwd_var, _ = labelled_entry(page, 11, "Decoy passphrase:", show="*")
    recipient_var = file_picker(page, 12, "Recipient pubkey (X25519/age):", save=False,
                                filetypes=[("Public key", "*.pub *.age *"), ("All files", "*.*")])
    sign_var = file_picker(page, 13, "Sign with Ed25519 key (optional):", save=False,
                           filetypes=[("Ed25519 key", "*"), ("All files", "*.*")])

    log_frame, log_widget = make_log(page)
    log_frame.grid(row=15, column=0, columnspan=4, sticky="nsew", padx=6, pady=(8, 4))
    page.grid_rowconfigure(15, weight=1)

    status = tk.StringVar(value="Ready")
    ttk.Label(page, textvariable=status).grid(row=16, column=0, columnspan=4, sticky="w", padx=6)

    runner = JobRunner(log_widget, status)

    def run():
        if not input_var.get() or not output_var.get():
            messagebox.showerror("Missing fields", "Set both payload and output paths.")
            return
        args = list(CLI) + ["embed", input_var.get(), output_var.get()]
        if cover_var.get():
            args += ["--cover-video", cover_var.get()]
        if preset_var.get() and preset_var.get() != "(none)":
            args += ["--preset", preset_var.get()]
        else:
            args += ["--mode", mode_var.get(),
                     "--crypto", crypto_var.get(),
                     "--kdf", kdf_var.get(),
                     "--ecc", ecc_var.get()]
        env = os.environ.copy()
        if pwd_var.get():
            env["__FCGUI_PWD"] = pwd_var.get()
            args += ["--password-env", "__FCGUI_PWD"]
        if decoy_var.get():
            args += ["--decoy-file", decoy_var.get()]
        if decoy_pwd_var.get():
            env["__FCGUI_DPWD"] = decoy_pwd_var.get()
            args += ["--decoy-password-env", "__FCGUI_DPWD"]
        if recipient_var.get():
            args += ["--recipient", recipient_var.get()]
        if sign_var.get():
            args += ["--sign-with", sign_var.get()]
        runner.start(args, env=env, label="Embedding...")

    btn_frame = ttk.Frame(page)
    btn_frame.grid(row=14, column=0, columnspan=4, sticky="w", padx=6, pady=(8, 4))
    ttk.Button(btn_frame, text="Embed", command=run).pack(side="left", padx=4)
    ttk.Button(btn_frame, text="Clear log", command=lambda: _clear(log_widget)).pack(side="left", padx=4)


def build_extract_tab(notebook):
    page = ttk.Frame(notebook, padding=8)
    notebook.add(page, text="Extract")
    page.grid_columnconfigure(1, weight=1)

    ttk.Label(page, text="Recover a payload from a carrier", font=FONT_HEADING).grid(
        row=0, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 8))

    carrier_var = file_picker(page, 1, "Carrier file:", save=False,
                              filetypes=[("Videos", "*.mp4 *.mkv *.mov *.webm")])
    out_var = file_picker(page, 2, "Output file:", save=True,
                          filetypes=[("All files", "*.*")])
    pwd_var, _ = labelled_entry(page, 3, "Passphrase:", show="*")
    identity_var = file_picker(page, 4, "Identity key (X25519/age):", save=False,
                               filetypes=[("Private key", "*"), ("All files", "*.*")])
    verify_var = file_picker(page, 5, "Verify with Ed25519 pubkey:", save=False,
                             filetypes=[("Pub key", "*.pub"), ("All files", "*.*")])

    log_frame, log_widget = make_log(page)
    log_frame.grid(row=7, column=0, columnspan=4, sticky="nsew", padx=6, pady=(8, 4))
    page.grid_rowconfigure(7, weight=1)

    status = tk.StringVar(value="Ready")
    ttk.Label(page, textvariable=status).grid(row=8, column=0, columnspan=4, sticky="w", padx=6)
    runner = JobRunner(log_widget, status)

    def run():
        if not carrier_var.get() or not out_var.get():
            messagebox.showerror("Missing fields", "Set both carrier and output paths.")
            return
        args = list(CLI) + ["extract", carrier_var.get(), out_var.get()]
        env = os.environ.copy()
        if pwd_var.get():
            env["__FCGUI_PWD"] = pwd_var.get()
            args += ["--password-env", "__FCGUI_PWD"]
        if identity_var.get():
            args += ["--identity", identity_var.get()]
        if verify_var.get():
            args += ["--verify-with", verify_var.get()]
        runner.start(args, env=env, label="Extracting...")

    btn = ttk.Frame(page)
    btn.grid(row=6, column=0, columnspan=4, sticky="w", padx=6, pady=(8, 4))
    ttk.Button(btn, text="Extract", command=run).pack(side="left", padx=4)
    ttk.Button(btn, text="Clear log", command=lambda: _clear(log_widget)).pack(side="left", padx=4)


def build_keys_tab(notebook):
    page = ttk.Frame(notebook, padding=8)
    notebook.add(page, text="Keys")
    page.grid_columnconfigure(1, weight=1)

    ttk.Label(page, text="Key management (X25519 / Ed25519 / age)", font=FONT_HEADING).grid(
        row=0, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 8))

    out_var = file_picker(page, 1, "Output private key path:", save=True,
                          filetypes=[("All files", "*.*")])
    type_var = labelled_combo(page, 2, "Key type:", ["x25519", "ed25519"], default="x25519")
    age_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(page, text="Also export as age format", variable=age_var).grid(
        row=3, column=1, sticky="w", padx=6, pady=4)
    import_var = file_picker(page, 4, "Import existing age key (optional):", save=False,
                             filetypes=[("All files", "*.*")])

    log_frame, log_widget = make_log(page)
    log_frame.grid(row=7, column=0, columnspan=4, sticky="nsew", padx=6, pady=(8, 4))
    page.grid_rowconfigure(7, weight=1)
    status = tk.StringVar(value="Ready")
    ttk.Label(page, textvariable=status).grid(row=8, column=0, columnspan=4, sticky="w", padx=6)
    runner = JobRunner(log_widget, status)

    def gen():
        if not out_var.get():
            messagebox.showerror("Missing field", "Set an output key path.")
            return
        args = list(CLI) + ["keygen", out_var.get(), "--type", type_var.get(), "--force"]
        if age_var.get():
            args += ["--export-age"]
        if import_var.get():
            args += ["--import-age", import_var.get()]
        runner.start(args, label="Generating keypair...")

    btn = ttk.Frame(page)
    btn.grid(row=6, column=0, columnspan=4, sticky="w", padx=6, pady=(8, 4))
    ttk.Button(btn, text="Generate keypair", command=gen).pack(side="left", padx=4)
    ttk.Button(btn, text="Clear log", command=lambda: _clear(log_widget)).pack(side="left", padx=4)


def build_inspect_tab(notebook):
    page = ttk.Frame(notebook, padding=8)
    notebook.add(page, text="Inspect")
    page.grid_columnconfigure(1, weight=1)

    ttk.Label(page, text="Inspect a carrier or any video", font=FONT_HEADING).grid(
        row=0, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 8))

    file_var = file_picker(page, 1, "Video file:", save=False,
                           filetypes=[("Videos", "*.mp4 *.mkv *.mov *.webm")])

    log_frame, log_widget = make_log(page)
    log_frame.grid(row=4, column=0, columnspan=4, sticky="nsew", padx=6, pady=(8, 4))
    page.grid_rowconfigure(4, weight=1)
    status = tk.StringVar(value="Ready")
    ttk.Label(page, textvariable=status).grid(row=5, column=0, columnspan=4, sticky="w", padx=6)
    runner = JobRunner(log_widget, status)

    def run(cmd):
        if not file_var.get():
            messagebox.showerror("Missing field", "Pick a video file first.")
            return
        runner.start(list(CLI) + [cmd, file_var.get()], label=f"Running {cmd}...")

    btn = ttk.Frame(page)
    btn.grid(row=3, column=0, columnspan=4, sticky="w", padx=6, pady=(8, 4))
    ttk.Button(btn, text="Probe", command=lambda: run("probe")).pack(side="left", padx=4)
    ttk.Button(btn, text="Info", command=lambda: run("info")).pack(side="left", padx=4)
    ttk.Button(btn, text="Fingerprint", command=lambda: run("fingerprint")).pack(side="left", padx=4)
    ttk.Button(btn, text="Cover-score", command=lambda: run("cover-score")).pack(side="left", padx=4)
    ttk.Button(btn, text="Clear log", command=lambda: _clear(log_widget)).pack(side="left", padx=4)


def build_steganalyse_tab(notebook):
    page = ttk.Frame(notebook, padding=8)
    notebook.add(page, text="Steganalyse")
    page.grid_columnconfigure(1, weight=1)

    ttk.Label(page, text="Run LSB steganalysis detectors", font=FONT_HEADING).grid(
        row=0, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 8))

    file_var = file_picker(page, 1, "Video file:", save=False,
                           filetypes=[("Videos", "*.mp4 *.mkv *.mov *.webm")])
    frames_var, _ = labelled_entry(page, 2, "Frames to test:", default="8", width=8)
    external_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(page, text="Also run external tools (stegdetect / aletheia) if installed",
                    variable=external_var).grid(row=3, column=1, columnspan=2, sticky="w", padx=6, pady=4)

    log_frame, log_widget = make_log(page)
    log_frame.grid(row=5, column=0, columnspan=4, sticky="nsew", padx=6, pady=(8, 4))
    page.grid_rowconfigure(5, weight=1)
    status = tk.StringVar(value="Ready")
    ttk.Label(page, textvariable=status).grid(row=6, column=0, columnspan=4, sticky="w", padx=6)
    runner = JobRunner(log_widget, status)

    def run():
        if not file_var.get():
            messagebox.showerror("Missing field", "Pick a video file first.")
            return
        args = list(CLI) + ["steganalyse", file_var.get(), "--frames", frames_var.get() or "8"]
        if external_var.get():
            args += ["--external"]
        runner.start(args, label="Steganalysing...")

    btn = ttk.Frame(page)
    btn.grid(row=4, column=0, columnspan=4, sticky="w", padx=6, pady=(8, 4))
    ttk.Button(btn, text="Steganalyse", command=run).pack(side="left", padx=4)
    ttk.Button(btn, text="Clear log", command=lambda: _clear(log_widget)).pack(side="left", padx=4)


def build_tools_tab(notebook):
    page = ttk.Frame(notebook, padding=8)
    notebook.add(page, text="Tools")
    page.grid_columnconfigure(1, weight=1)

    # Make-cover section
    ttk.Label(page, text="Generate a test cover", font=FONT_HEADING).grid(
        row=0, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 8))
    out_var = file_picker(page, 1, "Output path:", save=True,
                          filetypes=[("MP4", "*.mp4")], default=str(ROOT / "default" / "default.mp4"))
    filter_var = labelled_combo(page, 2, "Filter:",
                                ["testsrc2", "mandelbrot", "smptebars", "noise", "gradient"],
                                default="mandelbrot")
    w_var, _ = labelled_entry(page, 3, "Width:", default="1280", width=8)
    h_var, _ = labelled_entry(page, 4, "Height:", default="720", width=8)
    fps_var, _ = labelled_entry(page, 5, "FPS:", default="30", width=8)
    dur_var, _ = labelled_entry(page, 6, "Duration (s):", default="10", width=8)

    # Spacer + diagnostics
    ttk.Separator(page).grid(row=7, column=0, columnspan=4, sticky="ew", padx=6, pady=12)
    ttk.Label(page, text="Diagnostics", font=FONT_HEADING).grid(
        row=8, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 8))

    log_frame, log_widget = make_log(page)
    log_frame.grid(row=11, column=0, columnspan=4, sticky="nsew", padx=6, pady=(8, 4))
    page.grid_rowconfigure(11, weight=1)
    status = tk.StringVar(value="Ready")
    ttk.Label(page, textvariable=status).grid(row=12, column=0, columnspan=4, sticky="w", padx=6)
    runner = JobRunner(log_widget, status)

    def make_cover():
        if not out_var.get():
            messagebox.showerror("Missing field", "Set an output path.")
            return
        Path(out_var.get()).parent.mkdir(parents=True, exist_ok=True)
        args = list(CLI) + ["make-cover", out_var.get(),
                            "--filter", filter_var.get(),
                            "--width", w_var.get() or "1280",
                            "--height", h_var.get() or "720",
                            "--fps", fps_var.get() or "30",
                            "--duration", dur_var.get() or "10",
                            "--force"]
        runner.start(args, label="Generating cover...")

    def run(cmd, *extra):
        runner.start(list(CLI) + [cmd] + list(extra), label=f"Running {cmd}...")

    bf1 = ttk.Frame(page)
    bf1.grid(row=9, column=0, columnspan=4, sticky="w", padx=6, pady=4)
    ttk.Button(bf1, text="Generate cover", command=make_cover).pack(side="left", padx=4)
    ttk.Button(bf1, text="Doctor", command=lambda: run("doctor")).pack(side="left", padx=4)
    ttk.Button(bf1, text="Version", command=lambda: run("version")).pack(side="left", padx=4)
    ttk.Button(bf1, text="Modes", command=lambda: run("modes")).pack(side="left", padx=4)
    ttk.Button(bf1, text="Recipes", command=lambda: run("recipes")).pack(side="left", padx=4)
    ttk.Button(bf1, text="Examples", command=lambda: run("examples")).pack(side="left", padx=4)

    bf2 = ttk.Frame(page)
    bf2.grid(row=10, column=0, columnspan=4, sticky="w", padx=6, pady=4)
    why_var, _ = labelled_entry(page, 10, "    why (error keyword):", default="", width=30)
    def why():
        run("why", why_var.get() or "SHA-256 mismatch")
    ttk.Button(page, text="Run why", command=why).grid(row=10, column=3, sticky="w", padx=6)


def build_help_tab(notebook):
    page = ttk.Frame(notebook, padding=8)
    notebook.add(page, text="Help")
    page.grid_columnconfigure(0, weight=1)
    page.grid_rowconfigure(2, weight=1)

    ttk.Label(page, text="What is FrameCourier?", font=FONT_HEADING).grid(
        row=0, column=0, sticky="w", padx=6, pady=(0, 8))
    intro = (
        "FrameCourier hides arbitrary binary files inside ordinary-looking H.264 video carriers.\n\n"
        "Default flow (Embed tab):\n"
        "  1. Pick a payload file (any file).\n"
        "  2. Pick or generate a cover video (Tools -> Generate cover).\n"
        "  3. Optionally choose a preset, mode, or crypto layer.\n"
        "  4. Type a passphrase (or pick a recipient public key for asymmetric).\n"
        "  5. Embed -> get carrier.mp4.\n\n"
        "Recovery (Extract tab):\n"
        "  1. Pick the carrier.mp4 produced earlier.\n"
        "  2. Type the same passphrase or pick the matching identity key.\n"
        "  3. Extract -> get the original file back, byte-exact.\n\n"
        "Inspect tab gives you probe / info / fingerprint / cover-score buttons; Steganalyse runs\n"
        "the built-in LSB detectors; Keys creates X25519 / Ed25519 / age keypairs; Tools generates\n"
        "test covers and runs every diagnostic command. The output area on every tab is the same\n"
        "stream you would see in the terminal."
    )
    txt = scrolledtext.ScrolledText(page, height=18, font=FONT, wrap="word")
    txt.grid(row=2, column=0, sticky="nsew", padx=6, pady=6)
    txt.insert("1.0", intro)
    txt.configure(state="disabled")


def _clear(widget):
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.configure(state="disabled")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    root = tk.Tk()
    root.title("FrameCourier")
    root.geometry("1100x780")
    root.minsize(900, 600)

    style = ttk.Style()
    try:
        style.theme_use("vista" if "vista" in style.theme_names() else "clam")
    except Exception:
        pass
    style.configure(".", font=FONT)
    style.configure("TButton", padding=(10, 4))
    style.configure("TLabelFrame.Label", font=FONT_HEADING)

    header = ttk.Frame(root, padding=(12, 8))
    header.pack(side="top", fill="x")
    ttk.Label(header, text="FrameCourier", font=("Segoe UI Semibold", 16)).pack(side="left")
    ttk.Label(header, text="  hide files inside H.264 video carriers", foreground="#555").pack(side="left")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    build_embed_tab(notebook)
    build_extract_tab(notebook)
    build_keys_tab(notebook)
    build_inspect_tab(notebook)
    build_steganalyse_tab(notebook)
    build_tools_tab(notebook)
    build_help_tab(notebook)

    footer = ttk.Frame(root, padding=(12, 4))
    footer.pack(side="bottom", fill="x")
    ttk.Label(footer, text="Outputs run the CLI verbatim. See the same logs you would get in the terminal.",
              foreground="#666").pack(side="left")

    root.mainloop()


if __name__ == "__main__":
    main()
