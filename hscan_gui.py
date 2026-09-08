#!/usr/bin/env python3
"""
HScan GUI - a simple tkinter frontend for the HScan CLI.

Place this script next to hscan.exe (Windows) or hscan (Linux/macOS) and run:
    python hscan_gui.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext


class HScanGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("HScan GUI v1.0.1")
        self.root.geometry("720x560")
        self.root.configure(bg="#1e1e1e")
        self.root.minsize(640, 480)

        colors = {
            "bg": "#1e1e1e",
            "fg": "#d4d4d4",
            "accent": "#61d475",
            "input_bg": "#252526",
            "input_fg": "#ffffff",
            "log_bg": "#121212",
        }

        tk.Label(
            root,
            text="HScan — Secret & Cloud Credential Scanner",
            font=("Segoe UI", 14, "bold"),
            bg=colors["bg"],
            fg=colors["accent"],
        ).pack(pady=(16, 8))

        self.config_path = tk.StringVar(value="config.json")
        self.target_path = tk.StringVar()
        self.mode_var = tk.StringVar(value="scan")
        self.timeout_var = tk.StringVar(value="20")
        self.batch_var = tk.StringVar(value="500000")

        def add_row(label, var, browse_cmd):
            frame = tk.Frame(root, bg=colors["bg"])
            frame.pack(fill=tk.X, padx=24, pady=6)
            tk.Label(frame, text=label, font=("Segoe UI", 10), bg=colors["bg"], fg=colors["fg"], width=12, anchor=tk.W).pack(side=tk.LEFT)
            entry = tk.Entry(frame, textvariable=var, font=("Consolas", 10), bg=colors["input_bg"], fg=colors["input_fg"], insertbackground=colors["fg"], relief=tk.FLAT)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 8), ipady=4)
            tk.Button(frame, text="Browse", font=("Segoe UI", 9), bg=colors["input_bg"], fg=colors["fg"], relief=tk.FLAT, command=browse_cmd).pack(side=tk.RIGHT, ipadx=8)

        add_row("Config:", self.config_path, self._browse_config)
        add_row("Target list:", self.target_path, self._browse_target)

        mode_frame = tk.Frame(root, bg=colors["bg"])
        mode_frame.pack(fill=tk.X, padx=24, pady=6)
        tk.Label(mode_frame, text="Mode:", font=("Segoe UI", 10), bg=colors["bg"], fg=colors["fg"], width=12, anchor=tk.W).pack(side=tk.LEFT)
        for text, value in [("Scan targets", "scan"), ("GitHub token deep scan", "tokens")]:
            tk.Radiobutton(mode_frame, text=text, variable=self.mode_var, value=value, font=("Segoe UI", 10), bg=colors["bg"], fg=colors["fg"], selectcolor=colors["input_bg"]).pack(side=tk.LEFT, padx=8)

        opts_frame = tk.Frame(root, bg=colors["bg"])
        opts_frame.pack(fill=tk.X, padx=24, pady=6)
        tk.Label(opts_frame, text="Timeout:", font=("Segoe UI", 10), bg=colors["bg"], fg=colors["fg"]).pack(side=tk.LEFT)
        tk.Entry(opts_frame, textvariable=self.timeout_var, font=("Consolas", 10), bg=colors["input_bg"], fg=colors["input_fg"], width=8, relief=tk.FLAT).pack(side=tk.LEFT, padx=(8, 16))
        tk.Label(opts_frame, text="Batch:", font=("Segoe UI", 10), bg=colors["bg"], fg=colors["fg"]).pack(side=tk.LEFT)
        tk.Entry(opts_frame, textvariable=self.batch_var, font=("Consolas", 10), bg=colors["input_bg"], fg=colors["input_fg"], width=10, relief=tk.FLAT).pack(side=tk.LEFT, padx=(8, 0))

        run_btn = tk.Button(
            root,
            text="Run HScan",
            font=("Segoe UI", 11, "bold"),
            bg=colors["accent"],
            fg="#000000",
            relief=tk.FLAT,
            cursor="hand2",
            command=self._run,
        )
        run_btn.pack(pady=12, ipadx=24, ipady=6)

        tk.Label(root, text="Output", font=("Segoe UI", 10, "bold"), bg=colors["bg"], fg=colors["fg"]).pack(anchor=tk.W, padx=24, pady=(8, 4))
        self.log = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg=colors["log_bg"],
            fg=colors["fg"],
            insertbackground=colors["fg"],
            relief=tk.FLAT,
            state=tk.DISABLED,
        )
        self.log.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 16))

    def _browse_config(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if path:
            self.config_path.set(path)

    def _browse_target(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.target_path.set(path)

    def _log(self, text: str) -> None:
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    def _run(self) -> None:
        target = self.target_path.get().strip()
        if not target:
            messagebox.showerror("Error", "Please select a target list file.")
            return

        exe = "hscan.exe" if sys.platform == "win32" else "hscan"
        exe_path = Path(exe)
        if not exe_path.exists():
            # Try same directory as this script
            exe_path = Path(__file__).parent / exe
        if not exe_path.exists():
            messagebox.showerror("Error", f"Could not find {exe}. Place it next to this script.")
            return

        args = [str(exe_path), "-timeout", self.timeout_var.get(), "-batch", self.batch_var.get()]
        if self.mode_var.get() == "tokens":
            args.extend(["-tokenlist", target])
        else:
            args.append(target)

        cwd = str(Path(self.config_path.get()).parent) if self.config_path.get() else None

        self._log("$ " + " ".join(args))
        self.process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=cwd,
        )

        def read_output():
            for line in self.process.stdout:
                self._log(line.rstrip())
            self._log("[HScan process finished]")

        import threading
        threading.Thread(target=read_output, daemon=True).start()


def main() -> int:
    root = tk.Tk()
    HScanGUI(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
