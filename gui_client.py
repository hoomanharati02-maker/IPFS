#!/usr/bin/env python3
import os
import threading
import urllib.request
import urllib.parse
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

DEFAULT_BASE = "http://127.0.0.1:9000"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OS Project – IPFS-like Client")
        self.geometry("760x520")
        self.minsize(720, 480)

        self.base_url = tk.StringVar(value=DEFAULT_BASE)
        self.upload_path = tk.StringVar(value="")
        self.download_cid = tk.StringVar(value="")
        self.download_path = tk.StringVar(value="")

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 8}

        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Gateway URL:").pack(side="left")
        ttk.Entry(top, textvariable=self.base_url, width=40).pack(side="left", padx=8)
        ttk.Button(top, text="Ping", command=self.ping).pack(side="left")

        sep = ttk.Separator(self, orient="horizontal")
        sep.pack(fill="x", padx=10, pady=5)

        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=10, pady=10)

        # Upload group
        up = ttk.LabelFrame(main, text="Upload")
        up.pack(fill="x", pady=6)

        row1 = ttk.Frame(up)
        row1.pack(fill="x", padx=10, pady=8)
        ttk.Entry(row1, textvariable=self.upload_path).pack(side="left", fill="x", expand=True)
        ttk.Button(row1, text="Choose file…", command=self.choose_upload).pack(side="left", padx=8)

        row2 = ttk.Frame(up)
        row2.pack(fill="x", padx=10, pady=8)
        self.up_progress = ttk.Progressbar(row2, mode="determinate")
        self.up_progress.pack(side="left", fill="x", expand=True)
        ttk.Button(row2, text="Upload", command=self.start_upload).pack(side="left", padx=8)

        self.cid_label = ttk.Label(up, text="CID: (none)")
        self.cid_label.pack(anchor="w", padx=10, pady=(0, 10))

        # Download group
        down = ttk.LabelFrame(main, text="Download")
        down.pack(fill="x", pady=6)

        drow1 = ttk.Frame(down)
        drow1.pack(fill="x", padx=10, pady=8)
        ttk.Label(drow1, text="CID:").pack(side="left")
        ttk.Entry(drow1, textvariable=self.download_cid).pack(side="left", fill="x", expand=True, padx=8)

        drow2 = ttk.Frame(down)
        drow2.pack(fill="x", padx=10, pady=8)
        ttk.Entry(drow2, textvariable=self.download_path).pack(side="left", fill="x", expand=True)
        ttk.Button(drow2, text="Save as…", command=self.choose_download).pack(side="left", padx=8)

        drow3 = ttk.Frame(down)
        drow3.pack(fill="x", padx=10, pady=8)
        self.down_progress = ttk.Progressbar(drow3, mode="indeterminate")
        self.down_progress.pack(side="left", fill="x", expand=True)
        ttk.Button(drow3, text="Download", command=self.start_download).pack(side="left", padx=8)

        # Logs
        logs = ttk.LabelFrame(main, text="Logs")
        logs.pack(fill="both", expand=True, pady=6)

        self.log = tk.Text(logs, height=10, wrap="word")
        self.log.pack(fill="both", expand=True, padx=10, pady=10)
        self.log.configure(state="disabled")

    def write_log(self, msg: str):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def ping(self):
        # Gateway has no explicit ping; we try GET / (should 404 quickly).
        base = self.base_url.get().rstrip("/")
        url = base + "/"
        self.write_log(f"Ping: {url}")
        def run():
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=3) as resp:
                    self.write_log(f"Ping response: {resp.status}")
            except Exception as e:
                self.write_log(f"Ping failed: {e}")
        threading.Thread(target=run, daemon=True).start()

    def choose_upload(self):
        p = filedialog.askopenfilename(title="Select file to upload")
        if p:
            self.upload_path.set(p)
            self.write_log(f"Selected upload: {p}")

    def start_upload(self):
        path = self.upload_path.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Upload", "Please choose a valid file.")
            return

        base = self.base_url.get().rstrip("/")
        url = base + "/upload"
        fname = os.path.basename(path)
        size = os.path.getsize(path)

        self.up_progress.configure(value=0, maximum=max(size, 1))
        self.write_log(f"Uploading {fname} ({size} bytes) -> {url}")

        def run():
            try:
                # Stream the body from file:
                with open(path, "rb") as f:
                    data = f.read()  # simplest; fine for lab-scale files
                headers = {
                    "X-Filename": fname,
                    "Content-Length": str(len(data)),
                }
                req = urllib.request.Request(url, data=data, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                self.up_progress.configure(value=size)
                obj = json.loads(body)
                cid = obj.get("cid", "")
                self.cid_label.configure(text=f"CID: {cid}")
                self.download_cid.set(cid)
                self.write_log(f"Upload done. CID={cid}")
            except Exception as e:
                self.write_log(f"Upload failed: {e}")
                messagebox.showerror("Upload", str(e))

        threading.Thread(target=run, daemon=True).start()

    def choose_download(self):
        p = filedialog.asksaveasfilename(title="Save downloaded file as…", defaultextension=".bin")
        if p:
            self.download_path.set(p)
            self.write_log(f"Download target: {p}")

    def start_download(self):
        cid = self.download_cid.get().strip()
        outp = self.download_path.get().strip()
        if not cid:
            messagebox.showerror("Download", "Please enter a CID.")
            return
        if not outp:
            messagebox.showerror("Download", "Please choose a save path.")
            return

        base = self.base_url.get().rstrip("/")
        url = base + "/download?" + urllib.parse.urlencode({"cid": cid})
        self.write_log(f"Downloading {cid} -> {outp}")

        self.down_progress.start(10)

        def run():
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=30) as resp, open(outp, "wb") as out:
                    while True:
                        chunk = resp.read(256 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)
                self.write_log("Download done.")
            except Exception as e:
                self.write_log(f"Download failed: {e}")
                messagebox.showerror("Download", str(e))
            finally:
                self.down_progress.stop()

        threading.Thread(target=run, daemon=True).start()

if __name__ == "__main__":
    try:
        import tkinter  # noqa: F401
    except Exception:
        raise SystemExit("tkinter is not available in this Python installation.")
    App().mainloop()