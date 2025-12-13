import os
import signal
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox

DEFAULT_ENGINE_EXE = "./c_engine"
DEFAULT_GATEWAY_PY = "./main.py"
DEFAULT_SOCK = "/tmp/cengine.sock"
DEFAULT_STORE = "./store"

class ProcPane:
    def __init__(self, master, title):
        self.frame = tk.LabelFrame(master, text=title, padx=8, pady=8)
        self.text = tk.Text(self.frame, height=14, wrap="none")
        self.text.pack(fill="both", expand=True)
        self.proc = None
        self._reader_thread = None
        self._stop_reader = threading.Event()

    def append(self, s: str):
        self.text.insert("end", s)
        self.text.see("end")

    def start(self, cmd, env=None, cwd=None):
        if self.proc and self.proc.poll() is None:
            messagebox.showinfo("Already running", "Process is already running.")
            return
        self._stop_reader.clear()
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                bufsize=1,
                env=env,
                cwd=cwd,
            )
        except FileNotFoundError:
            messagebox.showerror("Not found", f"Could not run: {cmd[0]}\nCheck the path.")
            self.proc = None
            return
        except Exception as e:
            messagebox.showerror("Failed to start", str(e))
            self.proc = None
            return

        self.append(f"$ {' '.join(cmd)}\n")
        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

    def _reader_loop(self):
        assert self.proc is not None
        out = self.proc.stdout
        if out is None:
            return
        try:
            for line in out:
                if self._stop_reader.is_set():
                    break
                self.append(line)
        except Exception as e:
            self.append(f"[viewer] log reader error: {e}\n")

    def stop(self):
        if not self.proc or self.proc.poll() is not None:
            return
        self.append("[viewer] sending SIGINT...\n")
        try:
            self.proc.send_signal(signal.SIGINT)
        except Exception:
            pass

        # Give it a moment to exit cleanly
        for _ in range(20):
            if self.proc.poll() is not None:
                break
            time.sleep(0.1)

        if self.proc.poll() is None:
            self.append("[viewer] SIGINT not enough, sending SIGTERM...\n")
            try:
                self.proc.terminate()
            except Exception:
                pass

        for _ in range(20):
            if self.proc.poll() is not None:
                break
            time.sleep(0.1)

        if self.proc.poll() is None:
            self.append("[viewer] force killing...\n")
            try:
                self.proc.kill()
            except Exception:
                pass

        self._stop_reader.set()
        self.append(f"[viewer] exited with code {self.proc.poll()}\n")

    def is_running(self):
        return self.proc is not None and self.proc.poll() is None

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OS Project – Engine Viewer (Bonus GUI)")
        self.geometry("980x720")

        # Top controls
        top = tk.Frame(self, padx=10, pady=10)
        top.pack(fill="x")

        self.engine_path = tk.StringVar(value=DEFAULT_ENGINE_EXE)
        self.gateway_path = tk.StringVar(value=DEFAULT_GATEWAY_PY)
        self.sock_path = tk.StringVar(value=DEFAULT_SOCK)
        self.store_dir = tk.StringVar(value=DEFAULT_STORE)

        self._row(top, "Engine executable:", self.engine_path, browse_file=True)
        self._row(top, "Gateway script (main.py):", self.gateway_path, browse_file=True)
        self._row(top, "Socket path:", self.sock_path, browse_file=False)
        self._row(top, "Store dir:", self.store_dir, browse_dir=True)

        btns = tk.Frame(top)
        btns.pack(fill="x", pady=(8, 0))

        self.btn_start_engine = tk.Button(btns, text="Start Engine", command=self.start_engine)
        self.btn_stop_engine = tk.Button(btns, text="Stop Engine", command=self.stop_engine)
        self.btn_start_gateway = tk.Button(btns, text="Start Gateway", command=self.start_gateway)
        self.btn_stop_gateway = tk.Button(btns, text="Stop Gateway", command=self.stop_gateway)

        self.btn_start_engine.pack(side="left", padx=4)
        self.btn_stop_engine.pack(side="left", padx=4)
        self.btn_start_gateway.pack(side="left", padx=16)
        self.btn_stop_gateway.pack(side="left", padx=4)

        # Stats
        stats = tk.Frame(top)
        stats.pack(fill="x", pady=(8, 0))
        self.lbl_stats = tk.Label(stats, text="Store stats: (waiting...)")
        self.lbl_stats.pack(anchor="w")

        # Logs panes
        panes = tk.PanedWindow(self, orient="vertical")
        panes.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.engine_pane = ProcPane(panes, "c_engine logs")
        self.gateway_pane = ProcPane(panes, "main.py gateway logs")

        panes.add(self.engine_pane.frame)
        panes.add(self.gateway_pane.frame)

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(500, self.refresh_stats)

    def _row(self, parent, label, var, browse_file=False, browse_dir=False):
        row = tk.Frame(parent)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=label, width=22, anchor="w").pack(side="left")
        ent = tk.Entry(row, textvariable=var)
        ent.pack(side="left", fill="x", expand=True)
        if browse_file:
            tk.Button(row, text="Browse", command=lambda: self._browse_file(var)).pack(side="left", padx=4)
        if browse_dir:
            tk.Button(row, text="Browse", command=lambda: self._browse_dir(var)).pack(side="left", padx=4)

    def _browse_file(self, var):
        path = filedialog.askopenfilename()
        if path:
            var.set(path)

    def _browse_dir(self, var):
        path = filedialog.askdirectory()
        if path:
            var.set(path)

    def start_engine(self):
        exe = self.engine_path.get().strip()
        sock = self.sock_path.get().strip()

        if not exe:
            messagebox.showerror("Missing", "Engine executable path is empty.")
            return
        if not sock:
            messagebox.showerror("Missing", "Socket path is empty.")
            return

        env = os.environ.copy()
        cmd = [exe, sock]
        self.engine_pane.start(cmd, env=env)

    def stop_engine(self):
        self.engine_pane.stop()

    def start_gateway(self):
        py = self.gateway_path.get().strip()
        if not py:
            messagebox.showerror("Missing", "Gateway script path is empty.")
            return
        cmd = ["python3", py]
        self.gateway_pane.start(cmd, env=os.environ.copy())

    def stop_gateway(self):
        self.gateway_pane.stop()

    def refresh_stats(self):
        store = self.store_dir.get().strip() or DEFAULT_STORE
        blocks = 0
        manifests = 0
        try:
            bdir = os.path.join(store, "blocks")
            mdir = os.path.join(store, "manifests")
            if os.path.isdir(bdir):
                for root, _, files in os.walk(bdir):
                    for f in files:
                        if f.endswith(".bin"):
                            blocks += 1
            if os.path.isdir(mdir):
                for f in os.listdir(mdir):
                    if f.endswith(".json"):
                        manifests += 1
            self.lbl_stats.config(text=f"Store stats: blocks={blocks}   manifests={manifests}   store={store}")
        except Exception as e:
            self.lbl_stats.config(text=f"Store stats: error reading '{store}': {e}")

        self.after(1000, self.refresh_stats)

    def on_close(self):
        try:
            if self.gateway_pane.is_running():
                self.gateway_pane.stop()
        except Exception:
            pass
        try:
            if self.engine_pane.is_running():
                self.engine_pane.stop()
        except Exception:
            pass
        self.destroy()

if __name__ == "__main__":
    App().mainloop()