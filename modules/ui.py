#!/usr/bin/env python3
"""tbh ui - curses interface for people who live in termux.

fullscreen: tools / scan / findings / config.
j-k or arrows to move, enter to run, tab switches section, q quits.
output shows up in the bottom pane while a tool runs.
"""
import argparse
import datetime
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import threading

VERSION = "1.0"
TBH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tbh"))
HOME = os.path.expanduser("~/.tbh")
JOBS_DIR = os.path.join(HOME, "jobs")

from importlib.machinery import SourceFileLoader
_loader = SourceFileLoader("tbh_dispatch", TBH)
_spec = importlib.util.spec_from_loader("tbh_dispatch", _loader)
tbh = importlib.util.module_from_spec(_spec)
_loader.exec_module(tbh)

TARGET_FLAG = {"portscan": "-t", "subfinder": "-t"}
NO_TARGET = {"utils", "passstrength"}
CONFIG_ROWS = [("proxy", "http://127.0.0.1:8080"),
               ("cookie", "session=..."),
               ("timeout", "10"),
               ("header", "one per line, enter to edit")]

SECTIONS = ("tools", "scan", "findings", "config")


class Job:
    def __init__(self, tool, cmd, log_path):
        self.tool = tool
        self.cmd = cmd
        self.lines = []
        self.rc = None
        self.started = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_path = log_path
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        try:
            with open(self.log_path, "w") as logf:
                proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        text=True, bufsize=1)
                for line in proc.stdout:
                    self.lines.append(line.rstrip("\n"))
                    logf.write(line)
                self.rc = proc.wait()
        except OSError as e:
            self.lines.append(f"[!] {e}")
            self.rc = 127


def start_job(tool, target, flags):
    jid = datetime.datetime.now().strftime("%H%M%S") + "-" + tool
    jdir = os.path.join(JOBS_DIR, jid)
    os.makedirs(jdir, exist_ok=True)
    flag = TARGET_FLAG.get(tool, "-u")
    cmd = [sys.executable, TBH, tool]
    if target and tool not in NO_TARGET:
        cmd += [flag, target]
    cmd += tbh.finalize_argv(tool, flags)
    return Job(tool, cmd, os.path.join(jdir, "out.log"))


class App:
    def __init__(self):
        self.sec = 0
        self.ti = 0          # tool index
        self.scroll = 0      # findings scroll
        self.out_scroll = 0  # output pane scroll from bottom
        self.job = None
        self.status = "welcome. j-k move, enter run, tab switch, q quit."
        self.scan_deep = False
        self.findings_cache = None
        self.colors = {}

    # ---------- drawing ----------
    def init_colors(self, scr):
        import curses
        scr.start_color()
        scr.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_CYAN, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_YELLOW, -1)
        curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_CYAN)
        self.colors = {k: curses.color_pair(v) for k, v in
                       {"red": 1, "cyan": 2, "grn": 3, "amb": 4, "sel": 5}.items()}

    def prompt(self, scr, label, default=""):
        import curses
        scr.timeout(-1)
        curses.curs_set(1)
        h, w = scr.getmaxyx()
        line = f" {label}: {default}"
        scr.move(h - 1, 0)
        scr.clrtoeol()
        scr.addstr(h - 1, 0, line[:w - 2], self.colors["cyan"])
        scr.refresh()
        try:
            raw = scr.getstr(h - 1, min(len(line), w - 2), 200)
            val = raw.decode(errors="replace").strip()
        except Exception:
            val = ""
        curses.curs_set(0)
        scr.timeout(120)
        return val if val else (default if default else "")

    def draw(self, scr):
        import curses
        scr.erase()
        h, w = scr.getmaxyx()
        # title
        title = f" TBH v{tbh.VERSION} "
        scr.addstr(0, 0, title, self.colors["red"] | curses.A_BOLD)
        scr.addstr(0, len(title), "tulungagung black hat - authorized testing only",
                   self.colors["cyan"])
        # tabs
        x = 0
        for i, s in enumerate(SECTIONS):
            label = f" {s} "
            attr = self.colors["sel"] if i == self.sec else curses.A_DIM
            scr.addstr(1, x, label, attr)
            x += len(label) + 1
        scr.hline(2, 0, curses.ACS_HLINE, w)

        body_top = 3
        out_h = max(6, h // 3)
        body_bot = h - 2 - out_h
        if body_bot < body_top + 3:
            body_bot = body_top + 3
            out_h = h - 2 - body_bot

        if self.sec == 0:
            self.draw_tools(scr, body_top, body_bot, w)
        elif self.sec == 1:
            self.draw_scan(scr, body_top, body_bot, w)
        elif self.sec == 2:
            self.draw_findings(scr, body_top, body_bot, w)
        else:
            self.draw_config(scr, body_top, body_bot, w)

        # output pane
        scr.hline(h - 2 - out_h - 1, 0, curses.ACS_HLINE, w)
        label = " output "
        if self.job:
            state = "running..." if self.job.rc is None else f"exit {self.job.rc}"
            label = f" output - {self.job.tool} ({state}) "
        scr.addstr(h - 2 - out_h - 1, 2, label, self.colors["amb"])
        self.draw_output(scr, h - 1 - out_h, out_h, w)

        # status bar
        msg = f" {self.status}"
        scr.hline(h - 2, 0, curses.ACS_HLINE, w)
        try:
            scr.addstr(h - 1, 0, msg[:w - 1], curses.A_DIM)
        except curses.error:
            pass
        scr.refresh()

    def draw_tools(self, scr, top, bot, w):
        import curses
        names = [n for n, _, _ in tbh.REGISTRY]
        list_h = bot - top
        sel_y = top
        for i, (name, _mod, desc) in enumerate(tbh.REGISTRY[:list_h]):
            attr = self.colors["sel"] if i == self.ti else 0
            mark = ">" if i == self.ti else " "
            scr.addstr(top + i, 0, f" {mark} {name}", attr | curses.A_BOLD if i == self.ti else 0)
            if i == self.ti:
                scr.addstr(top + i, 18, desc[: w - 20], self.colors["cyan"])
            else:
                scr.addstr(top + i, 18, desc[: w - 20], curses.A_DIM)
        name, _m, desc = tbh.REGISTRY[self.ti]
        hint = " enter: run  "
        if name in NO_TARGET:
            hint += "(no url needed)"
        elif name == "scan":
            hint += "(try the scan tab, nicer)"
        scr.addstr(bot - 1, 2, hint[: w - 2], self.colors["amb"])

    def draw_scan(self, scr, top, bot, w):
        import curses
        scr.addstr(top, 2, "quick multi-tool scan", curses.A_BOLD)
        deep = "[x]" if self.scan_deep else "[ ]"
        scr.addstr(top + 2, 2, f"deep {deep}  (d toggles: subs+dirs+js+ports+phish)",
                   self.colors["cyan"])
        scr.addstr(top + 4, 2, "enter: prompt for url, then run", curses.A_DIM)
        scr.addstr(top + 5, 2, "findings land in ~/.tbh/findings.jsonl", curses.A_DIM)

    def draw_findings(self, scr, top, bot, w):
        import curses
        recs = load_findings()
        self.findings_cache = recs
        scr.addstr(top, 2, f"{len(recs)} saved finding(s)", curses.A_BOLD)
        if not recs:
            scr.addstr(top + 2, 2, "run a scan first (scan tab)", curses.A_DIM)
            return
        rows = recs[::-1][: bot - top - 2]
        for i, r in enumerate(rows):
            y = top + 2 + i
            if y >= bot:
                break
            sev = str(r.get("severity", "info"))
            attr = self.colors["amb"] if sev == "medium" else (
                self.colors["red"] if sev == "high" else curses.A_DIM)
            line = (f" {r.get('when','?')[-8:]}  {sev:<7}  "
                    f"{r.get('tool','?'):<10}  {r.get('url', r.get('target',''))}")
            scr.addstr(y, 2, line[: w - 4], attr)

    def draw_config(self, scr, top, bot, w):
        import curses
        cfg = tbh.load_config()
        scr.addstr(top, 2, "config (applies to every run, menu + cli + here)",
                   curses.A_BOLD)
        keys = ["proxy", "cookie", "timeout", "header"]
        for i, k in enumerate(keys):
            y = top + 2 + i
            v = cfg.get(k)
            if k == "header":
                v = f"{len(v or [])} header(s)" if v else ""
            shown = str(v) if v else "(empty)"
            scr.addstr(y, 4, f"{k:<8}", curses.A_DIM)
            scr.addstr(y, 14, shown[: w - 16],
                       self.colors["grn"] if v else curses.A_DIM)
        scr.addstr(bot - 1, 2, "enter: edit  d: clear  (stored in ~/.tbh/config.json)",
                   self.colors["amb"])

    def draw_output(self, scr, top, h, w):
        job = self.job
        if not job or not job.lines:
            try:
                scr.addstr(top, 2, "(no output yet)", curses.A_DIM)
            except Exception:
                pass
            return
        n = max(0, len(job.lines) - h - self.out_scroll)
        chunk = job.lines[n: n + h]
        for i, ln in enumerate(chunk):
            attr = 0
            if "[+]" in ln or "[ok]" in ln or " ok " in ln:
                attr = self.colors["grn"]
            elif "[!]" in ln or "[✗]" in ln or "err" in ln:
                attr = self.colors["red"]
            elif "finding" in ln or "hit" in ln:
                attr = self.colors["amb"]
            try:
                scr.addstr(top + i, 2, ln[: w - 4], attr)
            except Exception:
                break

    # ---------- input ----------
    def handle_key(self, scr, ch):
        import curses
        key = ch
        # map arrows to vim keys
        if ch == curses.KEY_UP:
            key = ord("k")
        elif ch == curses.KEY_DOWN:
            key = ord("j")
        elif ch == curses.KEY_PPAGE:
            self.out_scroll += 5
            return
        elif ch == curses.KEY_NPAGE:
            self.out_scroll = max(0, self.out_scroll - 5)
            return
        if key in (ord("q"),) and self.sec != -1:
            raise KeyboardInterrupt
        if key == 9:  # tab
            self.sec = (self.sec + 1) % len(SECTIONS)
            self.status = f"section: {SECTIONS[self.sec]}"
            return
        if key in (ord("1"), ord("2"), ord("3"), ord("4")):
            self.sec = key - ord("1")
            return
        if self.sec == 0:
            self.key_tools(scr, key)
        elif self.sec == 1:
            self.key_scan(scr, key)
        elif self.sec == 2:
            if key in (ord("j"),):
                self.scroll += 1
            elif key in (ord("k"),):
                self.scroll = max(0, self.scroll - 1)
        elif self.sec == 3:
            self.key_config(scr, key)

    def key_tools(self, scr, key):
        n = len(tbh.REGISTRY)
        if key in (ord("j"),):
            self.ti = (self.ti + 1) % n
        elif key in (ord("k"),):
            self.ti = (self.ti - 1) % n
        elif key in (10, 13, 343):
            name = tbh.REGISTRY[self.ti][0]
            target = ""
            flags = []
            if name not in NO_TARGET:
                default = ""
                try:
                    with open(os.path.join(HOME, "last_target")) as f:
                        default = f.read().strip()
                except OSError:
                    pass
                target = self.prompt(scr, f"{name} url (blank = tool menu)", default)
                if target:
                    try:
                        os.makedirs(HOME, exist_ok=True)
                        with open(os.path.join(HOME, "last_target"), "w") as f:
                            f.write(target)
                    except OSError:
                        pass
            extra = self.prompt(scr, "extra flags (optional)")
            if extra:
                try:
                    flags = shlex.split(extra)
                except ValueError as e:
                    self.status = f"bad flags: {e}"
                    return
            self.out_scroll = 0
            self.job = start_job(name, target, flags)
            self.status = f"running {name}..."

    def key_scan(self, scr, key):
        if key == ord("d"):
            self.scan_deep = not self.scan_deep
        elif key in (10, 13):
            default = ""
            try:
                with open(os.path.join(HOME, "last_target")) as f:
                    default = f.read().strip()
            except OSError:
                pass
            url = self.prompt(scr, "scan url", default)
            if not url:
                self.status = "need a url"
                return
            try:
                os.makedirs(HOME, exist_ok=True)
                with open(os.path.join(HOME, "last_target"), "w") as f:
                    f.write(url)
            except OSError:
                pass
            flags = ["--deep"] if self.scan_deep else []
            self.out_scroll = 0
            self.job = start_job("scan", url, flags)
            self.status = "running scan..."

    def key_config(self, scr, key):
        keys = ["proxy", "cookie", "timeout", "header"]
        cfg = tbh.load_config()
        if not hasattr(self, "cfg_i"):
            self.cfg_i = 0
        if key in (ord("j"),):
            self.cfg_i = (self.cfg_i + 1) % len(keys)
        elif key in (ord("k"),):
            self.cfg_i = (self.cfg_i - 1) % len(keys)
        elif key in (10, 13):
            k = keys[self.cfg_i]
            if k == "header":
                cur = "\n".join(cfg.get("header") or [])
                val = self.prompt(scr, "headers ( ; separated)", cur.replace("\n", ";"))
                hs = [x.strip() for x in val.split(";") if x.strip()]
                if hs:
                    cfg["header"] = hs
                else:
                    cfg.pop("header", None)
            else:
                val = self.prompt(scr, f"{k} = ", str(cfg.get(k, "")))
                if val:
                    if k == "timeout":
                        try:
                            cfg[k] = int(val)
                        except ValueError:
                            self.status = "timeout must be a number"
                            return
                    else:
                        cfg[k] = val
                else:
                    cfg.pop(k, None)
            tbh.save_config(cfg)
            self.status = f"saved {k}"
        elif key == ord("d"):
            k = keys[self.cfg_i]
            cfg.pop(k, None)
            tbh.save_config(cfg)
            self.status = f"cleared {k}"


def load_findings():
    recs = []
    try:
        with open(tbh.FINDINGS_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return recs


def run_ui():
    import curses
    os.makedirs(JOBS_DIR, exist_ok=True)
    app = App()

    def _loop(scr):
        curses.curs_set(0)
        app.init_colors(scr)
        scr.timeout(120)
        while True:
            app.draw(scr)
            ch = scr.getch()
            if ch == -1:
                continue
            try:
                app.handle_key(scr, ch)
            except KeyboardInterrupt:
                return

    try:
        curses.wrapper(_loop)
    except KeyboardInterrupt:
        print("bye.")
    return 0


def selftest():
    """no-screen sanity check (safe for CI)."""
    import curses  # noqa: F401
    assert len(tbh.REGISTRY) >= 18
    assert "scan" in {n for n, _, _ in tbh.REGISTRY}
    a = App()
    assert SECTIONS[a.sec] == "tools"
    print("ui selftest ok")
    return 0


def main():
    p = argparse.ArgumentParser(prog="tbh ui",
                                description="curses interface for the toolkit")
    p.add_argument("--selftest", action="store_true",
                   help="no-screen sanity check (for CI)")
    p.add_argument("--version", action="version", version=f"tbh-ui {VERSION}")
    args = p.parse_args()
    if args.selftest:
        return selftest()
    if not sys.stdout.isatty():
        print("[!] ui needs a real terminal (tty). try: tbh --help for cli mode.",
              file=sys.stderr)
        return 2
    return run_ui()


if __name__ == "__main__":
    sys.exit(main())
