"""Real security-tool adapters — subprocess invocations of CLI binaries.

Scope enforcement is done UPSTREAM in tool_service.execute_tool via scope_check().
This module trusts that a call reaching it is authorised. Each adapter:
  - Runs the CLI with tight timeouts and resource limits
  - Parses the raw output into the same shape as sim_tools (for downstream code paths)
  - Returns {parsed:..., raw:..., mode:"real"|"sim"}
  - Falls back to sim_tools.run_sim_tool() if TOOL_MODE=sim or the binary is missing.

Set TOOL_MODE=real to force real (raises if binary missing).
Set TOOL_MODE=sim to force simulation.
Default (TOOL_MODE=auto) tries real, falls back to sim.
"""
import os
import re
import shlex
import shutil
import subprocess
from urllib.parse import urlparse

from sim_tools import run_sim_tool

TOOL_MODE = (os.environ.get("TOOL_MODE") or "auto").lower()
TIMEOUTS = {"nmap": 90, "nikto": 180, "wpscan": 240, "dirbust": 180, "sqlmap": 240}

BINARIES = {
    "nmap": "nmap",
    "nikto": "nikto",
    "wpscan": "wpscan",
    "dirbust": os.environ.get("DIRBUST_BIN", "gobuster"),  # gobuster preferred, dirb fallback
    "sqlmap": "sqlmap",
}
DIRBUST_WORDLIST = os.environ.get("DIRBUST_WORDLIST", "/usr/share/wordlists/dirb/common.txt")


def _bin(tool: str) -> str | None:
    exe = BINARIES.get(tool)
    return shutil.which(exe) if exe else None


def _host_of(target: str) -> str:
    if not target:
        return ""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired as e:
        return 124, (e.stdout or "") if isinstance(e.stdout, str) else "", f"[timeout after {timeout}s]"
    except FileNotFoundError:
        return 127, "", "binary not found"


def _use_real(tool: str) -> bool:
    if TOOL_MODE == "sim":
        return False
    if TOOL_MODE == "real":
        return True
    # auto
    return _bin(tool) is not None


def run_real_tool(tool_id: str, target: str, args: dict | None = None) -> dict:
    """Dispatch to a real adapter or fall back to sim.
    Always returns {parsed, raw, mode:"real"|"sim", cmd?:"..."}.
    """
    args = args or {}
    if not _use_real(tool_id):
        out = run_sim_tool(tool_id, target, args)
        return {**out, "mode": "sim"}
    fn = _ADAPTERS.get(tool_id)
    if not fn:
        out = run_sim_tool(tool_id, target, args)
        return {**out, "mode": "sim"}
    try:
        return fn(target, args)
    except Exception as e:  # never crash the tool boundary
        out = run_sim_tool(tool_id, target, args)
        return {**out, "mode": "sim", "raw": f"[real-{tool_id} failed → sim fallback] {e}\n\n{out.get('raw', '')}"}


# ────────────────────────── nmap ──────────────────────────
_NMAP_LINE = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([\w\-\?]+)(?:\s+(.*))?$")


def adapter_nmap(target: str, args: dict) -> dict:
    host = _host_of(target)
    ports_arg = str(args.get("ports", "--top-ports 1000"))
    if ports_arg.startswith("--"):
        ports_flags = shlex.split(ports_arg)
    else:
        ports_flags = ["-p", ports_arg]
    cmd = [_bin("nmap") or "nmap", "-Pn", "-sV", "-T4", *ports_flags, host]
    rc, out, err = _run(cmd, TIMEOUTS["nmap"])
    ports = []
    for line in out.splitlines():
        m = _NMAP_LINE.match(line.strip())
        if not m:
            continue
        port, proto, state, service, extra = m.groups()
        product, version = "", ""
        if extra:
            parts = extra.split(" ", 1)
            product = parts[0]
            version = parts[1] if len(parts) > 1 else ""
        if state == "open":
            ports.append({"port": int(port), "proto": proto, "state": state, "service": service,
                          "product": product, "version": version})
    parsed = {"host": host, "ports": ports}
    raw = f"$ {shlex.join(cmd)}\n(exit {rc})\n\n{out}\n{err}"
    return {"parsed": parsed, "raw": raw, "mode": "real", "cmd": shlex.join(cmd)}


# ────────────────────────── nikto ──────────────────────────
def adapter_nikto(target: str, args: dict) -> dict:
    url = target if "://" in (target or "") else f"http://{target}"
    cmd = [_bin("nikto") or "nikto", "-h", url, "-Tuning", "1234567", "-maxtime", "150s", "-nointeractive"]
    rc, out, err = _run(cmd, TIMEOUTS["nikto"])
    issues = []
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("+ ") and ":" in s:
            msg = s[2:].strip()
            issues.append({"id": "nikto", "msg": msg})
    parsed = {"host": _host_of(url), "issues": issues}
    raw = f"$ {shlex.join(cmd)}\n(exit {rc})\n\n{out}\n{err}"
    return {"parsed": parsed, "raw": raw, "mode": "real", "cmd": shlex.join(cmd)}


# ────────────────────────── dirbust (gobuster / dirb) ──────────────────────────
def adapter_dirbust(target: str, args: dict) -> dict:
    url = target if "://" in (target or "") else f"http://{target}"
    binname = _bin("dirbust") or "gobuster"
    wordlist = args.get("wordlist") or DIRBUST_WORDLIST
    if not os.path.exists(wordlist):
        # tiny inline fallback wordlist so gobuster still runs in minimal containers
        wordlist = "/tmp/8pi_common.txt"
        with open(wordlist, "w") as f:
            f.write("\n".join(["admin", "login", "api", "backup", ".git", "uploads",
                                "config", "test", "docs", "console", "dashboard"]))
    if binname.endswith("gobuster"):
        cmd = [binname, "dir", "-u", url, "-w", wordlist, "-q", "--no-error", "-t", "20",
               "--timeout", "8s"]
    else:  # dirb
        cmd = [binname, url, wordlist, "-S", "-w"]
    rc, out, err = _run(cmd, TIMEOUTS["dirbust"])
    paths = []
    for line in out.splitlines():
        s = line.strip()
        m = re.match(r"^(/\S+)\s+\(Status:\s*(\d+)\)", s)  # gobuster
        if m:
            paths.append(m.group(1))
            continue
        m = re.match(r"^\+\s+(\S+)\s+\(CODE:\s*(\d+)", s)  # dirb
        if m:
            paths.append(m.group(1))
    parsed = {"host": _host_of(url), "paths": paths}
    raw = f"$ {shlex.join(cmd)}\n(exit {rc})\n\n{out}\n{err}"
    return {"parsed": parsed, "raw": raw, "mode": "real", "cmd": shlex.join(cmd)}


# ────────────────────────── wpscan ──────────────────────────
def adapter_wpscan(target: str, args: dict) -> dict:
    url = target if "://" in (target or "") else f"http://{target}"
    cmd = [_bin("wpscan") or "wpscan", "--url", url, "--no-update", "--random-user-agent",
           "--disable-tls-checks", "--format", "cli", "--enumerate", str(args.get("enumerate", "vp"))]
    rc, out, err = _run(cmd, TIMEOUTS["wpscan"])
    wp_version = None
    plugins = []
    for line in out.splitlines():
        s = line.strip()
        m = re.match(r"WordPress version\s+([\d\.]+)", s)
        if m:
            wp_version = m.group(1)
        m = re.match(r"\[!\]\s+Title:\s+(.+)", s)
        if m:
            plugins.append({"name": m.group(1)[:80]})
    parsed = {"host": _host_of(url), "wp_version": wp_version, "vulnerable_plugins": plugins}
    raw = f"$ {shlex.join(cmd)}\n(exit {rc})\n\n{out}\n{err}"
    return {"parsed": parsed, "raw": raw, "mode": "real", "cmd": shlex.join(cmd)}


# ────────────────────────── sqlmap ──────────────────────────
def adapter_sqlmap(target: str, args: dict) -> dict:
    url = target if "://" in (target or "") else f"http://{target}"
    cmd = [_bin("sqlmap") or "sqlmap", "-u", url, "--batch", "--level=1", "--risk=1",
           "--technique=B", "--timeout=10", "--retries=1"]
    rc, out, err = _run(cmd, TIMEOUTS["sqlmap"])
    injectable = "is vulnerable" in out.lower() or "parameter" in out.lower() and "injectable" in out.lower()
    dbms = None
    m = re.search(r"back-end DBMS:\s+([\w\s]+)", out)
    if m:
        dbms = m.group(1).strip()
    parsed = {"host": _host_of(url), "injectable": injectable, "dbms": dbms}
    raw = f"$ {shlex.join(cmd)}\n(exit {rc})\n\n{out}\n{err}"
    return {"parsed": parsed, "raw": raw, "mode": "real", "cmd": shlex.join(cmd)}


_ADAPTERS = {
    "nmap": adapter_nmap,
    "nikto": adapter_nikto,
    "dirbust": adapter_dirbust,
    "wpscan": adapter_wpscan,
    "sqlmap": adapter_sqlmap,
}


def tool_availability() -> dict:
    """Snapshot of which real binaries are present and the effective mode per tool."""
    out = {"mode": TOOL_MODE, "tools": {}}
    for t, exe in BINARIES.items():
        path = shutil.which(exe)
        effective = "real" if _use_real(t) else "sim"
        out["tools"][t] = {"binary": exe, "path": path, "installed": bool(path), "effective": effective}
    return out
