"""C-03 simulated tool adapters + registry. Deterministic per-target output (no real network)."""
import hashlib

TOOL_REGISTRY = [
    {"tool_id": "nmap", "name": "Nmap", "class": "oss", "min_intensity": "recon",
     "license_verified": True, "category": "recon",
     "description": "Network host / service / version discovery.",
     "params": {"ports": "top-1000", "service_detection": True}},
    {"tool_id": "nikto", "name": "Nikto", "class": "oss", "min_intensity": "safe-active",
     "license_verified": True, "category": "web",
     "description": "Web server misconfiguration & known-issue scanner.",
     "params": {"tuning": "default"}},
    {"tool_id": "dirbust", "name": "ffuf / gobuster", "class": "oss", "min_intensity": "safe-active",
     "license_verified": True, "category": "web",
     "description": "Content / directory brute-forcing.",
     "params": {"wordlist": "common.txt"}},
    {"tool_id": "wpscan", "name": "WPScan", "class": "oss", "min_intensity": "safe-active",
     "license_verified": True, "category": "web",
     "description": "WordPress version & plugin vulnerability scanner.",
     "params": {"enumerate": "vp"}},
    {"tool_id": "sqlmap", "name": "SQLMap", "class": "oss", "min_intensity": "exploit",
     "license_verified": True, "category": "exploit",
     "description": "Automated SQL injection detection & exploitation.",
     "params": {"level": 1, "risk": 1}},
    {"tool_id": "burp", "name": "Burp Suite Pro", "class": "licensed", "min_intensity": "safe-active",
     "license_verified": False, "category": "web",
     "description": "Licensed. Forward hook only (RISK-04) — not wired into autonomous pipeline in v1.",
     "params": {}},
    {"tool_id": "nessus", "name": "Nessus", "class": "licensed", "min_intensity": "safe-active",
     "license_verified": False, "category": "vuln",
     "description": "Licensed. Forward hook only (RISK-04) — not wired into autonomous pipeline in v1.",
     "params": {}},
]

TOOL_BY_ID = {t["tool_id"]: t for t in TOOL_REGISTRY}

# port -> (service, product, version) catalog; versions chosen to correlate with the CVE cache
_CATALOG = [
    (22, "ssh", "OpenSSH", "7.4"),
    (80, "http", "Apache httpd", "2.4.49"),
    (443, "https", "nginx", "1.18.0"),
    (21, "ftp", "vsftpd", "2.3.4"),
    (3306, "mysql", "MySQL", "5.7.29"),
    (8080, "http-proxy", "Apache Tomcat", "9.0.30"),
    (25, "smtp", "Postfix", "3.4.13"),
    (445, "microsoft-ds", "Samba", "4.9.5"),
]


def _seed(target):
    return int(hashlib.sha256((target or "x").encode()).hexdigest(), 16)


def _pick_ports(target):
    seed = _seed(target)
    chosen = [c for i, c in enumerate(_CATALOG) if (seed >> i) & 1]
    if len(chosen) < 3:
        chosen = _CATALOG[:3]
    # web targets always expose an http server
    if "://" in (target or "") or (target or "").startswith("www") or "web" in (target or ""):
        if not any(p in (80, 443, 8080) for p, *_ in chosen):
            chosen.append(_CATALOG[1])
    return chosen


def run_sim_tool(tool_id, target, args=None):
    args = args or {}
    if tool_id == "nmap":
        return _sim_nmap(target)
    if tool_id == "nikto":
        return _sim_nikto(target)
    if tool_id == "dirbust":
        return _sim_dirbust(target)
    if tool_id == "wpscan":
        return _sim_wpscan(target)
    if tool_id == "sqlmap":
        return _sim_sqlmap(target)
    return {"parsed": {}, "raw": f"[sim] no adapter for tool '{tool_id}'"}


def _sim_nmap(target):
    ports = _pick_ports(target)
    parsed_ports = [
        {"port": p, "proto": "tcp", "state": "open", "service": svc, "product": prod, "version": ver}
        for (p, svc, prod, ver) in ports
    ]
    raw = [f"Starting Nmap scan against {target}", "Host is up (0.0089s latency).",
           "PORT     STATE SERVICE     VERSION"]
    for pp in parsed_ports:
        raw.append(f"{pp['port']}/tcp open  {pp['service']:<11} {pp['product']} {pp['version']}")
    raw.append(f"Nmap done: 1 host scanned, {len(parsed_ports)} open ports.")
    return {"parsed": {"host": target, "ports": parsed_ports}, "raw": "\n".join(raw)}


def _sim_nikto(target):
    findings = [
        {"id": "OSVDB-3092", "msg": "/admin/: Admin login page found."},
        {"id": "hdr", "msg": "X-Frame-Options header not present."},
        {"id": "srv", "msg": "Server banner leaks version information."},
    ]
    raw = "\n".join([f"+ {f['msg']}" for f in findings])
    return {"parsed": {"host": target, "issues": findings}, "raw": f"- Nikto v2.5 target {target}\n{raw}"}


def _sim_dirbust(target):
    paths = ["/admin", "/login", "/api", "/backup", "/.git", "/uploads"]
    seed = _seed(target)
    found = [p for i, p in enumerate(paths) if (seed >> (i + 3)) & 1] or ["/admin", "/login"]
    raw = "\n".join([f"200  GET  {target}{p}" for p in found])
    return {"parsed": {"host": target, "paths": found}, "raw": raw}


def _sim_wpscan(target):
    return {"parsed": {"host": target, "wp_version": "5.7",
                       "vulnerable_plugins": [{"name": "contact-form", "version": "1.2", "cve": "CVE-2021-34527"}]},
            "raw": f"[+] WordPress 5.7 identified at {target}\n[!] contact-form 1.2 is vulnerable"}


def _sim_sqlmap(target):
    return {"parsed": {"host": target, "injectable": True, "param": "id", "dbms": "MySQL",
                       "technique": "boolean-based blind"},
            "raw": f"[*] target {target}\n[+] parameter 'id' is injectable (boolean-based blind, MySQL)"}
