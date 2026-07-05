"""SEC-02 / SEC-03 scope + intensity enforcement, evaluated server-side."""
import ipaddress
from urllib.parse import urlparse
from datetime import datetime, timezone

INTENSITY = {"recon": 0, "safe-active": 1, "exploit": 2}


def intensity_level(x):
    return INTENSITY.get(x, 0)


def _looks_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _is_cidr(s):
    return "/" in s and _looks_ip(s.split("/")[0])


def host_of(target):
    t = (target or "").strip()
    if "://" in t:
        return (urlparse(t).hostname or t)
    if "/" in t and not _is_cidr(t):
        return t.split("/")[0]
    return t


def _parse_dt(v):
    d = datetime.fromisoformat(v)
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def match_entry(target, entry):
    entry = (entry or "").strip()
    if not entry:
        return False
    host = host_of(target)
    # CIDR range
    if _is_cidr(entry):
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return _looks_ip(host) and ipaddress.ip_address(host) in net
        except Exception:
            return False
    ehost = host_of(entry)
    if host == ehost:
        return True
    if ehost.startswith("*."):
        return host.endswith(ehost[1:])
    if host.endswith("." + ehost):
        return True
    if (target or "").strip() == entry:
        return True
    return False


def scope_check(roe, target, tool_id=None, intensity="recon", now=None):
    """Deny-by-default scope evaluation. Returns {allow, reason}."""
    if not roe:
        return {"allow": False, "reason": "no_roe_bound"}
    if not roe.get("signature"):
        return {"allow": False, "reason": "roe_not_signed"}
    now = now or datetime.now(timezone.utc)
    ws, we = roe.get("window_start"), roe.get("window_end")
    try:
        if ws and _parse_dt(ws) > now:
            return {"allow": False, "reason": "before_roe_window"}
        if we and _parse_dt(we) < now:
            return {"allow": False, "reason": "roe_window_expired"}
    except Exception:
        pass
    for e in roe.get("scope_denylist", []) or []:
        if match_entry(target, e):
            return {"allow": False, "reason": f"target_in_denylist:{e}"}
    allowlist = roe.get("scope_allowlist", []) or []
    if not any(match_entry(target, e) for e in allowlist):
        return {"allow": False, "reason": "target_out_of_scope"}
    if tool_id and tool_id not in (roe.get("allowed_tools", []) or []):
        return {"allow": False, "reason": f"tool_not_permitted:{tool_id}"}
    if intensity_level(intensity) > intensity_level(roe.get("max_intensity", "recon")):
        return {"allow": False, "reason": f"exceeds_max_intensity:{intensity}>{roe.get('max_intensity')}"}
    return {"allow": True, "reason": "in_scope"}
