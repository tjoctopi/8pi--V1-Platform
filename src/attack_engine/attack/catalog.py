"""Curated ATT&CK catalog + capability mapping (the engine's real coverage).

Every technique here is mapped to the concrete engine component that performs or
confirms it, with an honest ``available`` / ``planned`` status — so the coverage
matrix reflects what the platform can actually do today, not aspiration. This is
the single source of truth for technique ids used elsewhere (kill-chain planner,
intelligence dossier, adversary profiles).

Capability refs point at real names: registered tool wrappers, exploit module
ids, verification oracle ids, and post-exploitation actions.
"""

from __future__ import annotations

from .technique import (
    CapabilityKind,
    Tactic,
    Technique,
    TechniqueCapability,
    TechniqueLibrary,
)


def _cap(kind: CapabilityKind, ref: str, status: str = "available") -> TechniqueCapability:
    return TechniqueCapability(kind=kind, ref=ref, status=status)


_TOOL = CapabilityKind.TOOL
_MOD = CapabilityKind.EXPLOIT_MODULE
_ORACLE = CapabilityKind.ORACLE
_POSTEX = CapabilityKind.POSTEX
_PLANNED = CapabilityKind.PLANNED

#: The curated technique set with capability mappings. Ordered by tactic.
_CATALOG: tuple[Technique, ...] = (
    # --- Reconnaissance -----------------------------------------------------
    Technique(id="T1595", name="Active Scanning", tactic=Tactic.RECONNAISSANCE,
              description="Probe hosts/services to map the attack surface.",
              capabilities=(_cap(_TOOL, "nmap"), _cap(_TOOL, "masscan"), _cap(_TOOL, "httpx"))),
    Technique(id="T1595.002", name="Vulnerability Scanning", tactic=Tactic.RECONNAISSANCE,
              description="Templated/authenticated vulnerability scanning.",
              capabilities=(_cap(_TOOL, "nuclei"), _cap(_TOOL, "nikto"),
                            _cap(_TOOL, "nessus", "planned"))),
    Technique(id="T1590", name="Gather Victim Network Information", tactic=Tactic.RECONNAISSANCE,
              description="Enumerate subdomains / network surface.",
              capabilities=(_cap(_TOOL, "subfinder"), _cap(_TOOL, "amass"))),
    Technique(id="T1596", name="Search Open Technical Databases", tactic=Tactic.RECONNAISSANCE,
              description="Map known exploits to discovered software.",
              capabilities=(_cap(_TOOL, "searchsploit"),)),
    # --- Discovery ----------------------------------------------------------
    Technique(id="T1046", name="Network Service Discovery", tactic=Tactic.DISCOVERY,
              capabilities=(_cap(_TOOL, "nmap"), _cap(_TOOL, "masscan"))),
    Technique(id="T1083", name="File and Directory Discovery", tactic=Tactic.DISCOVERY,
              description="Content/endpoint discovery + OpenAPI ingestion.",
              capabilities=(_cap(_TOOL, "ffuf"), _cap(_TOOL, "katana"),
                            _cap(_POSTEX, "enumerate"))),
    Technique(id="T1082", name="System Information Discovery", tactic=Tactic.DISCOVERY,
              capabilities=(_cap(_POSTEX, "enumerate"),)),
    Technique(id="T1518", name="Software Discovery", tactic=Tactic.DISCOVERY,
              description="Product/version fingerprinting for CVE correlation.",
              capabilities=(_cap(_TOOL, "httpx"), _cap(_TOOL, "nmap"), _cap(_TOOL, "nuclei"))),
    Technique(id="T1087", name="Account Discovery", tactic=Tactic.DISCOVERY,
              description="Enumerate AD users/computers (BloodHound collection).",
              capabilities=(_cap(_TOOL, "bloodhound"),)),
    Technique(id="T1069", name="Permission Groups Discovery", tactic=Tactic.DISCOVERY,
              description="AD group membership + attack-path graphing.",
              capabilities=(_cap(_TOOL, "bloodhound"),)),
    # --- Initial Access -----------------------------------------------------
    Technique(id="T1190", name="Exploit Public-Facing Application", tactic=Tactic.INITIAL_ACCESS,
              description="SQLi / RCE / traversal exploitation of exposed apps + CVE exploits.",
              capabilities=(_cap(_ORACLE, "sqli_boolean_blind_oracle_v1"),
                            _cap(_MOD, "path_traversal_module_v1"),
                            _cap(_MOD, "metasploit_exploit_v1"),
                            _cap(_TOOL, "sqlmap_confirm"), _cap(_TOOL, "metasploit"))),
    Technique(id="T1078", name="Valid Accounts", tactic=Tactic.INITIAL_ACCESS,
              description="Authenticate with default/weak credentials.",
              capabilities=(_cap(_MOD, "default_credentials_module_v1"),)),
    # --- Execution ----------------------------------------------------------
    Technique(id="T1059", name="Command and Scripting Interpreter", tactic=Tactic.EXECUTION,
              description="OS command execution via injection or a session.",
              capabilities=(_cap(_MOD, "command_injection_module_v1"),
                            _cap(_POSTEX, "run"))),
    Technique(id="T1059.007", name="JavaScript (XSS)", tactic=Tactic.EXECUTION,
              description="Reflected/stored cross-site scripting.",
              capabilities=(_cap(_ORACLE, "reflected_xss_oracle_v1"), _cap(_TOOL, "dalfox"))),
    Technique(id="T1221", name="Template Injection", tactic=Tactic.EXECUTION,
              capabilities=(_cap(_MOD, "ssti_module_v1"),)),
    Technique(id="T1203", name="Exploitation for Client Execution", tactic=Tactic.EXECUTION,
              capabilities=(_cap(_PLANNED, "client-side exploit delivery", "planned"),)),
    # --- Credential Access --------------------------------------------------
    Technique(id="T1552", name="Unsecured Credentials", tactic=Tactic.CREDENTIAL_ACCESS,
              description="Exposed secrets (.env/.git/backups) found during discovery.",
              capabilities=(_cap(_TOOL, "ffuf"), _cap(_TOOL, "nuclei"))),
    Technique(id="T1110", name="Brute Force", tactic=Tactic.CREDENTIAL_ACCESS,
              capabilities=(_cap(_PLANNED, "hydra / credential spraying", "planned"),)),
    Technique(id="T1558.003", name="Kerberoasting", tactic=Tactic.CREDENTIAL_ACCESS,
              description="Request TGS for SPN accounts → crackable hashes.",
              capabilities=(_cap(_TOOL, "kerberoast"),)),
    Technique(id="T1558.004", name="AS-REP Roasting", tactic=Tactic.CREDENTIAL_ACCESS,
              description="Harvest AS-REP hashes for accounts without pre-auth.",
              capabilities=(_cap(_TOOL, "kerberoast"),)),
    Technique(id="T1550.002", name="Pass the Hash", tactic=Tactic.CREDENTIAL_ACCESS,
              capabilities=(_cap(_PLANNED, "PtH via captured NT hashes (O6)", "planned"),)),
    # --- Privilege Escalation ----------------------------------------------
    Technique(id="T1068", name="Exploitation for Privilege Escalation",
              tactic=Tactic.PRIVILEGE_ESCALATION,
              capabilities=(_cap(_PLANNED, "local privesc modules (O5)", "planned"),)),
    # --- Lateral Movement ---------------------------------------------------
    Technique(id="T1210", name="Exploitation of Remote Services", tactic=Tactic.LATERAL_MOVEMENT,
              capabilities=(_cap(_TOOL, "metasploit"), _cap(_MOD, "metasploit_exploit_v1"))),
    Technique(id="T1021", name="Remote Services", tactic=Tactic.LATERAL_MOVEMENT,
              description="Pivot to internal hosts; full session establishment is O5/O6.",
              capabilities=(_cap(_POSTEX, "pivot_recon"),
                            _cap(_PLANNED, "lateral session establishment (O5/O6)", "planned"))),
    # --- Command and Control ------------------------------------------------
    Technique(id="T1071", name="Application Layer Protocol", tactic=Tactic.COMMAND_AND_CONTROL,
              description="C2 session channel to a foothold.",
              capabilities=(_cap(_POSTEX, "session-manager"),
                            _cap(_PLANNED, "persistent C2 server (Sliver/msfrpcd)", "planned"))),
    # --- Collection ---------------------------------------------------------
    Technique(id="T1005", name="Data from Local System", tactic=Tactic.COLLECTION,
              capabilities=(_cap(_PLANNED, "bounded collection via post-ex", "planned"),)),
    # --- Impact (always human-gated; never autonomous) ----------------------
    Technique(id="T1499", name="Endpoint Denial of Service", tactic=Tactic.IMPACT,
              description="High-impact — always gated, never run autonomously.",
              capabilities=(_cap(_PLANNED, "gated impact action", "planned"),)),
    Technique(id="T1486", name="Data Encrypted for Impact", tactic=Tactic.IMPACT,
              description="High-impact — always gated, never run autonomously.",
              capabilities=(_cap(_PLANNED, "gated impact action", "planned"),)),
)


def build_library() -> TechniqueLibrary:
    """Construct the engine's ATT&CK technique library."""

    lib = TechniqueLibrary()
    for technique in _CATALOG:
        lib.register(technique)
    return lib


#: Canonical finding-type-prefix → ATT&CK technique id. The single source used by
#: the kill-chain planner, the intelligence dossier, and reporting.
TECHNIQUE_BY_FINDING_TYPE: tuple[tuple[str, str], ...] = (
    ("sqli", "T1190"),
    ("path-traversal", "T1190"),
    ("lfi", "T1190"),
    ("rce", "T1190"),
    ("command-injection", "T1059"),
    ("cmdi", "T1059"),
    ("ssti", "T1221"),
    ("template-injection", "T1221"),
    ("xss", "T1059.007"),
    ("open-redirect", "T1204.001"),
    ("default-cred", "T1078"),
    ("cve-", "T1190"),
)


def technique_for_finding_type(finding_type: str) -> str:
    """Map a finding type to its ATT&CK technique id (default T1190)."""

    low = finding_type.lower()
    for prefix, technique in TECHNIQUE_BY_FINDING_TYPE:
        if low.startswith(prefix):
            return technique
    return "T1190"
