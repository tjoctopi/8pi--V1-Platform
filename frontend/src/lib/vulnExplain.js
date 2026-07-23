// Client-friendly explanations for findings.
//
// The engine confirms a finding + captures technical evidence, but does not
// emit a plain-language brief (the `remediation` field is usually null). This
// module turns a finding into a non-technical brief a client can act on:
//   what it is · the loophole (why it's exploitable) · business impact · fix.
//
// It classifies by the finding's MITRE technique + title keywords, and always
// falls back to a generic web-weakness brief so nothing renders empty. If the
// engine ever does provide `remediation`, that takes precedence for the fix.

const CATALOG = {
  sqli: {
    name: "SQL Injection",
    what: "The application builds a database query using text the user supplies, without safely separating the two. An attacker can inject their own database commands.",
    loophole: "An input (URL parameter or form field) is placed directly into a SQL query. Sending crafted values like ' OR '1'='1 changes what the query does.",
    impact: "Read, modify, or delete the entire database — user accounts, passwords, customer data — and in many cases run commands on the server itself.",
    fix: "Use parameterized queries / prepared statements (never string-concatenate user input into SQL). Apply least-privilege DB accounts and input validation.",
  },
  lfi: {
    name: "Local File Inclusion (LFI) / Path Traversal",
    what: "The application decides which file to open based on user input, without restricting it — so the server can be tricked into reading files it should never expose.",
    loophole: "A parameter (e.g. ?page=) is used to build a file path with no allow-list. Supplying a path like ../../../../etc/passwd returns arbitrary server files.",
    impact: "Disclosure of sensitive files — configs, credentials, source code, system files — which frequently becomes the foothold for a fuller compromise.",
    fix: "Never build file paths from user input. Use a fixed allow-list of permitted pages, reject path separators and absolute paths, and disable dynamic file inclusion.",
  },
  xss: {
    name: "Cross-Site Scripting (XSS)",
    what: "The application reflects user-supplied text into a page without neutralizing it, so an attacker's script runs in another user's browser.",
    loophole: "Input is echoed into HTML/JS without output-encoding. A crafted value containing a script executes in the victim's session.",
    impact: "Session/cookie theft, account takeover, credential phishing, and actions performed as the victim (including admins).",
    fix: "Context-aware output encoding of all user data, a strict Content-Security-Policy, and input validation. Use framework auto-escaping.",
  },
  ssti: {
    name: "Server-Side Template Injection (SSTI)",
    what: "User input is evaluated by the server's template engine, letting an attacker inject template code that the server executes.",
    loophole: "Input is concatenated into a server-side template instead of passed as data. Payloads like {{7*7}} evaluate, proving code runs on the server.",
    impact: "Often full remote code execution on the server — read data, pivot internally, take over the host.",
    fix: "Never render user input as a template. Pass user data only as template variables (context), sandbox the engine, and validate input.",
  },
  cmdi: {
    name: "Command Injection / Remote Code Execution",
    what: "The application passes user input into an operating-system command, so an attacker can run their own commands on the server.",
    loophole: "Input is placed into a shell command without safe handling. Adding ; or | plus a command runs it on the host.",
    impact: "Full control of the server — read/modify anything, install backdoors, and pivot to other systems on the network.",
    fix: "Avoid shell calls with user input. Use safe APIs / argument arrays (no shell), strict allow-list validation, and least-privilege service accounts.",
  },
  ssrf: {
    name: "Server-Side Request Forgery (SSRF)",
    what: "The application fetches a URL the user controls, so an attacker can make the server request internal systems it shouldn't reach.",
    loophole: "A user-supplied URL is fetched server-side without restriction — pointing it at internal addresses (or the cloud metadata endpoint 169.254.169.254) reaches protected resources.",
    impact: "Access to internal-only services and, on cloud hosts, theft of cloud credentials from the metadata service — a common route to full cloud compromise.",
    fix: "Allow-list permitted destinations, block internal/link-local ranges and the metadata IP, and require IMDSv2. Don't let user input choose the fetch target.",
  },
  authbypass: {
    name: "Broken Access Control / Authentication Bypass",
    what: "Protected pages or actions can be reached without the proper permission — the app checks who you are, but not what you're allowed to do.",
    loophole: "An endpoint or object is accessible by changing an ID or visiting a URL directly, with no server-side authorization check.",
    impact: "Access to other users' data or admin functions, privilege escalation, and unauthorized changes.",
    fix: "Enforce server-side authorization on every request (deny-by-default), verify object ownership, and never rely on hidden UI as the control.",
  },
  exposure: {
    name: "Information Exposure / Misconfiguration",
    what: "The server reveals information it shouldn't — an exposed service, directory, version, or file — that helps an attacker plan the next step.",
    loophole: "A service/endpoint is reachable and discloses details (software versions, directory listings, an exposed admin panel or .git directory) without needing authentication.",
    impact: "Its own severity depends on what is exposed; it maps the attack surface for an attacker and frequently chains into a more serious weakness.",
    fix: "Remove or lock down exposed services/directories, suppress version banners, require auth on admin/management endpoints, and review the external surface.",
  },
  k8s: {
    name: "Exposed Kubernetes / Container Control Plane",
    what: "A container-orchestration control-plane component (Kubernetes API server, kubelet, or etcd) is reachable over the network.",
    loophole: "A control-plane port (6443 API server, 10250 kubelet, 2379 etcd) answers on the network. If authentication is weak or anonymous access is enabled, an attacker can enumerate or control the cluster; even when hardened, the exposure hands an attacker reconnaissance it should never have.",
    impact: "Ranges from cluster reconnaissance to full takeover — scheduling workloads, reading every secret, and pivoting to all nodes and pods.",
    fix: "Restrict control-plane ports to a trusted network or VPN only, disable anonymous auth, enforce RBAC, and rotate credentials. Never expose 6443 / 10250 / 2379 to untrusted networks.",
  },
  generic: {
    name: "Web Application Weakness",
    what: "The engine confirmed a weakness in how this target handles input or access.",
    loophole: "The target accepts input or a request in a way that deviates from safe behaviour, which an attacker can abuse.",
    impact: "Depending on the weakness, this can lead to data exposure, account compromise, or server access.",
    fix: "Validate and sanitize all input, enforce authorization server-side, keep software patched, and re-test after fixing.",
  },
};

function classify(finding) {
  const t = `${finding.title || ""} ${finding.technique_ref || ""}`.toLowerCase();
  if (/\bsqli|sql inj|sql-i/.test(t)) return "sqli";
  if (/\blfi\b|file inclusion|path travers|directory travers/.test(t)) return "lfi";
  if (/\bxss\b|cross.site|cross site/.test(t)) return "xss";
  if (/\bssti\b|template inj|template injection|t1221/.test(t)) return "ssti";
  if (/command inj|cmd inj|\brce\b|remote code|os command|t1059/.test(t)) return "cmdi";
  if (/\bssrf\b|request forgery|t1190.*ssrf/.test(t)) return "ssrf";
  if (/auth.?bypass|access control|idor|broken access|unauthor|t1078/.test(t)) return "authbypass";
  if (/kubernetes|\bk8s\b|control plane|kubelet|\betcd\b|container orchestrat|docker daemon|docker socket|kube-/.test(t)) return "k8s";
  if (/expos|disclosure|misconfig|directory listing|version|banner|open port|\.git/.test(t)) return "exposure";
  return "generic";
}

/** Return a client-friendly brief for a finding: {kind,name,what,loophole,impact,fix,fixSource}. */
export function explainFinding(finding) {
  const kind = classify(finding);
  const base = CATALOG[kind] || CATALOG.generic;
  // The engine's own remediation wins for the fix line, if present.
  const engineFix = (finding.remediation || "").trim();
  return {
    kind,
    ...base,
    fix: engineFix || base.fix,
    fixSource: engineFix ? "engine" : "guidance",
  };
}

/**
 * A finding the engine ACTIVELY DISPROVED (state REJECTED -> serialized as
 * status "false-positive"). This is the only "false positive" — an unconfirmed
 * finding is unproven, NOT disproved, and must never be labelled discarded.
 */
export function isFalsePositive(finding) {
  return finding.status === "false-positive";
}

/** Engine-CONFIRMED: proven by a deterministic verification oracle (highest confidence). */
export function isConfirmed(finding) {
  return finding.exploitability === "confirmed";
}

/**
 * Reportable to a client. Not a proven false-positive, AND either the engine
 * confirmed/reached it OR it is high-impact enough to warrant attention while
 * still unconfirmed (e.g. an exposed control plane). Low-severity unconfirmed
 * candidates stay out of the default view but remain visible under "All".
 *
 * Rationale (engine model PROPOSED -> VERIFIED -> CONFIRMED/REJECTED): only
 * REJECTED is a false positive. "unconfirmed" is unproven, not false — so we
 * surface the serious ones instead of hiding a genuine HIGH (e.g. a recognized
 * but not-yet-exploited Kubernetes control-plane exposure).
 */
export function isReal(finding) {
  if (isFalsePositive(finding)) return false;
  if (finding.exploitability === "confirmed" || finding.exploitability === "reachable") return true;
  return finding.severity === "crit" || finding.severity === "high";
}

/** Unproven but not disproved — still being tested. Excluded from the default view. */
export function isUnconfirmedCandidate(finding) {
  return !isFalsePositive(finding) && !isReal(finding);
}
