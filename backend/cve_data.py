"""C-09 CVE/KEV cache seed (DM-09). Live-feed use only; NOT model-training data (FR-VULN-07)."""

CVE_FEED = [
    {
        "cve_id": "CVE-2021-41773", "product": "Apache httpd", "versions": ["2.4.49"],
        "patched_version": "2.4.51", "cvss": 9.8, "kev": True, "exploit_known": True,
        "cpe_matches": ["cpe:2.3:a:apache:http_server:2.4.49"],
        "summary": "Path traversal & RCE in Apache HTTP Server 2.4.49.",
        "refs": ["https://httpd.apache.org/security/vulnerabilities_24.html"],
    },
    {
        "cve_id": "CVE-2020-1938", "product": "Apache Tomcat", "versions": ["9.0.30"],
        "patched_version": "9.0.31", "cvss": 9.8, "kev": True, "exploit_known": True,
        "cpe_matches": ["cpe:2.3:a:apache:tomcat:9.0.30"],
        "summary": "Ghostcat AJP file read/inclusion leading to RCE.",
        "refs": ["https://tomcat.apache.org/security-9.html"],
    },
    {
        "cve_id": "CVE-2011-2523", "product": "vsftpd", "versions": ["2.3.4"],
        "patched_version": "3.0.5", "cvss": 9.8, "kev": False, "exploit_known": True,
        "cpe_matches": ["cpe:2.3:a:vsftpd:vsftpd:2.3.4"],
        "summary": "vsftpd 2.3.4 backdoor command execution.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    },
    {
        "cve_id": "CVE-2018-15473", "product": "OpenSSH", "versions": ["7.4"],
        "patched_version": "7.7", "cvss": 5.3, "kev": False, "exploit_known": True,
        "cpe_matches": ["cpe:2.3:a:openbsd:openssh:7.4"],
        "summary": "OpenSSH username enumeration via timing.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
    },
    {
        "cve_id": "CVE-2021-23017", "product": "nginx", "versions": ["1.18.0"],
        "patched_version": "1.21.0", "cvss": 7.7, "kev": False, "exploit_known": False,
        "cpe_matches": ["cpe:2.3:a:nginx:nginx:1.18.0"],
        "summary": "Off-by-one in nginx resolver.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
    },
    {
        "cve_id": "CVE-2021-2154", "product": "MySQL", "versions": ["5.7.29"],
        "patched_version": "5.7.34", "cvss": 4.9, "kev": False, "exploit_known": False,
        "cpe_matches": ["cpe:2.3:a:oracle:mysql:5.7.29"],
        "summary": "MySQL Server DML privilege escalation / DoS.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-2154"],
    },
    {
        "cve_id": "CVE-2021-44142", "product": "Samba", "versions": ["4.9.5"],
        "patched_version": "4.13.17", "cvss": 9.9, "kev": False, "exploit_known": False,
        "cpe_matches": ["cpe:2.3:a:samba:samba:4.9.5"],
        "summary": "Out-of-bounds heap R/W in vfs_fruit module.",
        "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44142"],
    },
    {
        "cve_id": "CVE-2021-34527", "product": "WordPress", "versions": ["5.7"],
        "patched_version": "5.8", "cvss": 8.8, "kev": False, "exploit_known": True,
        "cpe_matches": ["cpe:2.3:a:wordpress:wordpress:5.7"],
        "summary": "Vulnerable plugin path in WordPress 5.7 install.",
        "refs": ["https://wpscan.com/"],
    },
]


def severity_from_cvss(cvss):
    if cvss >= 9.0:
        return "crit"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "med"
    if cvss > 0:
        return "low"
    return "info"


def correlate(product, version):
    out = []
    for c in CVE_FEED:
        if c["product"].lower() == (product or "").lower() and version in c["versions"]:
            out.append(c)
    return out
