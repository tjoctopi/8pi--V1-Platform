# Ground-Truth Cyber Range

Known-vulnerable targets with **planted** bugs — the precision/recall yardstick
and the safe sandbox the engine is measured against (spec §7).

| Host | IP | What it is |
|------|----|-----------|
| `ae-juice-shop` | `10.5.0.10:3000` | OWASP Juice Shop (web / OWASP Top 10) |
| `ae-dvwa` | `10.5.0.11:80` | DVWA (SQLi, XSS, cmd-injection, upload) |
| `ae-metasploitable` | `10.5.0.12` | Metasploitable 2 (network services) |

All three sit on the isolated `10.5.0.0/24` bridge network, so an engagement
scope maps directly:

```yaml
allowed_cidrs: ["10.5.0.0/24"]
```

## Usage

```bash
attack-engine range up       # docker compose up -d
attack-engine range status
attack-engine range down     # tear down + remove volumes
```

## ⚠️ Safety

This range is **intentionally vulnerable**. Ports are bound to `127.0.0.1` only.
Never expose it to an untrusted network, and only run it on a host you control.
