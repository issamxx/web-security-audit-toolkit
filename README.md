# Web Security Audit Toolkit

A lightweight, **zero-dependency Python 3 CLI** for defensive web security auditing: evaluates HTTP security headers, detects server version fingerprinting leaks, inspects SSL/TLS certificates, and exports clean **Markdown** or **JSON** reports.

> ⚠️ **Ethical Use Notice:** Use this tool only on websites, servers, and networks that you own or have explicit written authorization to audit.

## Features

- **Weighted HTTP Security Header Scoring (0–100, Grade A–F):** Checks `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy`.
- **Information Disclosure Detection:** Flags exposed `Server`, `X-Powered-By`, `X-AspNet-Version`, and `X-Generator` headers.
- **SSL/TLS Certificate Inspection:** Reports TLS protocol version, Common Name, Issuer, and days remaining until expiration.
- **Optional Port Verification:** Checks specified TCP ports for authorized infrastructure reviews.
- **Report Export:** Output directly to terminal or save as `.md` or `.json`.

## Usage

```bash
# Run a standard Markdown audit report
python sec_audit.py https://example.com

# Export results as JSON to a file
python sec_audit.py https://example.com --json --output audit_report.json

# Include authorized TCP port check
python sec_audit.py https://example.com --ports 80,443 --markdown --output audit_report.md
```

## Run Tests

```bash
python -m unittest discover -v
```

## Author

**Issam Derai** — [LinkedIn](https://www.linkedin.com/in/issam-derai) · [GitHub](https://github.com/issamxx)
