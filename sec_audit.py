#!/usr/bin/env python3
"""
Web Security Audit Toolkit (Defensive Auditing CLI)
---------------------------------------------------
Zero-dependency Python 3 utility for authorized web security header analysis,
SSL/TLS certificate inspection, information disclosure detection, and report export.

Author: Issam Derai (https://github.com/issamxx)
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

SECURITY_HEADERS: Dict[str, Tuple[int, str]] = {
    "strict-transport-security": (20, "Enforces HTTPS connections (HSTS)."),
    "content-security-policy": (25, "Mitigates XSS and data injection attacks (CSP)."),
    "x-frame-options": (15, "Prevents clickjacking via iframe embedding."),
    "x-content-type-options": (15, "Prevents MIME-type sniffing (nosniff)."),
    "referrer-policy": (10, "Controls referrer information sent across origins."),
    "permissions-policy": (10, "Restricts sensitive browser features (camera, mic, geo)."),
    "cross-origin-opener-policy": (5, "Isolates browsing context against cross-origin leaks."),
}

DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")


@dataclass
class HeaderFinding:
    header: str
    present: bool
    value: Optional[str]
    weight: int
    recommendation: str


@dataclass
class TlsInfo:
    enabled: bool
    protocol: Optional[str] = None
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_after: Optional[str] = None
    days_remaining: Optional[int] = None
    error: Optional[str] = None


@dataclass
class AuditReport:
    target_url: str
    timestamp_utc: str
    status_code: Optional[int]
    score: int
    grade: str
    headers: List[HeaderFinding] = field(default_factory=list)
    disclosure_warnings: Dict[str, str] = field(default_factory=dict)
    tls: Optional[TlsInfo] = None
    open_ports: List[int] = field(default_factory=list)
    error: Optional[str] = None


def normalize_url(raw_url: str) -> str:
    """Ensure the target URL includes an explicit HTTP(S) scheme."""
    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("Target URL cannot be empty.")
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    parsed = urllib.parse.urlparse(cleaned)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {raw_url}")
    return cleaned


def compute_grade(score: int) -> str:
    """Map a 0-100 security score to a letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def evaluate_headers(response_headers: Dict[str, str]) -> Tuple[int, str, List[HeaderFinding], Dict[str, str]]:
    """Score HTTP response headers and flag server fingerprinting leaks."""
    lower_headers = {k.lower(): v for k, v in response_headers.items()}
    findings: List[HeaderFinding] = []
    score = 0

    for header, (weight, description) in SECURITY_HEADERS.items():
        val = lower_headers.get(header)
        present = bool(val)
        if present:
            score += weight
        findings.append(
            HeaderFinding(
                header=header,
                present=present,
                value=val,
                weight=weight,
                recommendation=description,
            )
        )

    disclosures = {
        h: lower_headers[h]
        for h in DISCLOSURE_HEADERS
        if h in lower_headers and lower_headers[h].strip()
    }
    if disclosures:
        score = max(0, score - min(10, 5 * len(disclosures)))

    return score, compute_grade(score), findings, disclosures


def inspect_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> TlsInfo:
    """Inspect TLS protocol version and certificate expiration for a host."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                subject = dict(x[0] for x in cert.get("subject", ())).get("commonName")
                issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName")
                not_after_raw = cert.get("notAfter")
                days_remaining: Optional[int] = None
                if not_after_raw:
                    expiry = dt.datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=dt.timezone.utc
                    )
                    days_remaining = (expiry - dt.datetime.now(dt.timezone.utc)).days
                return TlsInfo(
                    enabled=True,
                    protocol=protocol,
                    subject=subject,
                    issuer=issuer,
                    not_after=not_after_raw,
                    days_remaining=days_remaining,
                )
    except Exception as exc:  # noqa: BLE001
        return TlsInfo(enabled=False, error=str(exc))


def check_ports(hostname: str, ports: List[int], timeout: float = 1.0) -> List[int]:
    """Check whether specific TCP ports accept connections (authorized targets only)."""
    open_ports: List[int] = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((hostname, port)) == 0:
                open_ports.append(port)
    return open_ports


def run_audit(url: str, timeout: float = 8.0, ports: Optional[List[int]] = None) -> AuditReport:
    """Run a complete defensive audit against an authorized HTTP(S) target."""
    normalized = normalize_url(url)
    parsed = urllib.parse.urlparse(normalized)
    hostname = parsed.hostname or ""
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    req = urllib.request.Request(
        normalized,
        headers={"User-Agent": "WebSecurityAuditToolkit/1.0 (+https://github.com/issamxx)"},
        method="GET",
    )

    status_code: Optional[int] = None
    raw_headers: Dict[str, str] = {}
    error_msg: Optional[str] = None

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            raw_headers = dict(resp.headers.items())
    except urllib.error.HTTPError as http_err:
        status_code = http_err.code
        raw_headers = dict(http_err.headers.items())
    except Exception as exc:  # noqa: BLE001
        error_msg = str(exc)

    if error_msg:
        return AuditReport(
            target_url=normalized,
            timestamp_utc=timestamp,
            status_code=status_code,
            score=0,
            grade="F",
            error=error_msg,
        )

    score, grade, findings, disclosures = evaluate_headers(raw_headers)
    tls_info = inspect_tls(hostname, parsed.port or 443, timeout=timeout) if parsed.scheme == "https" else TlsInfo(enabled=False)
    open_ports = check_ports(hostname, ports) if ports else []

    return AuditReport(
        target_url=normalized,
        timestamp_utc=timestamp,
        status_code=status_code,
        score=score,
        grade=grade,
        headers=findings,
        disclosure_warnings=disclosures,
        tls=tls_info,
        open_ports=open_ports,
    )


def render_markdown(report: AuditReport) -> str:
    """Render an AuditReport as a clean Markdown summary."""
    lines = [
        f"# Web Security Audit Report — `{report.target_url}`",
        "",
        f"- **Timestamp (UTC):** {report.timestamp_utc}",
        f"- **HTTP Status:** {report.status_code}",
        f"- **Security Score:** **{report.score}/100 (Grade {report.grade})**",
        "",
    ]

    if report.error:
        lines.append(f"> **Error:** {report.error}")
        return "\n".join(lines)

    lines.extend(["## HTTP Security Headers", "", "| Header | Status | Weight | Details |", "|---|---|---:|---|"])
    for item in report.headers:
        status = "✅ Present" if item.present else "❌ Missing"
        detail = f"`{item.value}`" if item.present else item.recommendation
        lines.append(f"| `{item.header}` | {status} | {item.weight} | {detail} |")

    if report.disclosure_warnings:
        lines.extend(["", "## Information Disclosure Warnings", ""])
        for h, v in report.disclosure_warnings.items():
            lines.append(f"- ⚠️ `{h}`: `{v}` — consider hiding or generalizing this header.")

    if report.tls:
        lines.extend(["", "## TLS / SSL Certificate", ""])
        if report.tls.enabled:
            lines.append(f"- **Protocol:** `{report.tls.protocol}`")
            lines.append(f"- **Subject CN:** `{report.tls.subject}`")
            lines.append(f"- **Issuer:** `{report.tls.issuer}`")
            lines.append(f"- **Expires:** `{report.tls.not_after}` ({report.tls.days_remaining} days remaining)")
        else:
            lines.append(f"- **TLS:** Not enabled or error (`{report.tls.error or 'HTTP target'}`)")

    if report.open_ports:
        lines.extend(["", "## Checked Open Ports", "", f"- Open TCP ports: `{', '.join(map(str, report.open_ports))}`"])

    return "\n".join(lines) + "\n"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Defensive Web Security Audit CLI (headers, TLS, and optional port inspection)."
    )
    parser.add_argument("url", help="Authorized target URL (e.g. https://example.com)")
    parser.add_argument("--ports", help="Optional comma-separated TCP ports to check (e.g. 80,443,22)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output report as JSON")
    parser.add_argument("--markdown", action="store_true", help="Output report as Markdown")
    parser.add_argument("--output", help="Optional file path to save the generated report")
    parser.add_argument("--timeout", type=float, default=8.0, help="Network timeout in seconds (default: 8)")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()] if args.ports else None
    report = run_audit(args.url, timeout=args.timeout, ports=ports)

    if args.as_json:
        output_text = json.dumps(asdict(report), indent=2)
    else:
        output_text = render_markdown(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output_text)
        print(f"Report saved to {args.output}")
    else:
        print(output_text)

    return 0 if not report.error else 1


if __name__ == "__main__":
    sys.exit(main())
