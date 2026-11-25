import unittest

from sec_audit import (
    AuditReport,
    TlsInfo,
    compute_grade,
    evaluate_headers,
    normalize_url,
    render_markdown,
)


class TestWebSecurityAuditToolkit(unittest.TestCase):
    def test_normalize_url_adds_https(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com")
        self.assertEqual(normalize_url("http://localhost:8080"), "http://localhost:8080")

    def test_normalize_url_rejects_empty(self):
        with self.assertRaises(ValueError):
            normalize_url("   ")

    def test_compute_grade_bands(self):
        self.assertEqual(compute_grade(95), "A")
        self.assertEqual(compute_grade(80), "B")
        self.assertEqual(compute_grade(65), "C")
        self.assertEqual(compute_grade(45), "D")
        self.assertEqual(compute_grade(20), "F")

    def test_evaluate_headers_perfect_score(self):
        headers = {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
        }
        score, grade, findings, disclosures = evaluate_headers(headers)
        self.assertEqual(score, 100)
        self.assertEqual(grade, "A")
        self.assertEqual(len(findings), 7)
        self.assertEqual(disclosures, {})

    def test_evaluate_headers_penalizes_server_disclosure(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Server": "Apache/2.4.54",
            "X-Powered-By": "PHP/8.1.0",
        }
        score, grade, _, disclosures = evaluate_headers(headers)
        self.assertEqual(score, 25)  # 20 + 15 - 10 penalty
        self.assertEqual(grade, "F")
        self.assertIn("server", disclosures)
        self.assertIn("x-powered-by", disclosures)

    def test_render_markdown_contains_key_sections(self):
        report = AuditReport(
            target_url="https://example.com",
            timestamp_utc="2026-11-25T12:00:00Z",
            status_code=200,
            score=90,
            grade="A",
            tls=TlsInfo(enabled=True, protocol="TLSv1.3", subject="example.com", issuer="Let's Encrypt", days_remaining=60),
        )
        md = render_markdown(report)
        self.assertIn("# Web Security Audit Report", md)
        self.assertIn("90/100 (Grade A)", md)
        self.assertIn("TLSv1.3", md)


if __name__ == "__main__":
    unittest.main()
