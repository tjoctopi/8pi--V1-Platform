"""NVD 2.0 + CISA KEV ingest tests (fixture-driven; no network)."""

from __future__ import annotations

from attack_engine.correlate.nvd import build_feed, parse_kev, parse_nvd

# A realistic (trimmed) NVD 2.0 document: CVE-2021-41773, Apache 2.4.49, fixed 2.4.50.
NVD_DOC = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49."},
                    {"lang": "es", "value": "Recorrido de ruta..."},
                ],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-22"}]},
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2022-0001",
                "descriptions": [{"lang": "en", "value": "Range-based example."}],
                "metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 9.1}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "1.0.0",
                                        "versionEndExcluding": "1.4.2",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        },
    ]
}

KEV_DOC = {"vulnerabilities": [{"cveID": "CVE-2021-41773"}, {"cveID": "CVE-2019-9999"}]}


class TestParseNvd:
    def test_extracts_id_cvss_cwe_description(self) -> None:
        records = {r.id: r for r in parse_nvd(NVD_DOC)}
        apache = records["CVE-2021-41773"]
        assert apache.cvss == 7.5
        assert apache.cwe == "CWE-22"
        assert "Apache" in apache.description

    def test_exact_version_cpe_becomes_pinned_interval(self) -> None:
        apache = {r.id: r for r in parse_nvd(NVD_DOC)}["CVE-2021-41773"]
        ap = apache.affected[0]
        assert ap.matches("apache http server", "2.4.49")   # affected
        assert not ap.matches("apache http server", "2.4.50")  # a different version

    def test_range_cpe_maps_to_interval(self) -> None:
        widget = {r.id: r for r in parse_nvd(NVD_DOC)}["CVE-2022-0001"]
        ap = widget.affected[0]
        assert ap.matches("widget", "1.0.0")     # start-including
        assert ap.matches("widget", "1.4.1")     # inside range
        assert not ap.matches("widget", "1.4.2")  # end-excluding (the fix)
        assert not ap.matches("widget", "0.9.0")  # before range

    def test_cpe_aliases_include_vendor_and_product(self) -> None:
        apache = {r.id: r for r in parse_nvd(NVD_DOC)}["CVE-2021-41773"]
        ap = apache.affected[0]
        assert ap.product == "http server"
        assert "apache" in ap.aliases


class TestParseKev:
    def test_returns_cve_id_set(self) -> None:
        assert parse_kev(KEV_DOC) == {"CVE-2021-41773", "CVE-2019-9999"}


class TestBuildFeed:
    def test_marks_kev_and_public_exploit(self) -> None:
        feed = build_feed(NVD_DOC, KEV_DOC)
        assert feed.is_kev("CVE-2021-41773")
        matches = feed.match("apache http server", "2.4.49")
        assert any(m.id == "CVE-2021-41773" and m.kev and m.has_public_exploit
                   for m in matches)

    def test_non_kev_cve_not_flagged(self) -> None:
        feed = build_feed(NVD_DOC, KEV_DOC)
        widget = feed.match("widget", "1.2.0")
        assert widget and widget[0].kev is False

    def test_build_from_files(self, tmp_path) -> None:
        import json

        from attack_engine.correlate.nvd import build_feed_from_files

        nvd = tmp_path / "nvd.json"
        kev = tmp_path / "kev.json"
        nvd.write_text(json.dumps(NVD_DOC))
        kev.write_text(json.dumps(KEV_DOC))
        feed = build_feed_from_files(nvd, kev)
        assert feed.is_kev("CVE-2021-41773")
