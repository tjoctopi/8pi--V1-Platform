"""EPSS + exploit-maturity ingest and config-driven feed selection (B3)."""

from __future__ import annotations

import json

from attack_engine.config import Settings
from attack_engine.correlate.feeds import LocalCveFeed
from attack_engine.correlate.nvd import (
    build_feed,
    build_feed_from_files,
    parse_epss,
    parse_exploit_ids,
)
from attack_engine.engine import build_cve_feed
from tests.correlate.test_nvd_ingest import KEV_DOC, NVD_DOC

EPSS_CSV = (
    "#model_version:v2023.03.01,score_date:2024-06-01T00:00:00Z\n"
    "cve,epss,percentile\n"
    "CVE-2021-41773,0.97430,0.99958\n"
    "CVE-2022-0001,0.00210,0.58000\n"
    "\n"  # trailing blank line
)

EXPLOIT_IDS = "# known public exploits\nCVE-2022-0001\n"


# --- parsers --------------------------------------------------------------------


def test_parse_epss_skips_comment_and_header() -> None:
    scores = parse_epss(EPSS_CSV)
    assert scores == {"CVE-2021-41773": 0.9743, "CVE-2022-0001": 0.0021}


def test_parse_epss_tolerates_malformed_rows() -> None:
    assert parse_epss("cve,epss\nGARBAGE\nCVE-1,notafloat\nCVE-2,0.5") == {"CVE-2": 0.5}


def test_parse_exploit_ids_ignores_comments_and_blanks() -> None:
    assert parse_exploit_ids(EXPLOIT_IDS) == {"CVE-2022-0001"}


# --- build_feed with EPSS + exploit-maturity ------------------------------------


def test_build_feed_attaches_epss_and_public_exploit() -> None:
    feed = build_feed(
        NVD_DOC, KEV_DOC,
        epss=parse_epss(EPSS_CSV),
        exploit_ids={"CVE-2022-0001"},
    )
    widget = feed.match("widget", "1.4.1")[0]  # CVE-2022-0001
    assert widget.kev is False  # not on KEV...
    assert widget.has_public_exploit is True  # ...but has a known public exploit
    assert widget.epss == 0.0021

    apache = feed.match("apache http server", "2.4.49")[0]  # CVE-2021-41773
    assert apache.kev and apache.has_public_exploit  # KEV ⇒ exploited
    assert apache.epss == 0.9743


def test_build_feed_from_files_with_epss_and_exploits(tmp_path) -> None:
    (tmp_path / "nvd.json").write_text(json.dumps(NVD_DOC))
    (tmp_path / "kev.json").write_text(json.dumps(KEV_DOC))
    (tmp_path / "epss.csv").write_text(EPSS_CSV)
    (tmp_path / "exploits.txt").write_text(EXPLOIT_IDS)
    feed = build_feed_from_files(
        tmp_path / "nvd.json", tmp_path / "kev.json",
        epss_path=tmp_path / "epss.csv",
        exploit_ids_path=tmp_path / "exploits.txt",
    )
    assert feed.match("widget", "1.4.1")[0].epss == 0.0021
    assert feed.match("widget", "1.4.1")[0].has_public_exploit is True


# --- engine feed selection ------------------------------------------------------


def test_build_cve_feed_uses_files_when_configured(tmp_path) -> None:
    (tmp_path / "nvd.json").write_text(json.dumps(NVD_DOC))
    (tmp_path / "kev.json").write_text(json.dumps(KEV_DOC))
    settings = Settings(
        cve_nvd_path=str(tmp_path / "nvd.json"),
        cve_kev_path=str(tmp_path / "kev.json"),
        _env_file=None,
    )
    feed = build_cve_feed(settings)
    # 'widget' exists only in the file feed, never in the bundled seed.
    assert feed.match("widget", "1.4.1")


def test_build_cve_feed_falls_back_to_seed(tmp_path) -> None:
    settings = Settings(_env_file=None)  # no feed files configured
    feed = build_cve_feed(settings)
    assert feed.match("widget", "1.4.1") == []  # not in the seed
    # the seed still carries its bundled Apache traversal CVE
    assert feed.is_kev("CVE-2021-41773") or feed.match("apache http server", "2.4.49")


# --- the bundled offline feed covers the exploitable range services (#4) --------


def _seed_feed() -> LocalCveFeed:
    return LocalCveFeed.from_json()


def test_offline_feed_correlates_range_service_cves() -> None:
    # The classically-exploitable services on the range (the ones the network-
    # exploit foothold path scans) must correlate to a CVE from the bundled feed
    # WITHOUT any network — so the Vulnerability & Patch Loop lights up offline.
    feed = _seed_feed()
    cases = [
        ("vsftpd", "2.3.4", "CVE-2011-2523"),
        ("samba smbd", "3.0.20", "CVE-2007-2447"),
        ("samba", "4.5.0", "CVE-2017-7494"),
        ("distccd", None, "CVE-2004-2687"),
        ("unrealircd", "3.2.8.1", "CVE-2010-2075"),
    ]
    for product, version, cve_id in cases:
        ids = {r.id for r in feed.match(product, version)}
        assert cve_id in ids, f"{product} {version} should correlate {cve_id}, got {ids}"


def test_offline_feed_does_not_false_positive_on_patched_versions() -> None:
    # Interval matching, not string matching: a patched vsftpd / newer Samba must
    # NOT correlate the backdoor CVEs (the #1 false-positive source).
    feed = _seed_feed()
    assert not feed.match("vsftpd", "3.0.3")  # post-backdoor build
    assert "CVE-2007-2447" not in {r.id for r in feed.match("samba", "4.5.0")}


def test_offline_feed_marks_kev() -> None:
    feed = _seed_feed()
    assert feed.is_kev("CVE-2017-7494")  # SambaCry is on CISA KEV
    assert not feed.is_kev("CVE-2004-2687")  # distcc design flaw is not
