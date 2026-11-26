"""Tests for report generation."""
from __future__ import annotations

import json

from exhume.models import FileResult, Finding, ScanStats, Severity, Verified
from exhume.reporting.csv_report import write_csv
from exhume.reporting.html import write_html
from exhume.reporting.json_report import build_payload, human_size, write_json
from exhume.reporting.sarif import write_sarif


def _sample_results():
    f = Finding(detector="AWS Access Key ID", severity=Severity.CRITICAL, line=1,
                redacted="AKIA...MPLE", context="KEY=AKIA...MPLE", path="a.env",
                verified=Verified.LIVE, detail="account 123")
    r = FileResult(path="a.env", name="a.env", ext=".env", size=50,
                   tags=["config", "sensitive_name"], findings=[f])
    return [r]


def _stats():
    return ScanStats(root="/x", seen=1, scanned=1, verified_live=1)


def test_human_size():
    assert human_size(0) == "0.0B"
    assert human_size(1024) == "1.0KB"
    assert human_size(1024 * 1024) == "1.0MB"


def test_build_payload_structure():
    payload = build_payload(_sample_results(), _stats())
    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["verified_live"] == 1
    assert payload["meta"]["tool"] == "exhume"
    assert "secret" not in payload["findings"][0]
    assert payload["findings"][0]["value"] == "AKIA...MPLE"


def test_write_json(tmp_path):
    p = tmp_path / "r.json"
    write_json(build_payload(_sample_results(), _stats()), str(p))
    data = json.loads(p.read_text())
    assert data["findings"][0]["verified"] == "live"


def test_write_csv(tmp_path):
    p = tmp_path / "r.csv"
    write_csv(build_payload(_sample_results(), _stats()), str(p))
    content = p.read_text()
    assert "severity" in content
    assert "LIVE" in content


def test_write_sarif(tmp_path):
    p = tmp_path / "r.sarif"
    write_sarif(build_payload(_sample_results(), _stats()), str(p))
    data = json.loads(p.read_text())
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"][0]["level"] == "error"


def test_print_report_runs(capsys):
    from exhume.config import Config
    from exhume.reporting import print_report
    cfg = Config(verify=True)
    print_report(_sample_results(), _stats(), cfg)
    out = capsys.readouterr().out
    assert "Exhume" in out
    assert "AWS Access Key ID" in out
    assert "LIVE" in out


def test_print_report_only_verified(capsys):
    from exhume.config import Config
    from exhume.reporting import print_report
    results = _sample_results()
    results[0].findings[0].verified = Verified.DEAD
    cfg = Config(verify=True, only_verified=True)
    print_report(results, _stats(), cfg)
    out = capsys.readouterr().out
    assert "No verified findings" in out


def test_write_html_safe_embedding(tmp_path):
    results = _sample_results()
    results[0].findings[0].context = "<script>alert(1)</script>"
    p = tmp_path / "r.html"
    write_html(build_payload(results, _stats()), str(p))
    html = p.read_text()
    # The data is embedded as JSON with </ neutralized, so no tag breakout survives.
    assert "</script>alert" not in html
    assert "<\\/script>" in html


def test_html_shows_real_value_by_default(tmp_path):
    from exhume.models import FileResult, Finding, Severity
    f = Finding(detector="GitHub token", severity=Severity.CRITICAL, line=1,
                redacted="ghp_...cd", context="token=ghp_REALSECRET", path="a.txt",
                secret="ghp_REALSECRET")
    payload = build_payload([FileResult(path="a.txt", name="a.txt", ext=".txt", size=9, findings=[f])],
                            _stats(), mask=False)
    assert payload["findings"][0]["value"] == "ghp_REALSECRET"
    masked = build_payload([FileResult(path="a.txt", name="a.txt", ext=".txt", size=9, findings=[f])],
                           _stats(), mask=True)
    assert masked["findings"][0]["value"] == "ghp_...cd"
    assert "ghp_REALSECRET" not in str(masked)


def test_html_truncates_to_max_and_reports_omitted(tmp_path):
    payload = build_payload(_sample_results(), _stats())
    payload["findings"] = payload["findings"] * 30
    p = tmp_path / "r.html"
    omitted = write_html(payload, str(p), max_findings=10)
    assert omitted == len(payload["findings"]) - 10
    assert "highest-severity unique values" in p.read_text()
    assert write_html(payload, str(p), max_findings=0) == 0


def test_html_has_report_mode_and_dismiss(tmp_path):
    p = tmp_path / "r.html"
    write_html(build_payload(_sample_results(), _stats()), str(p))
    html = p.read_text()
    assert "toggleReport" in html and "setDis" in html and "exhume-dismissed" in html


def test_html_has_report_mode_picking(tmp_path):
    """Report mode lets someone check individual findings and show only that curated
    set (e.g. 2 highs + 1 medium) for a screenshot, independent of the severity/search filters."""
    p = tmp_path / "r.html"
    write_html(build_payload(_sample_results(), _stats()), str(p))
    html = p.read_text()
    assert "pickonly" in html and "exhume-picked" in html and "clearPicks" in html


def test_html_has_sortable_columns_and_responsive_cards(tmp_path):
    p = tmp_path / "r.html"
    write_html(build_payload(_sample_results(), _stats()), str(p))
    html = p.read_text()
    assert "toggleSort" in html and "sortable" in html
    assert "@media (max-width:860px)" in html and "@media (max-width:480px)" in html


def test_html_sticky_table_header_tracks_real_header_height(tmp_path):
    """The table header sticks right below the page <header>, but that header's height isn't
    fixed (a long target path, coverage notes or the AI-engine line can wrap it over several
    lines) — a hardcoded sticky offset left a gap where an already-scrolled-past row peeked
    through, overlapping the SEVERITY/VERIFIED/... column labels (reported bug). The offset
    must track the header's real, live height instead of a constant."""
    p = tmp_path / "r.html"
    write_html(build_payload(_sample_results(), _stats()), str(p))
    html = p.read_text()
    assert "--hdrH" in html and "ResizeObserver" in html
    assert "top:var(--hdrH" in html


def test_html_truncates_location_column_with_ellipsis(tmp_path):
    """A deeply nested path used to wrap the location cell across 2-3 lines, bloating row
    height and making the table noisy — it's now a single truncated line with the full path
    available via a title tooltip and in the expanded detail view."""
    p = tmp_path / "r.html"
    write_html(build_payload(_sample_results(), _stats()), str(p))
    html = p.read_text()
    assert "locpath" in html and "text-overflow:ellipsis" in html


def test_tablewrap_is_not_a_scroll_container(tmp_path):
    """overflow-x:auto on this wrapper would make it its own scroll container, which hijacks
    position:sticky on the th's below — they'd stick to THIS box's edge instead of the page's,
    detaching the header row so it floats mid-table instead of sitting above row one. Location
    and value are truncated instead so the table doesn't need its own horizontal scrollbar."""
    import re
    p = tmp_path / "r.html"
    write_html(build_payload(_sample_results(), _stats()), str(p))
    html = p.read_text()
    m = re.search(r"\.tablewrap\{([^}]*)\}", html)
    assert m and "overflow" not in m.group(1)


def test_ai_triage_bold_markdown_is_rendered_in_html():
    from exhume.reporting.html import _md_to_html
    out = _md_to_html("## Fastest paths to access\n- **AWS Credentials**: rotate immediately.")
    assert "<strong>AWS Credentials</strong>" in out
    assert "**" not in out


def test_html_has_unknown_verified_badge_and_metachips(tmp_path):
    """Some detectors (passwords, generic secrets, phone numbers) have no checksum or host to
    test, so they only ever carry an AI verdict — this used to render as a blank gap next to
    rows that DO have a VALID/invalid badge, which looked like a missing/broken badge rather
    than a fact about that data type. A reported point of confusion ("por que en algunos pone
    valid ai real y en otros ai real??"). Also checks the metadata line was broken up into
    scannable chips instead of one dense wall of pipe-separated text."""
    p = tmp_path / "r.html"
    write_html(build_payload(_sample_results(), _stats()), str(p))
    html = p.read_text()
    assert "v-unknown" in html and "n/a" in html
    assert "metachips" in html and "mchip" in html
    assert "covdetails" in html


def test_detected_assets_title_and_tree_share_one_hideable_wrapper(tmp_path):
    """Report mode hides #assetsec — the old code appended the "Detected assets" <h2> as a
    SEPARATE sibling before the #assetsec tree box, so the title stayed visible with nothing
    under it once the box was hidden (reported bug: "sigue saliendo el titulo de Detected
    assets" in report mode). Both the title and the tree must now live inside one element
    carrying that id, so hiding it hides the whole section including its heading."""
    p = tmp_path / "r.html"
    write_html(build_payload(_sample_results(), _stats()), str(p))
    html = p.read_text()
    assert "wrap.id='assetsec'" in html
    assert "ex.appendChild(h); ex.appendChild(box)" not in html
