#!/usr/bin/env python3
"""Regenerate docs/report-demo.gif: the HTML report, actually clicked through.

    python scripts/make_report_demo.py     # needs: playwright (pip install playwright), ffmpeg,
                                            # the system Google Chrome, and the local AI model

Drives a real browser (Playwright, via the system Chrome — no extra download) against a report
Exhume just generated from a synthetic share, clicking the real controls (severity tabs, a row,
Report mode) so every frame is the actual page responding to actual clicks, not a mock-up.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_demo import make_share  # noqa: E402

OUT = ROOT / "docs" / "report-demo.gif"
VIEWPORT = {"width": 1500, "height": 760}


def build_report(share: Path, out_prefix: Path) -> Path:
    subprocess.run([sys.executable, "-m", "exhume", str(share), "--no-open", "--no-verify",
                    "--no-csv", "-o", str(out_prefix)], cwd=ROOT, check=False,
                   capture_output=True, timeout=300)
    html = out_prefix.with_suffix(".html")
    if not html.exists():
        raise SystemExit(f"report was not generated at {html}")
    return html


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("pip install playwright", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = Path(tmp)
        share = make_share(tmp_p)
        print("scanning the demo share...")
        html = build_report(share, tmp_p / "report")
        frames_dir = tmp_p / "frames"
        frames_dir.mkdir()
        shots: list[tuple[Path, float]] = []

        def shot(page, dur: float) -> None:
            p = frames_dir / f"f{len(shots):03d}.png"
            page.screenshot(path=str(p))
            shots.append((p, dur))

        with sync_playwright() as pw:
            browser = pw.chromium.launch(channel="chrome", headless=True)
            page = browser.new_page(viewport=VIEWPORT, device_scale_factor=2)
            page.goto(f"file://{html}")
            page.wait_for_timeout(300)
            shot(page, 1.4)                                    # full report, all severities

            page.click("#sevseg button[data-sev='3']")
            page.wait_for_timeout(250)
            shot(page, 1.3)                                    # Critical only

            page.click("#sevseg button[data-sev='all']")
            page.wait_for_timeout(200)
            page.click("table tbody tr.row")
            page.wait_for_timeout(250)
            page.locator("tr.detail").scroll_into_view_if_needed()
            page.wait_for_timeout(150)
            shot(page, 1.6)                                    # a finding expanded

            page.click("table tbody tr.row")                   # collapse it again
            page.click("#rmode")
            page.wait_for_timeout(300)
            shot(page, 1.8)                                    # Report mode: censored, clean

            page.click("#rmode")
            page.wait_for_timeout(200)
            page.click("#hideinv")
            page.wait_for_timeout(250)
            shot(page, 1.6)                                    # showing AI/checksum false positives too
            browser.close()

        listing = tmp_p / "frames.txt"
        with open(listing, "w") as fh:
            for p, dur in shots:
                fh.write(f"file '{p}'\nduration {dur}\n")
            fh.write(f"file '{shots[-1][0]}'\n")

        OUT.parent.mkdir(exist_ok=True)
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listing),
             "-vf", "fps=10,split[a][b];[a]palettegen=max_colors=192:stats_mode=diff[p];"
                    "[b][p]paletteuse=dither=bayer:diff_mode=rectangle",
             "-loop", "0", str(OUT)], check=True)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
