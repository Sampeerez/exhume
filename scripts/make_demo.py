#!/usr/bin/env python3
"""Regenerate docs/demo.gif from a REAL Exhume run over a synthetic share.

    python scripts/make_demo.py            # needs: Pillow, ffmpeg, and the local AI model (first run downloads it)

Everything shown is produced by the tool itself; only the fake data below is made up. The
sample secrets are assembled at runtime so that no real-looking token literal lives in this repo.
"""
from __future__ import annotations

import os
import pty
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "demo.gif"
COLS, ROWS = 104, 36
FONT = "/System/Library/Fonts/Menlo.ttc"
FONT_SIZE, LINE_H, PAD_X, PAD_Y, TOP = 15, 21, 22, 14, 38

PALETTE = {30: "#484f58", 31: "#ff7b72", 32: "#3fb950", 33: "#e3b341", 34: "#58a6ff", 35: "#bc8cff",
           36: "#39c5cf", 37: "#e6edf3", 90: "#8b949e", 91: "#ff7b72", 92: "#56d364", 93: "#e3b341"}
BG, FG = "#0d1117", "#c9d1d9"


def make_share(base: Path) -> Path:
    share = base / "share"
    (share / "finance").mkdir(parents=True)
    (share / "it" / "backups").mkdir(parents=True)
    (share / "docs").mkdir()
    (share / "finance" / "Thumbs.db").write_bytes(b"\x00" * 64)
    (share / "it" / "deploy.env").write_text(
        "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=" + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY\n"
        "GITHUB_TOKEN=" + "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8\n"
        "db_password = 'Sup3rS3cret!2024'\n")
    (share / "it" / "network.txt").write_text(
        "servidor SQL 10.20.30.40 puerto 1433\n"
        "Manual de seguridad\n3.2.2.1 Seguridad en el almacén\nFirmware 2.7.5.4 instalado\n")
    (share / "finance" / "pagos.txt").write_text(
        "Transferir a IBAN ES91 2100 0418 4502 0005 1332\n"
        "TOTAL 62.412499999999994\n"
        "Titular: Maria Lopez, NIF 12345678Z\n"
        "Tarjeta Visa 4539 1488 0343 6467 caduca 12/27\n")
    (share / "docs" / "README.txt").write_text("Nothing to see here.\n")
    return share


def capture(share: Path, out_prefix: Path) -> str:
    cmd = [sys.executable, "-m", "exhume", str(share), "--no-open", "--no-verify", "--no-html", "--no-csv",
           "-o", str(out_prefix)]
    chunks: list[bytes] = []

    def read(fd):
        data = os.read(fd, 65536)
        chunks.append(data)
        return data

    # Fresh AI home so the demo shows real model calls, not remembered verdicts (models are shared by symlink).
    from exhume.ai_filter import home_dir
    demo_home = out_prefix.parent / "exhume_home"
    demo_home.mkdir(exist_ok=True)
    if (home_dir() / "models").exists() and not (demo_home / "models").exists():
        (demo_home / "models").symlink_to(home_dir() / "models")
    env = dict(os.environ, TERM="xterm-256color", PYTHONWARNINGS="ignore", EXHUME_HOME=str(demo_home))
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(ROOT)
        os.execvpe(cmd[0], cmd, env)
    while True:
        try:
            if not read(fd):
                break
        except OSError:
            break
    os.waitpid(pid, 0)
    text = b"".join(chunks).decode("utf-8", "replace").replace("\r\n", "\n")
    return text.replace(str(share), "/srv/share")


def clean(text: str) -> list[str]:
    lines = []
    for raw in text.split("\n"):
        if "\r" in raw:                      # progress redraws: keep only the final state
            raw = raw.split("\r")[-1]
        plain = re.sub(r"\x1b\[[0-9;]*m", "", raw).strip()
        if not plain or plain.startswith(("Preparing", "Multiprocessing")) or re.fullmatch(r"\d+/\d+\.*", plain):
            continue
        if re.search(r"AI judged \d+", plain) or "Live verification" in plain:
            continue
        lines.append(raw.rstrip())
    return lines


def wrap(line: str) -> list[str]:
    """Hard-wrap on visible width, keeping ANSI sequences intact."""
    out, cur, vis = [], "", 0
    for tok in re.split(r"(\x1b\[[0-9;]*m)", line):
        if tok.startswith("\x1b["):
            cur += tok
            continue
        for ch in tok:
            if vis >= COLS:
                out.append(cur)
                cur, vis = "", 0
            cur += ch
            vis += 1
    out.append(cur)
    return out


def draw_line(d: ImageDraw.ImageDraw, font, y: int, text: str) -> None:
    x, color, bold = PAD_X, FG, False
    char_w = font.getlength("M")
    for tok in re.split(r"(\x1b\[[0-9;]*m)", text):
        if tok.startswith("\x1b["):
            for code in (int(c or 0) for c in tok[2:-1].split(";")):
                if code == 0:
                    color, bold = FG, False
                elif code == 1:
                    bold = True
                elif code == 2:
                    color = "#6e7681"
                elif code in PALETTE:
                    color = PALETTE[code]
            continue
        d.text((x, y), tok, font=font, fill=color)
        if bold:
            d.text((x + 0.6, y), tok, font=font, fill=color)
        x += char_w * len(tok)


def frame(lines: list[str], font, cursor: bool = False) -> Image.Image:
    w = int(PAD_X * 2 + font.getlength("M") * COLS)
    h = TOP + PAD_Y + LINE_H * ROWS
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 30], fill="#161b22")
    for i, c in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        d.ellipse([16 + i * 22, 9, 28 + i * 22, 21], fill=c)
    d.text((w // 2 - 60, 7), "exhume — audit demo", font=font, fill="#8b949e")
    visible = lines[-ROWS:]
    for i, ln in enumerate(visible):
        draw_line(d, font, TOP + i * LINE_H, ln)
    if cursor:
        cx = PAD_X + font.getlength("M") * (len(re.sub(r"\x1b\[[0-9;]*m", "", visible[-1])) if visible else 0)
        d.rectangle([cx, TOP + (len(visible) - 1) * LINE_H + 2, cx + 9, TOP + (len(visible) - 1) * LINE_H + LINE_H - 2],
                    fill="#c9d1d9")
    return img


def main() -> int:
    if not shutil.which("ffmpeg"):
        print("ffmpeg is required", file=sys.stderr)
        return 1
    font = ImageFont.truetype(FONT, FONT_SIZE)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = Path(tmp)
        share = make_share(tmp_p)
        print("running exhume on the demo share (the first run downloads the AI model)...")
        out = capture(share, tmp_p / "report")
        body: list[str] = []
        for ln in clean(out):
            body.extend(wrap(ln))
        prompt = "\x1b[32m❯\x1b[0m "
        cmd = "exhume /srv/share"
        frames: list[tuple[Image.Image, float]] = []
        for i in range(len(cmd) + 1):
            frames.append((frame([prompt + cmd[:i]], font, cursor=True), 0.07))
        frames.append((frame([prompt + cmd], font), 0.5))
        shown = [prompt + cmd, ""]
        batch = 0
        for ln in body:
            shown.append(ln)
            batch += 1
            slow = ("Local AI" in ln) or ("AI (" in ln) or ln.startswith("\x1b[35m")
            if slow:
                frames.append((frame(shown, font), 0.8))
                batch = 0
            elif batch == 3:
                frames.append((frame(shown, font), 0.16))
                batch = 0
        frames.append((frame(shown, font), 0.16))
        frames.append((frame(shown, font), 4.0))
        listing = tmp_p / "frames.txt"
        with open(listing, "w") as fh:
            for n, (img, dur) in enumerate(frames):
                p = tmp_p / f"f{n:04d}.png"
                img.save(p, optimize=True)
                fh.write(f"file '{p}'\nduration {dur}\n")
            fh.write(f"file '{tmp_p / f'f{len(frames) - 1:04d}.png'}'\n")
        OUT.parent.mkdir(exist_ok=True)
        subprocess.run(
            ["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listing),
             "-vf", "split[a][b];[a]palettegen=max_colors=48:stats_mode=diff[p];"
                    "[b][p]paletteuse=dither=none:diff_mode=rectangle",
             "-loop", "0", str(OUT)], check=True)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
