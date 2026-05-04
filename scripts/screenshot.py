#!/usr/bin/env python3
"""
Take WireGuide+ screenshots and blur private data.

Usage:
  python3 scripts/screenshot.py

The script:
1. Focuses WireGuide+
2. Captures the window
3. Blurs regions that typically contain private info (IPs, endpoints, keys)
4. Saves to docs/screenshots/

Requires Screen Recording permission for the terminal app.
"""

import subprocess, sys, time, os, re
from pathlib import Path

try:
    from PIL import Image, ImageFilter, ImageDraw
except ImportError:
    sys.exit("pip install Pillow")

DOCS = Path(__file__).parent.parent / "docs" / "screenshots"
DOCS.mkdir(parents=True, exist_ok=True)

# ── helpers ──────────────────────────────────────────────────────────────────

def focus_app():
    subprocess.run(["open", "-a", "WireGuide+"], check=True)
    time.sleep(1.2)

def capture_window(out: Path):
    """Capture the frontmost WireGuide+ window via screencapture -l."""
    # Get window ID via CGWindowList
    script = """
import Quartz
opts = Quartz.kCGWindowListOptionOnScreenOnly | Quartz.kCGWindowListExcludeDesktopElements
wins = Quartz.CGWindowListCopyWindowInfo(opts, Quartz.kCGNullWindowID)
for w in wins:
    if "wireguide" in (w.get("kCGWindowOwnerName") or "").lower():
        print(w["kCGWindowNumber"])
        break
"""
    result = subprocess.run(["python3", "-c", script], capture_output=True, text=True)
    wid = result.stdout.strip()
    if wid:
        subprocess.run(["screencapture", "-l", wid, "-x", str(out)], check=True)
    else:
        # Fallback: capture full screen, let user crop
        subprocess.run(["screencapture", "-x", str(out)], check=True)
    return Image.open(out)

def blur_region(img: Image.Image, box: tuple, radius: int = 20) -> Image.Image:
    """Blur a rectangular region (x1, y1, x2, y2) in-place."""
    region = img.crop(box)
    blurred = region.filter(ImageFilter.GaussianBlur(radius))
    img.paste(blurred, box)
    return img

def auto_blur(img: Image.Image) -> Image.Image:
    """
    Blur value columns in the expanded tunnel detail rows.
    The layout is fixed: label column (~150px wide) on the left,
    value stretches to ~740px on the right side of the card.
    Row height is ~28px, starting at different Y positions depending on state.

    We blur the right ~60% of any row that looks like it contains an IP/key.
    Since we can't read text without OCR, we blur the value area of ALL
    config rows (Address, DNS, Endpoint, Allowed IPs, Public Key).
    """
    w, h = img.size

    # Scale factor for Retina (2x) displays
    scale = 2 if w > 1500 else 1

    # Card content area: left edge ~155px, right edge ~755px (at 1x)
    # Value column starts after label (~155px) and ends at card right (~755px)
    lx = int(155 * scale)
    rx = int(760 * scale)

    # Scan for rows: look for horizontal bands that likely contain config values.
    # We use a heuristic: blur every row in the expanded card area that is
    # between y=180 and y=480 (1x coords) — covers Address/DNS/Endpoint/AllowedIPs.
    row_ys_1x = [
        (180, 210),  # Address value
        (210, 240),  # DNS value
        (240, 270),  # Endpoint value
        (270, 300),  # Allowed IPs value
        (300, 330),  # Public Key (if shown)
    ]
    for y1_1x, y2_1x in row_ys_1x:
        box = (lx, int(y1_1x * scale), rx, int(y2_1x * scale))
        if box[3] <= h and box[2] <= w:
            img = blur_region(img, box, radius=18)

    return img

# ── screenshot sequence ───────────────────────────────────────────────────────

def shoot(name: str, instruction: str, blur: bool = False) -> Path:
    out = DOCS / name
    input(f"\n  → {instruction}\n    Press ENTER to capture…")
    img = capture_window(Path("/tmp/_wg_raw.png"))
    if blur:
        img = auto_blur(img)
    img.save(out, optimize=True)
    print(f"    ✓ saved {out.relative_to(Path(__file__).parent.parent)}")
    return out

# ── main ─────────────────────────────────────────────────────────────────────

def main():
    print("WireGuide+ screenshot helper")
    print("Make sure Screen Recording is granted to this terminal.\n")

    focus_app()

    shoot("01-tunnels.png",
          "Show the main tunnel list (idle, all tunnels collapsed)")

    shoot("02-expanded.png",
          "Expand one tunnel (click the › arrow) — do NOT connect it",
          blur=True)

    shoot("03-connected.png",
          "Connect a tunnel so it shows CONNECTED + stats chips + speed graph",
          blur=True)

    shoot("04-speedgraph.png",
          "Same connected state — scroll/expand so speed graph is prominent",
          blur=True)

    print("\nAll done! Review docs/screenshots/ and commit when happy.")

if __name__ == "__main__":
    main()
