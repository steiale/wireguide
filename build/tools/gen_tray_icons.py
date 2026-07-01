from PIL import Image, ImageDraw
from collections import deque

SRC = "/Volumes/Data/Downloads/Gemini_Generated_Image_fd9w78fd9w78fd9w-2-2.png"
OUT_DIR = "/Volumes/Data/Code/lockplus/internal/gui/assets"

ORIG_BG = (5, 33, 56)
TOL = 30
CANVAS = 44
RADIUS = 9
MARGIN = 40  # px margin around padlock crop, in source-image pixels
SHIFT_FALLOFF = 55  # tuned so shadow pixels (far from bg color) keep their tone

STATUSES = {
    "lockplus_off.png":    (255, 255, 255),
    "lockplus_green.png":  (52, 199, 89),
    "lockplus_orange.png": (255, 159, 10),
}


def dist(c1, c2):
    return sum((a - b) ** 2 for a, b in zip(c1, c2)) ** 0.5


def find_padlock_bbox(img):
    W, H = img.size
    px = img.load()
    visited = bytearray(W * H)
    q = deque()
    for cx, cy in [(0, 0), (W - 1, 0), (0, H - 1), (W - 1, H - 1)]:
        idx = cy * W + cx
        if not visited[idx]:
            visited[idx] = 1
            q.append((cx, cy))

    bg_mask = bytearray(W * H)
    while q:
        x, y = q.popleft()
        bg_mask[y * W + x] = 1
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nx, ny = x + dx, y + dy
            if 0 <= nx < W and 0 <= ny < H:
                nidx = ny * W + nx
                if not visited[nidx]:
                    c = px[nx, ny][:3]
                    if dist(c, ORIG_BG) < TOL:
                        visited[nidx] = 1
                        q.append((nx, ny))

    minx, miny, maxx, maxy = W, H, 0, 0
    for y in range(H):
        for x in range(W):
            if not bg_mask[y * W + x]:
                if x < minx: minx = x
                if x > maxx: maxx = x
                if y < miny: miny = y
                if y > maxy: maxy = y
    return minx, miny, maxx, maxy


def recolor_bg(img, target_bg):
    """Additive shift: pixels close to orig_bg move toward target_bg,
    weighted by distance so shadows/highlights keep their relative tone."""
    img = img.convert("RGBA")
    px = img.load()
    W, H = img.size
    dr = target_bg[0] - ORIG_BG[0]
    dg = target_bg[1] - ORIG_BG[1]
    db = target_bg[2] - ORIG_BG[2]
    for y in range(H):
        for x in range(W):
            r, g, b, a = px[x, y]
            d = dist((r, g, b), ORIG_BG)
            weight = max(0.0, 1.0 - d / SHIFT_FALLOFF)
            if weight <= 0:
                continue
            nr = min(255, max(0, round(r + weight * dr)))
            ng = min(255, max(0, round(g + weight * dg)))
            nb = min(255, max(0, round(b + weight * db)))
            px[x, y] = (nr, ng, nb, a)
    return img


def rounded_mask(size, radius):
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask


def main():
    src = Image.open(SRC).convert("RGBA")
    minx, miny, maxx, maxy = find_padlock_bbox(src)
    minx = max(0, minx - MARGIN)
    miny = max(0, miny - MARGIN)
    maxx = min(src.width - 1, maxx + MARGIN)
    maxy = min(src.height - 1, maxy + MARGIN)
    crop = src.crop((minx, miny, maxx + 1, maxy + 1))
    cw, ch = crop.size
    print(f"padlock crop: {cw}x{ch}")

    # scale so the taller dimension fills CANVAS-4 (2px margin each side)
    target_h = CANVAS - 4
    scale = target_h / ch
    new_w = max(1, round(cw * scale))
    new_h = max(1, round(ch * scale))

    mask = rounded_mask(CANVAS, RADIUS)

    for filename, bg in STATUSES.items():
        recolored = recolor_bg(crop, bg)
        resized = recolored.resize((new_w, new_h), Image.LANCZOS)

        canvas = Image.new("RGBA", (CANVAS, CANVAS), bg + (255,))
        ox = (CANVAS - new_w) // 2
        oy = (CANVAS - new_h) // 2
        canvas.alpha_composite(resized, (ox, oy))

        canvas.putalpha(mask)
        out_path = f"{OUT_DIR}/{filename}"
        canvas.save(out_path)
        print(f"wrote {out_path} ({new_w}x{new_h} lock on {CANVAS}x{CANVAS})")


if __name__ == "__main__":
    main()
