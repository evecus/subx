"""Generate SubX PNG icons from the same vector shape as favicon.svg.

Draws at 4x supersample for anti-aliasing, then downscales:
  favicon-512.png  (512x512)
  icon-192.png     (192x192)
  apple-touch-icon.png (180x180)
"""
import math
import os

from PIL import Image, ImageDraw

OUT = os.path.join(os.path.dirname(__file__), "..", "web", "public")

# viewBox is 108x108 like the SVG; scale factor for the render size
SS = 4  # supersample


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def cubic_points(p0, p1, p2, p3, steps=220):
    pts = []
    for i in range(steps + 1):
        t = i / steps
        mt = 1 - t
        x = mt**3 * p0[0] + 3 * mt**2 * t * p1[0] + 3 * mt * t**2 * p2[0] + t**3 * p3[0]
        y = mt**3 * p0[1] + 3 * mt**2 * t * p1[1] + 3 * mt * t**2 * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def stroke_path(d, pts, radius):
    """Draw a round-capped stroke by stamping overlapping discs along the
    path — no joint artifacts even at high curvature. Points are
    interpolated at fixed arc-length intervals so sparse control points
    still yield a continuous stroke."""
    r = radius
    step = max(0.75, r * 0.35)
    stamped = []
    cur = pts[0]
    stamped.append(cur)
    for i in range(1, len(pts)):
        x0, y0 = cur
        x1, y1 = pts[i]
        seg = math.hypot(x1 - x0, y1 - y0)
        if seg == 0:
            continue
        ux, uy = (x1 - x0) / seg, (y1 - y0) / seg
        traveled = 0.0
        while traveled + step <= seg:
            traveled += step
            cur = (x0 + ux * traveled, y0 + uy * traveled)
            stamped.append(cur)
        cur = (x1, y1)
        stamped.append(cur)
    for (x, y) in stamped:
        d.ellipse([x - r, y - r, x + r, y + r], fill=(255, 255, 255, 255))


def render(size):
    s = size / 108.0 * SS
    W = int(108 * s)
    img = Image.new("RGBA", (W, W), (0, 0, 0, 0))

    # --- gradient tile (diagonal, approximating CSS 120deg) ---
    c1, c2, c3 = (99, 102, 241), (139, 92, 246), (168, 85, 247)
    grad = Image.new("RGBA", (W, W))
    gd = ImageDraw.Draw(grad)
    for y in range(W):
        for seg_x in range(0, W, 8):
            t = ((seg_x + 4) / W * 0.5 + y / W * 0.5)
            col = lerp(c1, c2, t / 0.55) if t < 0.55 else lerp(c2, c3, (t - 0.55) / 0.45)
            gd.rectangle([seg_x, y, seg_x + 7, y], fill=col + (255,))

    mask = Image.new("L", (W, W), 0)
    md = ImageDraw.Draw(mask)
    x0, y0, x1, y1 = 4 * s, 4 * s, 104 * s, 104 * s
    md.rounded_rectangle([x0, y0, x1, y1], radius=26 * s, fill=255)
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)

    def P(x, y):
        return (x * s, y * s)

    # --- stroke S (same path as favicon.svg) ---
    segs = [
        ((76, 38), (74, 29), (65, 24), (54, 24)),
        ((54, 24), (41, 24), (33, 31), (33, 41)),
        ((33, 41), (33, 52), (43, 55), (54, 57)),
        ((54, 57), (65, 59), (75, 62), (75, 73)),
        ((75, 73), (75, 83), (65, 88), (54, 88)),
        ((54, 88), (42, 88), (34, 82), (32, 72)),
    ]
    pts = []
    for p0, p1, p2, p3 in segs:
        seg = cubic_points(P(*p0), P(*p1), P(*p2), P(*p3))
        if pts:
            seg = seg[1:]
        pts.extend(seg)
    w = 11 * s / 2
    stroke_path(d, pts, w)
    # x accent badge (top-right) as stamped strokes too
    stroke_path(d, [P(80, 20), P(86, 26), P(92, 32)], 6 * s / 2)
    stroke_path(d, [P(92, 20), P(86, 26), P(80, 32)], 6 * s / 2)

    return img.resize((size, size), Image.LANCZOS)


def main():
    for name, size in (("favicon-512.png", 512), ("icon-192.png", 192), ("apple-touch-icon.png", 180)):
        out = os.path.normpath(os.path.join(OUT, name))
        render(size).save(out, "PNG")
        print("wrote", out)


if __name__ == "__main__":
    main()
