"""Generates the app icon (assets/isolated.ico and assets/icon64.rgba).

A rounded square with a white shield. Pure Python, no dependencies:
    python3 assets/make_icon.py
"""
import math, struct, zlib, os

BG = (46, 84, 196)
FG = (255, 255, 255)

def shield_dist(x, y):
    """Signed-ish test: is (x, y) in [0,1]^2 inside the shield?"""
    cx = 0.5
    top, mid, bot = 0.18, 0.55, 0.86
    half = 0.30
    if y < top or y > bot:
        return False
    if y <= mid:
        # Top edge dips slightly in the middle.
        dip = 0.03 * (1 - ((x - cx) / half) ** 2) if abs(x - cx) < half else 0
        return abs(x - cx) <= half and y >= top + dip
    t = (y - mid) / (bot - mid)
    w = half * math.cos(t * math.pi / 2) ** 0.8
    return abs(x - cx) <= w

def pixel(x, y, n):
    ss = 4
    cov_bg = cov_fg = 0
    for i in range(ss):
        for j in range(ss):
            u = (x + (i + 0.5) / ss) / n
            v = (y + (j + 0.5) / ss) / n
            r = 0.2
            dx = max(abs(u - 0.5) - (0.5 - r) + 0.02, 0)
            dy = max(abs(v - 0.5) - (0.5 - r) + 0.02, 0)
            if dx * dx + dy * dy <= r * r:
                cov_bg += 1
                inner = shield_dist(u, v)
                hole = shield_dist(0.5 + (u - 0.5) / 0.7, 0.52 + (v - 0.52) / 0.7)
                core = shield_dist(0.5 + (u - 0.5) / 0.38, 0.52 + (v - 0.52) / 0.38)
                if (inner and not hole) or core:
                    cov_fg += 1
    total = ss * ss
    a = cov_bg / total
    if cov_bg == 0:
        return (0, 0, 0, 0)
    f = cov_fg / cov_bg
    rgb = tuple(round(BG[k] * (1 - f) + FG[k] * f) for k in range(3))
    return rgb + (round(a * 255),)

def render(n):
    return [[pixel(x, y, n) for x in range(n)] for y in range(n)]

def png(img):
    n = len(img)
    raw = b"".join(b"\x00" + bytes(c for p in row for c in p) for row in img)
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))

here = os.path.dirname(os.path.abspath(__file__))
sizes = [16, 24, 32, 48, 64, 256]
images = {n: render(n) for n in sizes}
pngs = [png(images[n]) for n in sizes]
header = struct.pack("<HHH", 0, 1, len(sizes))
offset = 6 + 16 * len(sizes)
entries = b""
for n, data in zip(sizes, pngs):
    entries += struct.pack("<BBBBHHII", n % 256, n % 256, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
with open(os.path.join(here, "isolated.ico"), "wb") as f:
    f.write(header + entries + b"".join(pngs))
with open(os.path.join(here, "icon64.rgba"), "wb") as f:
    f.write(bytes(c for row in images[64] for p in row for c in p))
with open(os.path.join(here, "icon256.png"), "wb") as f:
    f.write(pngs[-1])
