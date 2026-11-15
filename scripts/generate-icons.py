#!/usr/bin/env python3
"""Cross-platform installer & desktop icon generator for CheapAI AllUse.

Generates Windows multi-resolution `.ico`, macOS `.icns` (pure Python chunk
packer), and Linux PNG sizes from `assets/cheapai_logo_icon.png`. Works with
Pillow when installed and provides a zero-dependency pure-Python PNG fallback
when Pillow is absent.
"""

from __future__ import annotations

import argparse
from io import BytesIO
from pathlib import Path
import shutil
import struct
import sys
import tempfile

try:
    from PIL import Image, ImageDraw, ImageFilter

    HAS_PIL = True
except ImportError:
    HAS_PIL = False


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = ROOT / "assets" / "cheapai_logo_icon.png"
DEFAULT_OUT_DIR = ROOT / "target" / "installer-icons"

# Strictly monochrome dark tile palette aligned with AllUse Monochrome Workbench
BG_RGBA = (24, 24, 24, 255)
BORDER_RGBA = (54, 54, 54, 220)
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
LINUX_PNG_SIZES = (32, 128, 256, 512)
ICNS_TYPES = (
    (b"icp4", 16),
    (b"icp5", 32),
    (b"icp6", 64),
    (b"ic07", 128),
    (b"ic08", 256),
    (b"ic09", 512),
    (b"ic10", 1024),
)
MASTER_SIZE = 512
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _rounded_mask(size: int, radius: int) -> "Image.Image":
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return mask


def compose_tile(size: int, logo: "Image.Image") -> "Image.Image":
    tile = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    radius = max(3, round(size * 0.22))
    body = Image.new("RGBA", (size, size), BG_RGBA)
    body.putalpha(_rounded_mask(size, radius))
    tile.alpha_composite(body)

    if size >= 24:
        border = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        inset = max(1, round(size * 0.045))
        ImageDraw.Draw(border).rounded_rectangle(
            (inset, inset, size - 1 - inset, size - 1 - inset),
            radius=max(2, radius - inset),
            outline=BORDER_RGBA,
            width=max(1, round(size / 140) or 1),
        )
        tile.alpha_composite(border)

    pad_ratio = 0.10 if size <= 24 else 0.14
    pad = max(1, round(size * pad_ratio))
    mark_box = max(1, size - pad * 2)
    mark = logo.resize((mark_box, mark_box), Image.Resampling.LANCZOS)
    if size <= 32:
        mark = mark.filter(ImageFilter.UnsharpMask(radius=0.6, percent=135, threshold=2))
    tile.alpha_composite(mark, ((size - mark.width) // 2, (size - mark.height) // 2))
    return tile


def _pil_png_bytes(image: "Image.Image") -> bytes:
    buf = BytesIO()
    image.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _pil_dib_bytes(image: "Image.Image") -> bytes:
    rgba = image.convert("RGBA")
    width, height = rgba.size
    pixels = rgba.tobytes()
    stride = width * 4
    rows = []
    for y in range(height - 1, -1, -1):
        row = bytearray()
        start = y * stride
        for i in range(start, start + stride, 4):
            r, g, b, a = pixels[i : i + 4]
            row.extend((b, g, r, a))
        rows.append(bytes(row))
    xor_mask = b"".join(rows)
    and_stride = ((width + 31) // 32) * 4
    header = struct.pack("<IIIHHIIIIII", 40, width, height * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    return header + xor_mask + (b"\x00" * (and_stride * height))


def write_ico_pil(path: Path, images: list["Image.Image"]) -> None:
    payloads = [
        _pil_png_bytes(img) if img.size[0] >= 256 else _pil_dib_bytes(img)
        for img in images
    ]
    offset = 6 + 16 * len(images)
    header = struct.pack("<HHH", 0, 1, len(images))
    entries = bytearray()
    for img, payload in zip(images, payloads):
        w = 0 if img.size[0] >= 256 else img.size[0]
        h = 0 if img.size[1] >= 256 else img.size[1]
        entries += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(payload), offset)
        offset += len(payload)
    path.write_bytes(header + bytes(entries) + b"".join(payloads))


def write_icns_pil(path: Path, logo: "Image.Image") -> None:
    chunks = []
    for os_type, size in ICNS_TYPES:
        payload = _pil_png_bytes(compose_tile(size, logo))
        chunks.append(os_type + struct.pack(">I", 8 + len(payload)) + payload)
    body = b"".join(chunks)
    path.write_bytes(b"icns" + struct.pack(">I", 8 + len(body)) + body)


def _read_png_dimensions(png_bytes: bytes) -> tuple[int, int]:
    if not png_bytes.startswith(PNG_SIGNATURE):
        raise ValueError("Source icon is not a valid PNG file")
    if len(png_bytes) >= 24 and png_bytes[12:16] == b"IHDR":
        return struct.unpack(">II", png_bytes[16:24])
    return (64, 64)


def _write_fallback_without_pil(source: Path, out_dir: Path) -> list[Path]:
    src_bytes = source.read_bytes()
    width, height = _read_png_dimensions(src_bytes)
    written: list[Path] = []

    for size in LINUX_PNG_SIZES:
        p = out_dir / f"{size}x{size}.png"
        p.write_bytes(src_bytes)
        written.append(p)
    main_png = out_dir / "alluse.png"
    main_png.write_bytes(src_bytes)
    written.append(main_png)

    # Minimal valid Vista+ PNG-backed ICO
    ico_w = 0 if width >= 256 else max(1, min(255, width))
    ico_h = 0 if height >= 256 else max(1, min(255, height))
    ico_header = struct.pack("<HHH", 0, 1, 1)
    ico_entry = struct.pack("<BBBBHHII", ico_w, ico_h, 0, 0, 1, 32, len(src_bytes), 22)
    ico_path = out_dir / "alluse.ico"
    ico_path.write_bytes(ico_header + ico_entry + src_bytes)
    written.append(ico_path)

    # Minimal valid PNG-backed ICNS matching source size (plus ic07 fallback entry)
    icns_type = b"icp6" if width == 64 else (b"ic08" if width >= 256 else (b"ic07" if width >= 128 else b"icp5"))
    chunks = [icns_type + struct.pack(">I", 8 + len(src_bytes)) + src_bytes]
    if icns_type != b"ic07":
        chunks.append(b"ic07" + struct.pack(">I", 8 + len(src_bytes)) + src_bytes)
    body = b"".join(chunks)
    icns_path = out_dir / "AppIcon.icns"
    icns_path.write_bytes(b"icns" + struct.pack(">I", 8 + len(body)) + body)
    written.append(icns_path)
    return written


def generate_icons(source: Path, out_dir: Path, force_no_pil: bool = False) -> list[Path]:
    if not source.exists():
        raise FileNotFoundError(f"Source icon not found: {source}")
    out_dir.mkdir(parents=True, exist_ok=True)

    if force_no_pil or not HAS_PIL:
        return _write_fallback_without_pil(source, out_dir)

    logo = Image.open(source).convert("RGBA")
    written: list[Path] = []

    ico_tiles = [compose_tile(sz, logo) for sz in ICO_SIZES]
    ico_path = out_dir / "alluse.ico"
    write_ico_pil(ico_path, ico_tiles)
    written.append(ico_path)

    icns_path = out_dir / "AppIcon.icns"
    write_icns_pil(icns_path, logo)
    written.append(icns_path)

    for sz in LINUX_PNG_SIZES:
        p = out_dir / f"{sz}x{sz}.png"
        compose_tile(sz, logo).save(p, "PNG", optimize=True)
        written.append(p)

    master_src = out_dir / f"{MASTER_SIZE}x{MASTER_SIZE}.png"
    alluse_png = out_dir / "alluse.png"
    shutil.copyfile(master_src, alluse_png)
    written.append(alluse_png)
    return written


def _verify_ico(ico_path: Path, expected_min_entries: int) -> None:
    data = ico_path.read_bytes()
    assert len(data) >= 22, f"{ico_path} too small"
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    assert reserved == 0 and kind == 1, f"Invalid ICO header in {ico_path}"
    assert count >= expected_min_entries, f"Expected >= {expected_min_entries} ICO entries, got {count}"
    for i in range(count):
        base = 6 + i * 16
        w, h, _, _, planes, bpp, size, offset = struct.unpack("<BBBBHHII", data[base : base + 16])
        assert planes == 1 and bpp == 32
        assert offset + size <= len(data)
        if w == 0 and h == 0:
            assert data[offset : offset + 8] == PNG_SIGNATURE


def _verify_icns(icns_path: Path) -> None:
    data = icns_path.read_bytes()
    assert len(data) >= 16, f"{icns_path} too small"
    magic, total_len = struct.unpack(">4sI", data[:8])
    assert magic == b"icns", f"Bad ICNS magic: {magic!r}"
    assert total_len == len(data), f"ICNS length mismatch: {total_len} != {len(data)}"
    pos = 8
    chunk_count = 0
    while pos < total_len:
        os_type, chunk_len = struct.unpack(">4sI", data[pos : pos + 8])
        assert chunk_len > 8 and pos + chunk_len <= total_len
        payload = data[pos + 8 : pos + chunk_len]
        assert payload.startswith(PNG_SIGNATURE), f"Chunk {os_type!r} is not PNG"
        pos += chunk_len
        chunk_count += 1
    assert chunk_count >= 1


def run_self_test(source: Path) -> None:
    required = [
        "alluse.ico",
        "AppIcon.icns",
        "32x32.png",
        "128x128.png",
        "256x256.png",
        "512x512.png",
        "alluse.png",
    ]
    with tempfile.TemporaryDirectory(prefix="alluse-icons-test-") as tmp:
        tmp_path = Path(tmp)
        if HAS_PIL:
            pil_dir = tmp_path / "pil"
            generate_icons(source, pil_dir, force_no_pil=False)
            for name in required:
                p = pil_dir / name
                assert p.exists() and p.stat().st_size > 0, f"Missing {p}"
                if name.endswith(".png"):
                    assert p.read_bytes().startswith(PNG_SIGNATURE)
            _verify_ico(pil_dir / "alluse.ico", len(ICO_SIZES))
            _verify_icns(pil_dir / "AppIcon.icns")

        fb_dir = tmp_path / "fallback"
        generate_icons(source, fb_dir, force_no_pil=True)
        for name in required:
            p = fb_dir / name
            assert p.exists() and p.stat().st_size > 0, f"Missing fallback {p}"
            if name.endswith(".png"):
                assert p.read_bytes().startswith(PNG_SIGNATURE)
        _verify_ico(fb_dir / "alluse.ico", 1)
        _verify_icns(fb_dir / "AppIcon.icns")

    mode_str = "pil+fallback" if HAS_PIL else "fallback-only"
    print(f"generate-icons self-test ok ({mode_str})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate cross-platform AllUse installer icons.")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE, help="Source PNG icon path")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Output directory")
    parser.add_argument("--force-fallback", action="store_true", help="Force no-Pillow PNG fallback mode")
    parser.add_argument("--self-test", action="store_true", help="Run isolated temp-dir self-test")
    args = parser.parse_args()

    if args.self_test:
        run_self_test(args.source)
        return 0

    written = generate_icons(args.source, args.out_dir, force_no_pil=args.force_fallback)
    for item in written:
        print(item)
    return 0


if __name__ == "__main__":
    sys.exit(main())
