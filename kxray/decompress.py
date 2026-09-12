import gzip
import bz2
import lzma
import zlib
from . import log

try:
    import lz4.frame as lz4_frame
    HAVE_LZ4 = True
except ImportError:
    HAVE_LZ4 = False

try:
    import zstandard as zstd
    HAVE_ZSTD = True
except ImportError:
    HAVE_ZSTD = False

MAGIC_GZIP = b"\x1f\x8b"
MAGIC_BZIP2 = b"BZh"
MAGIC_LZMA = b"\x5d\x00\x00"
MAGIC_XZ = b"\xfd\x37\x7a\x58\x5a\x00"
MAGIC_ZSTD = b"\x28\xb5\x2f\xfd"
MAGIC_LZ4_FRAME = b"\x04\x22\x4d\x18"
MAGIC_LZ4_LEGACY = b"\x02\x21\x4c\x18"

def detect(data):
    if len(data) < 4:
        return None
    if data.startswith(MAGIC_GZIP):
        return "gzip"
    if data.startswith(MAGIC_BZIP2):
        return "bzip2"
    if data.startswith(MAGIC_LZMA):
        return "lzma"
    if data.startswith(MAGIC_XZ):
        return "xz"
    if data.startswith(MAGIC_ZSTD):
        return "zstd"
    if data.startswith(MAGIC_LZ4_FRAME):
        return "lz4_frame"
    if data.startswith(MAGIC_LZ4_LEGACY):
        return "lz4_legacy"
    return None

def try_gzip(data):
    try:
        return gzip.decompress(data)
    except Exception:
        try:
            return zlib.decompress(data, 16 + zlib.MAX_WBITS)
        except Exception:
            return None

def try_bzip2(data):
    try:
        return bz2.decompress(data)
    except Exception:
        return None

def try_lzma(data):
    try:
        return lzma.decompress(data)
    except Exception:
        try:
            return lzma.decompress(data, format=lzma.FORMAT_ALONE)
        except Exception:
            return None

def try_xz(data):
    try:
        return lzma.decompress(data, format=lzma.FORMAT_XZ)
    except Exception:
        return None

def try_zstd(data):
    if not HAVE_ZSTD:
        return None
    try:
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(data, max_output_size=256 * 1024 * 1024)
    except Exception:
        return None

def try_lz4_frame(data):
    if not HAVE_LZ4:
        return None
    try:
        return lz4_frame.decompress(data)
    except Exception:
        return None

def try_lz4_legacy(data):
    return None

HANDLERS = {
    "gzip": try_gzip,
    "bzip2": try_bzip2,
    "lzma": try_lzma,
    "xz": try_xz,
    "zstd": try_zstd,
    "lz4_frame": try_lz4_frame,
    "lz4_legacy": try_lz4_legacy,
}

def auto_decompress(data):
    kind = detect(data)
    if not kind:
        log.warn("unknown compression format")
        return None, None
    log.info(f"detected compression: {kind}")
    handler = HANDLERS.get(kind)
    if not handler:
        log.warn(f"handler not available for {kind}")
        return None, kind
    result = handler(data)
    if result is None:
        log.warn(f"decompression failed for {kind}")
        return None, kind
    log.ok(f"decompressed: {len(data)} -> {len(result)} bytes")
    return result, kind