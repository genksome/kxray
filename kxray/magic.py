MAGIC_ANDROID = b"ANDROID!"
MAGIC_VNDRBOOT = b"VNDRBOOT"
MAGIC_ELF = b"\x7fELF"
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_LZ4_LEGACY = b"\x02\x21\x4c\x18"
MAGIC_LZ4_FRAME = b"\x04\x22\x4d\x18"
MAGIC_LZMA = b"\x5d\x00\x00"
MAGIC_XZ = b"\xfd\x37\x7a\x58\x5a\x00"
MAGIC_ZSTD = b"\x28\xb5\x2f\xfd"
MAGIC_BZIP2 = b"BZh"
MAGIC_LZO = b"\x89LZO\x00\r\n\x1a\n"
MAGIC_DTB = b"\xd0\x0d\xfe\xed"

MAGIC_TABLE = [
    (MAGIC_ANDROID, "ANDROID_BOOT"),
    (MAGIC_VNDRBOOT, "VENDOR_BOOT"),
    (MAGIC_ELF, "ELF"),
    (MAGIC_GZIP, "GZIP"),
    (MAGIC_LZ4_LEGACY, "LZ4_LEGACY"),
    (MAGIC_LZ4_FRAME, "LZ4_FRAME"),
    (MAGIC_LZMA, "LZMA"),
    (MAGIC_XZ, "XZ"),
    (MAGIC_ZSTD, "ZSTD"),
    (MAGIC_BZIP2, "BZIP2"),
    (MAGIC_LZO, "LZO"),
    (MAGIC_DTB, "DTB"),
]

def identify(data):
    if len(data) < 4:
        return None
    for magic, name in MAGIC_TABLE:
        if data.startswith(magic):
            return name
    if len(data) >= 8 and data[4:8] == b"\x1f\x8b\x08\x00":
        return "GZIP"
    return None

def scan_for_magic(data, max_scan=0x10000):
    found = []
    offset = 0
    while offset < len(data) and offset < max_scan:
        for magic, name in MAGIC_TABLE:
            if data[offset:offset+len(magic)] == magic:
                found.append((offset, name, magic))
        offset += 1
    return found