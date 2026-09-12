import os
import struct

def read_file(path):
    with open(path, "rb") as f:
        return f.read()

def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)

def u32le(data, off):
    return struct.unpack_from("<I", data, off)[0]

def u64le(data, off):
    return struct.unpack_from("<Q", data, off)[0]

def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"