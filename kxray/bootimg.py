import struct
import re
from . import log
from . import utils
from . import decompress

MAGIC = b"ANDROID!"

class BootImage:
    def __init__(self, data):
        self.data = data
        self.magic = None
        self.version = None
        self.kernel_size = 0
        self.ramdisk_size = 0
        self.second_size = 0
        self.page_size = 0
        self.os_version = 0
        self.name = b""
        self.cmdline = b""
        self.id = b""
        self.extra_cmdline = b""
        self.header_size = 0
        self.header_version = 0
        self.kernel_offset = 0
        self.ramdisk_offset = 0
        self.second_offset = 0
        self.dtb_offset = 0
        self.dtb_size = 0
        self.bootconfig_offset = 0
        self.bootconfig_size = 0
        self.kernel_addr = 0
        self.ramdisk_addr = 0
        self.second_addr = 0
        self.tags_addr = 0

def align(value, page):
    if page == 0:
        return value
    return ((value + page - 1) // page) * page

def parse_v0_v2(img):
    data = img.data
    img.kernel_addr = utils.u32le(data, 0x0C)
    img.ramdisk_size = utils.u32le(data, 0x10)
    img.ramdisk_addr = utils.u32le(data, 0x14)
    img.second_size = utils.u32le(data, 0x18)
    img.second_addr = utils.u32le(data, 0x1C)
    img.tags_addr = utils.u32le(data, 0x20)
    img.page_size = utils.u32le(data, 0x24)
    img.name = data[0x30:0x40].split(b"\x00", 1)[0]
    img.cmdline = data[0x40:0x240].split(b"\x00", 1)[0]
    img.id = data[0x240:0x260]
    img.extra_cmdline = data[0x260:0x660].split(b"\x00", 1)[0]
    img.version = img.header_version
    log.info(f"page_size: 0x{img.page_size:X}")
    log.info(f"kernel_size: 0x{img.kernel_size:X}")
    log.info(f"ramdisk_size: 0x{img.ramdisk_size:X}")
    if img.name:
        log.info(f"name: {img.name.decode('utf-8', 'replace')}")
    if img.cmdline:
        log.info(f"cmdline: {img.cmdline.decode('utf-8', 'replace')}")
    n = img.page_size
    img.kernel_offset = n
    img.ramdisk_offset = img.kernel_offset + align(img.kernel_size, n)
    img.second_offset = img.ramdisk_offset + align(img.ramdisk_size, n)

def parse_v3_v4(img):
    data = img.data
    img.ramdisk_size = utils.u32le(data, 0x0C)
    img.page_size = 4096
    img.version = img.header_version
    log.info(f"kernel_size: 0x{img.kernel_size:X}")
    log.info(f"ramdisk_size: 0x{img.ramdisk_size:X}")
    if img.header_version == 4:
        img.cmdline = data[0x2C:0x2C+4096].split(b"\x00", 1)[0]
        if img.cmdline:
            log.info(f"cmdline: {img.cmdline.decode('utf-8', 'replace')}")
    img.kernel_offset = img.header_size
    img.ramdisk_offset = img.kernel_offset + align(img.kernel_size, img.page_size)
    img.bootconfig_offset = img.ramdisk_offset + align(img.ramdisk_size, img.page_size)

def parse(data):
    if len(data) < 8:
        log.err("file too small for boot.img")
        return None
    img = BootImage(data)
    img.magic = data[0:8]
    if img.magic != MAGIC:
        log.warn("not an ANDROID! boot image")
        return None
    log.ok("magic ANDROID! found")
    if len(data) < 0x30:
        log.err("header too small")
        return None
    img.kernel_size = utils.u32le(data, 0x08)
    img.os_version = utils.u32le(data, 0x10)
    img.header_size = utils.u32le(data, 0x14)
    img.header_version = utils.u32le(data, 0x28)
    log.info(f"header_version: {img.header_version}")
    if img.header_version in (0, 1, 2):
        parse_v0_v2(img)
    elif img.header_version in (3, 4):
        parse_v3_v4(img)
    else:
        log.warn(f"unknown header_version: {img.header_version}")
        return None
    return img

def extract_kernel(img, out_path, auto_decompress_flag=True):
    if img.kernel_size == 0:
        log.warn("kernel_size is 0")
        return False
    off = img.kernel_offset
    end = off + img.kernel_size
    if end > len(img.data):
        log.err("kernel exceeds file size")
        return False
    raw = img.data[off:end]
    utils.write_file(out_path, raw)
    log.ok(f"kernel saved to {out_path} ({len(raw)} bytes)")
    if auto_decompress_flag:
        kind = decompress.detect(raw)
        if kind:
            dec, kind = decompress.auto_decompress(raw)
            if dec:
                dec_path = out_path + ".decompressed"
                utils.write_file(dec_path, dec)
                log.ok(f"decompressed kernel saved to {dec_path}")
    return True

def extract_ramdisk(img, out_path, auto_decompress_flag=True):
    if img.ramdisk_size == 0:
        log.warn("ramdisk_size is 0")
        return False
    off = img.ramdisk_offset
    end = off + img.ramdisk_size
    if end > len(img.data):
        log.err("ramdisk exceeds file size")
        return False
    raw = img.data[off:end]
    utils.write_file(out_path, raw)
    log.ok(f"ramdisk saved to {out_path} ({len(raw)} bytes)")
    if auto_decompress_flag:
        kind = decompress.detect(raw)
        if kind:
            dec, kind = decompress.auto_decompress(raw)
            if dec:
                dec_path = out_path + ".decompressed"
                utils.write_file(dec_path, dec)
                log.ok(f"decompressed ramdisk saved to {dec_path}")
    return True

def extract_bootconfig(img, out_path):
    if img.bootconfig_size == 0:
        log.warn("bootconfig_size is 0")
        return False
    off = img.bootconfig_offset
    end = off + img.bootconfig_size
    if end > len(img.data):
        log.err("bootconfig exceeds file size")
        return False
    utils.write_file(out_path, img.data[off:end])
    log.ok(f"bootconfig saved to {out_path}")
    return True

def find_btf_in_kernel(kernel_data):
    from . import btf
    candidates = btf.find_btf(kernel_data)
    if not candidates:
        return None, []
    results = []
    for offset, hdr_len, type_off, type_len, str_off, str_len in candidates:
        log.info(f"BTF candidate at 0x{offset:X}: hdr_len={hdr_len}, type_len={type_len}, str_len={str_len}")
        try:
            parsed = btf.parse(kernel_data, offset)
            if len(parsed.types) > 0:
                results.append((offset, parsed))
        except Exception as e:
            log.warn(f"BTF parse failed at 0x{offset:X}: {e}")
    if results:
        return results[0][1], results
    return None, []

def extract_kernel_version(kernel_data):
    pattern = re.compile(rb"Linux version (\S+)")
    m = pattern.search(kernel_data)
    if not m:
        return None
    return m.group(1).decode("utf-8", "replace")

def extract_vermagic(kernel_data):
    pattern = re.compile(rb"(\d+\.\d+\.\d+[-\w.]*\S*\s+SMP\s+\S+)")
    m = pattern.search(kernel_data)
    if not m:
        return None
    return m.group(1).decode("utf-8", "replace")