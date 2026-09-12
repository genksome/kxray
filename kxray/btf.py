import struct
from . import log

BTF_MAGIC = 0xEB9F

KIND_INT = 1
KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_UNION = 5
KIND_ENUM = 6
KIND_FWD = 7
KIND_TYPEDEF = 8
KIND_VOLATILE = 9
KIND_CONST = 10
KIND_RESTRICT = 11
KIND_FUNC = 12
KIND_FUNC_PROTO = 13
KIND_VAR = 14
KIND_DATASEC = 15
KIND_FLOAT = 16
KIND_DECL_TAG = 17
KIND_TYPE_TAG = 18
KIND_ENUM64 = 19

KIND_NAMES = {
    1: "INT", 2: "PTR", 3: "ARRAY", 4: "STRUCT", 5: "UNION",
    6: "ENUM", 7: "FWD", 8: "TYPEDEF", 9: "VOLATILE", 10: "CONST",
    11: "RESTRICT", 12: "FUNC", 13: "FUNC_PROTO", 14: "VAR",
    15: "DATASEC", 16: "FLOAT", 17: "DECL_TAG", 18: "TYPE_TAG",
    19: "ENUM64",
}

class BtfHeader:
    def __init__(self):
        self.magic = 0
        self.version = 0
        self.flags = 0
        self.hdr_len = 0
        self.type_off = 0
        self.type_len = 0
        self.str_off = 0
        self.str_len = 0

class BtfType:
    def __init__(self):
        self.name_off = 0
        self.info = 0
        self.size_or_type = 0
        self.name = ""
        self.kind = 0
        self.kind_flag = 0
        self.vlen = 0
        self.members = []
        self.raw_offset = 0
        self.raw_data = b""

class BtfMember:
    def __init__(self):
        self.name_off = 0
        self.type_id = 0
        self.offset = 0
        self.name = ""

class Btf:
    def __init__(self):
        self.header = None
        self.types = []
        self.strings = b""
        self.base_offset = 0

def find_btf(data):
    candidates = []
    step = 4
    for offset in range(0, len(data) - 24, step):
        magic = struct.unpack_from("<H", data, offset)[0]
        if magic != BTF_MAGIC:
            continue
        version = data[offset + 2]
        flags = data[offset + 3]
        if version != 1:
            continue
        hdr_len = struct.unpack_from("<I", data, offset + 4)[0]
        if hdr_len not in (24, 28, 32):
            continue
        type_off = struct.unpack_from("<I", data, offset + 8)[0]
        type_len = struct.unpack_from("<I", data, offset + 12)[0]
        str_off = struct.unpack_from("<I", data, offset + 16)[0]
        str_len = struct.unpack_from("<I", data, offset + 20)[0]
        if type_len == 0 or str_len == 0:
            continue
        if type_len > 64 * 1024 * 1024:
            continue
        if str_len > 16 * 1024 * 1024:
            continue
        if offset + hdr_len + type_len + str_len > len(data):
            continue
        candidates.append((offset, hdr_len, type_off, type_len, str_off, str_len))
    return candidates

def parse_header(data, offset):
    h = BtfHeader()
    h.magic = struct.unpack_from("<H", data, offset)[0]
    h.version = data[offset + 2]
    h.flags = data[offset + 3]
    h.hdr_len = struct.unpack_from("<I", data, offset + 4)[0]
    h.type_off = struct.unpack_from("<I", data, offset + 8)[0]
    h.type_len = struct.unpack_from("<I", data, offset + 12)[0]
    h.str_off = struct.unpack_from("<I", data, offset + 16)[0]
    h.str_len = struct.unpack_from("<I", data, offset + 20)[0]
    return h

def get_string(data, str_base, str_len, off):
    if off >= str_len:
        return ""
    end = data.find(b"\x00", str_base + off)
    if end < 0:
        return ""
    return data[str_base + off:end].decode("utf-8", "replace")

def parse_type(data, type_base, type_end, pos):
    if pos + 12 > type_end:
        return None, pos
    t = BtfType()
    t.raw_offset = pos
    t.name_off = struct.unpack_from("<I", data, pos)[0]
    t.info = struct.unpack_from("<I", data, pos + 4)[0]
    t.size_or_type = struct.unpack_from("<I", data, pos + 8)[0]
    t.kind = (t.info >> 24) & 0x1F
    t.kind_flag = (t.info >> 31) & 1
    t.vlen = t.info & 0xFFFF
    pos += 12
    if t.kind in (KIND_INT, KIND_FLOAT, KIND_ENUM64):
        pos += 4
        if t.kind == KIND_ENUM64:
            pos += 8 * t.vlen
    elif t.kind in (KIND_PTR, KIND_CONST, KIND_VOLATILE, KIND_RESTRICT,
                    KIND_TYPEDEF, KIND_TYPE_TAG, KIND_FUNC):
        pass
    elif t.kind == KIND_ARRAY:
        pos += 12
    elif t.kind in (KIND_STRUCT, KIND_UNION):
        for i in range(t.vlen):
            if pos + 12 > type_end:
                break
            m = BtfMember()
            m.name_off = struct.unpack_from("<I", data, pos)[0]
            m.type_id = struct.unpack_from("<I", data, pos + 4)[0]
            m.offset = struct.unpack_from("<I", data, pos + 8)[0]
            t.members.append(m)
            pos += 12
    elif t.kind == KIND_ENUM:
        pos += 8 * t.vlen
    elif t.kind == KIND_FUNC_PROTO:
        pos += 8 * t.vlen
    elif t.kind == KIND_VAR:
        pos += 4
    elif t.kind == KIND_DATASEC:
        pos += 12 * t.vlen
    elif t.kind == KIND_DECL_TAG:
        pos += 4
    t.raw_data = data[t.raw_offset:pos]
    return t, pos

def parse(data, offset):
    h = parse_header(data, offset)
    type_base = offset + h.hdr_len + h.type_off
    str_base = offset + h.hdr_len + h.str_off
    type_end = type_base + h.type_len
    btf = Btf()
    btf.header = h
    btf.base_offset = offset
    btf.strings = data[str_base:str_base + h.str_len]
    pos = type_base
    tid = 1
    while pos < type_end:
        t, pos = parse_type(data, type_base, type_end, pos)
        if t is None:
            break
        t.id = tid
        tid += 1
        t.name = get_string(data, str_base, h.str_len, t.name_off)
        for m in t.members:
            m.name = get_string(data, str_base, h.str_len, m.name_off)
        btf.types.append(t)
    return btf

def find_struct(btf, name):
    for t in btf.types:
        if t.kind == KIND_STRUCT and t.name == name:
            return t
    return None

def find_field(struct, name):
    for m in struct.members:
        if m.name == name:
            return m
    return None

def get_field_offset(btf, struct_name, field_name):
    s = find_struct(btf, struct_name)
    if not s:
        return None
    f = find_field(s, field_name)
    if not f:
        return None
    return f.offset // 8

def get_struct_size(btf, struct_name):
    s = find_struct(btf, struct_name)
    if not s:
        return None
    return s.size_or_type

def find_var(btf, name):
    for t in btf.types:
        if t.kind == KIND_VAR and t.name == name:
            return t
    return None