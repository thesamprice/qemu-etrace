import sys
from ctypes import *

class etrace_hdr(Structure):
    _pack_ = 1
    _fields_ = [
        ("type", c_uint16),
        ("unit_id", c_uint16),
        ("len", c_uint32)
    ]

class etrace_exec_entry32(Structure):
    _pack_ = 1
    _fields_ = [
        ("duration", c_uint32),
        ("start", c_uint32),
        ("end", c_uint32)
    ]

class etrace_exec(Structure):
    _pack_ = 1
    _fields_ = [
        ("start_time", c_uint64)
    ]

class etrace_exec_p(Structure):
    _pack_ = 1
    _fields_ = [
        ("nr", c_uint64),
        ("ex32", POINTER(etrace_exec_entry32))
    ]

class etrace_all_subtypes(Union):
    _pack_ = 1
    _fields_ = [
        ("ex", etrace_exec_p),
        ("texec", etrace_exec)
    ]

class etrace_pkg(Structure):
    _pack_ = 1
    _fields_ = [
        ("hdr", etrace_hdr),
        ("all", etrace_all_subtypes)
    ]

class etrace:
    TYPE_EXEC = 1

    def __init__(self, f):
        self.f = f
        self.arch_bits = 32
        self.etype = etrace_exec_entry32

    def stepf(self):
        pos = self.f.tell()
        hdr_bytes = self.f.read(sizeof(etrace_hdr))
        if not hdr_bytes or len(hdr_bytes) < sizeof(etrace_hdr):
            return None

        #print(f"Offset {pos:08x} - Raw header bytes: {hdr_bytes.hex()}")

        hdr = etrace_hdr()
        memmove(addressof(hdr), hdr_bytes, sizeof(etrace_hdr))

        if hdr.len > 10_000_000:
            print(f"Suspicious length ({hdr.len}) at offset {pos:x}, skipping")
            return None

        pkg = etrace_pkg()
        pkg.hdr = hdr

        if hdr.type == self.TYPE_EXEC:
            exec_hdr = etrace_exec()
            self.f.readinto(exec_hdr)
            pkg.all.texec = exec_hdr

            num_entries = (hdr.len - sizeof(exec_hdr)) // sizeof(self.etype)
            entry_array_type = self.etype * num_entries
            entries = entry_array_type()
            self.f.readinto(entries)

            execp = etrace_exec_p()
            execp.nr = num_entries
            execp.ex32 = cast(entries, POINTER(etrace_exec_entry32))
            pkg.all.ex = execp
        else:
            self.f.seek(pos + sizeof(etrace_hdr) + hdr.len)

        return pkg
