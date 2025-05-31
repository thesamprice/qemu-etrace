import sys
import os
from collections import defaultdict
from etrace import etrace
import bisect

def load_nm_symbols(nm_file):
    nm_addrs = []
    nm_symbols = []
    with open(nm_file) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 3:
                addr_str, _type, name = parts
                if _type.lower() != 't':  # Only include text symbols (functions)
                    continue
                try:
                    addr = int(addr_str, 16)
                    nm_addrs.append(addr)
                    nm_symbols.append(name)
                except ValueError:
                    continue
    return nm_addrs, nm_symbols

def lookup_symbol_nm(pc, nm_addrs, nm_symbols):
    idx = bisect.bisect_right(nm_addrs, pc)
    if idx == 0:
        return ("??", 0)
    return (nm_symbols[idx - 1], nm_addrs[idx - 1])

def show_progress(current, total):
    percent = int((current / total) * 100)
    print(f"\rProgress: {percent:3d}%", end="", flush=True)

def main():
    if len(sys.argv) != 3:
        print("Usage: generate_hot_report.py <trace.bin> <nm.txt>")
        sys.exit(1)

    trace_file = sys.argv[1]
    nm_file = sys.argv[2]

    print("Loading NM symbols...")
    nm_addrs, nm_symbols = load_nm_symbols(nm_file)

    print("Parsing trace...")
    symbol_hits = defaultdict(int)
    symbol_addrs = {}
    symbol_pc_counts = defaultdict(lambda: defaultdict(int))

    total_size = os.path.getsize(trace_file)

    with open(trace_file, 'rb') as f:
        etr = etrace(f)
        while True:
            current_pos = f.tell()
            show_progress(current_pos, total_size)

            pkg = etr.stepf()
            if not pkg:
                break
            if pkg.hdr.type == etr.TYPE_EXEC:
                for i in range(pkg.all.ex.nr):
                    entry = pkg.all.ex.ex32[i]
                    pc = entry.start
                    func, addr = lookup_symbol_nm(pc, nm_addrs, nm_symbols)
                    symbol_hits[func] += 1
                    symbol_addrs[func] = addr
                    symbol_pc_counts[func][pc] += 1

    print("\rProgress: 100%")
    print("\n=== Hottest Functions (Top 30) ===")
    sorted_hits = sorted(symbol_hits.items(), key=lambda x: x[1], reverse=True)
    for func, count in sorted_hits[:30]:
        addr = symbol_addrs.get(func, 0)
        print(f"0x{addr:08x}  {func:40} {count:6d}")
        sorted_pcs = sorted(symbol_pc_counts[func].items(), key=lambda x: x[1], reverse=True)
        for pc, pc_count in sorted_pcs:
            print(f"    0x{pc:08x} : {pc_count:6d}")

if __name__ == "__main__":
    main()
