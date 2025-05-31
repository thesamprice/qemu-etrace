import sys
import os
import getopt
import curses
import time

import etrace
import addr2line

def usage():
    print("--help          Show help")
    print("--trace         filename of trace")

class traceview:
    def __init__(self, screen, e, elf_name, comp_dir, cfg):
        self.cfg = cfg
        self.fcache = {}
        self.e = e
        self.comp_dir = comp_dir
        self.screen = screen
        self.record = None
        self.record_idx = 0
        self.record_pos = 0
        self.symname = ""
        self.file = ""
        self.line = -1
        self.search_sym = ""
        self.debugf = None
        self.addrloc = {}
        self.log = []
        self.log_lines = 15

        if elf_name is not None:
            self.a2l = addr2line.addr2line(elf_name, comp_dir)
            self.screen.clear()
            self.screen.addstr(0, 0, "Processing ELF file.")
            self.screen.refresh()
            self.screen.addstr(1, 0, "Done. Step into first src line")
            self.screen.refresh()

    def debug(self, msg):
        if self.debugf is None:
            self.debugf = open(".debug", 'w+')
        self.debugf.write(msg)
        self.debugf.write("\n")

    def update_file_cache(self, fname):
        try:
            return self.fcache[fname]["lines"]
        except KeyError:
            pass

        full_fname = fname
        if self.comp_dir:
            full_fname = os.path.join(self.comp_dir, fname)

        try:
            with open(full_fname, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            return None

        if len(self.fcache) > 256:
            self.fcache = {}

        self.fcache[fname] = {"lines": lines}
        return lines

    def show_file_contents(self, filename, line_nr):
        lines = self.update_file_cache(filename)
        if lines is None:
            return

        h, w = self.screen.getmaxyx()
        if h > 60:
            h -= self.log_lines + 1
        h -= 4
        start = max(0, line_nr - h // 2)
        for i in range(4, h - 1):
            try:
                s = "%4d:%s" % (start + i, lines[start + i])
                if (start + i) == line_nr:
                    self.screen.addstr(i, 0, s, curses.A_REVERSE)
                else:
                    self.screen.addstr(i, 0, s)
            except (IndexError, curses.error):
                break

    def show_log(self):
        h, w = self.screen.getmaxyx()
        if h <= 60 or not self.log:
            return

        pos = max(0, len(self.log) - self.log_lines)
        for i in range(self.log_lines):
            if (pos + i) >= len(self.log):
                break
            try:
                self.screen.addstr(h - self.log_lines + i - 1, 0, self.log[pos + i])
            except curses.error:
                pass

    def step_end_of_subrecord(self, r):
        self.record_pos = max(r.all.ex.ex32[self.record_idx].start,
                              r.all.ex.ex32[self.record_idx].end - 4)

    def step_end_of_record(self, r):
        self.record_idx = r.all.ex.nr - 1
        self.step_end_of_subrecord(r)

    def step_start_of_record(self, r):
        self.record_idx = 0
        if r and r.hdr.type == self.e.TYPE_EXEC:
            self.record_pos = r.all.ex.ex32[0].start

    def step_existing_record_back(self, r):
        if not r or r.hdr.type != self.e.TYPE_EXEC:
            r = self.e.stepb()
            if r and r.hdr.type == self.e.TYPE_EXEC:
                self.step_end_of_record(r)
            return r

        if self.record_pos <= r.all.ex.ex32[self.record_idx].start:
            if self.record_idx == 0:
                return self.step_existing_record_back(None)
            self.record_idx -= 1
            self.step_end_of_subrecord(r)
            return r

        self.record_pos -= 4
        return r

    def step_record(self, count):
        if self.record and count < 0:
            return self.step_existing_record_back(self.record)
        elif self.record and count > 0:
            r = self.record
            if r.hdr.type == self.e.TYPE_EXEC:
                self.record_pos += 4
                if self.record_pos >= r.all.ex.ex32[self.record_idx].end:
                    self.record_idx += 1
                    if self.record_idx >= r.all.ex.nr:
                        self.record = None
                        r = self.e.stepf()
                        self.step_start_of_record(r)
                        return r
                    self.record_pos = r.all.ex.ex32[self.record_idx].start
            else:
                r = self.e.stepf()
                self.step_start_of_record(r)
            return r
        else:
            if count > 0:
                r = self.e.stepf()
                self.step_start_of_record(r)
            else:
                r = self.step_existing_record_back(None)
            return r

    def map_address_to_loc(self, address):
        if 'map_address' in self.cfg:
            address = self.cfg['map_address'](address)
        return self.a2l.map(address)

    def step_trace_record(self, count):
        r = self.step_record(count)
        self.record = r
        if not r:
            return r

        if r.hdr.type == self.e.TYPE_EXEC:
            try:
                loc = self.addrloc[self.record_pos]
            except KeyError:
                loc = self.map_address_to_loc(self.record_pos)
                self.addrloc[self.record_pos] = loc
            self.symname = loc[0]
            self.file = loc[1][0]
            self.line = int(loc[1][1]) - 1 if self.file != "??" else -1
            if self.file == "??":
                self.file = ""
        elif r.hdr.type == self.e.TYPE_MEM:
            op = "write" if (r.all.mem.attr & self.e.MEM_WRITE) else "read"
            self.log.append(f"mem {op} {r.all.mem.paddr:x} = {r.all.mem.value:x}")
            if len(self.log) > 100:
                self.log.pop(0)
        elif r.hdr.type == self.e.TYPE_EVENT_U64:
            val = r.all.event_u64.prev_val if count < 0 else r.all.event_u64.val
            self.log.append(f"event {r.all.dev_name} {r.all.event_name} "
                            f"{val:x} prev={r.all.event_u64.prev_val:x}")
        return r

    def step_new_exec(self, count=1):
        while True:
            r = self.step_trace_record(count)
            if not r:
                return None
            if r.hdr.type in (self.e.TYPE_EXEC, self.e.TYPE_EVENT_U64, self.e.TYPE_MEM):
                return r

    def step_new_line(self, count=1):
        while True:
            pfile, pline = self.file, self.line
            r = self.step_trace_record(count)
            if not r or r.hdr.type != self.e.TYPE_EXEC:
                return r
            if pfile != self.file or pline != self.line:
                return r

    def step_new_sym(self, newsymname=None, count=1):
        while True:
            if newsymname and newsymname == self.symname:
                break
            pname = self.symname
            r = self.step_new_line(count)
            if not r:
                return None
            if not newsymname and pname != self.symname:
                break
        return r

    def search_for_sym(self):
        h, _ = self.screen.getmaxyx()
        curses.echo()
        self.screen.addstr(h - 1, 0, "/")
        raw = self.screen.getstr(h - 1, 1)
        curses.noecho()
        return raw.decode('utf-8').strip()

    def loop(self):
        c = curses.KEY_DOWN
        r = self.step_new_exec(count=1)
        while True:
            if c == curses.KEY_DOWN:
                r = self.step_new_line()
            elif c == curses.KEY_RIGHT:
                r = self.step_new_sym(count=1)
            elif c == curses.KEY_LEFT:
                r = self.step_new_sym(count=-1)
            elif c == curses.KEY_UP:
                r = self.step_new_line(-1)
            elif c == ord('n'):
                if self.symname == self.search_sym:
                    r = self.step_new_sym()
                r = self.step_new_sym(self.search_sym)
            elif c == ord('/'):
                old_r = self.record
                self.search_sym = self.search_for_sym()
                r = self.step_new_sym(self.search_sym)
                if r is None:
                    r = old_r
            elif c == ord('g'):
                self.e.reset()
                r = self.step_new_exec(count=1)
            elif c == ord('G'):
                while self.step_trace_record(count=1):
                    pass
                r = self.step_new_exec(count=-1)
            elif c == ord('q'):
                return

            self.screen.clear()
            if r:
                try:
                    self.screen.addstr(0, 0,
                        f"{self.e.r_idx}: type={self.e.type_to_name(r.hdr.type)} "
                        f"{r.hdr.type:x} len={r.hdr.len} PC={self.record_pos:x} "
                        f"({r.all.ex.ex32[self.record_idx].start:x}-"
                        f"{r.all.ex.ex32[self.record_idx].end:x})",
                        curses.A_REVERSE)

                    self.screen.addstr(1, 0,
                        f"file={self.file}:{self.line} {self.symname}",
                        curses.A_REVERSE)

                    self.screen.addstr(3, 0,
                        f"search={self.search_sym}",
                        curses.A_REVERSE)

                    self.show_file_contents(self.file, self.line)
                except Exception:
                    pass

                self.show_log()
            else:
                self.screen.addstr(3, 0, "None", curses.A_REVERSE)

            self.screen.refresh()
            self.prev_file = self.file
            self.prev_line = self.line
            c = self.screen.getch()

def main(screen):
    args_comp_dir = None
    args_trace = None
    args_elf = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", [
            "help", "comp-dir=", "config=", "trace=", "elf="
        ])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(1)

    cfg = {}

    for o, a in opts:
        if o == "--trace":
            args_trace = a
        elif o == "--comp-dir":
            args_comp_dir = a
        elif o == "--config":
            exec(compile(open(a, "rb").read(), a, 'exec'), cfg)
        elif o == "--elf":
            args_elf = a
        elif o in ("-h", "--help"):
            usage()
            sys.exit(0)
        else:
            assert False, "Unhandled option " + o

    if args_trace is None:
        print("Missing trace file")
        sys.exit(1)

    screen.clear()
    with open(args_trace, 'rb') as f:
        e = etrace.etrace(f)
        tv = traceview(screen, e, args_elf, args_comp_dir, cfg)
        tv.loop()

if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        sys.exit(0)
