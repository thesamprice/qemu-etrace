# Depends on eu-addr2line
# Copyright (C) Xilinx Inc.
# Written by Edgar E. Iglesias
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; version 2.
#

import subprocess

class addr2line:
    def __init__(self, elf, comp_dir=None, addr2line_bin="addr2line"):
        self.cmd = [addr2line_bin, "-f", "-e", elf]
        self.debugf = None

    def debug(self, msg):
        if self.debugf is None:
            self.debugf = open(".debug.addr2line", 'w+')
        self.debugf.write(msg)
        self.debugf.write("\n")

    def map(self, addr):
        try:
            print(self.cmd)
            # Start subprocess with pipes
            p = subprocess.Popen(self.cmd,
                                 shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,
                                 bufsize=0)

            # Send address as input (must be bytes in Python 3)
            input_data = f"0x{addr:x}\n".encode("utf-8")
            out, _ = p.communicate(input_data)

            # Decode bytes to string
            out_str = out.decode("utf-8").strip()
            lines = out_str.split('\n')

            if len(lines) < 2:
                return ["??", ["??", "0"]]

            sym = lines[0].strip()
            file_line = lines[1].strip()
            loc = file_line.split(":") if ':' in file_line else ["??", "0"]

            return [sym, loc]
        except Exception as e:
            self.debug(f"Error mapping addr {addr:x}: {e}")
            return ["??", ["??", "0"]]
