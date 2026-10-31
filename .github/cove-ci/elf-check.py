#!/usr/bin/env python3
"""Check that a file is a static ELF executable of the wanted machine, by reading its bytes.

Usage: elf-check.py FILE WANT_MACHINE LABEL REFUSED_MACHINE REFUSED_LABEL
  x86-64:  elf-check.py FILE 62 x86-64 183 aarch64
  aarch64: elf-check.py FILE 183 aarch64 62 x86-64

Used by cove-release.yml's publish job, outside any container that ran build
code. The file is only read, never executed. This is the same check as
runcove's warpgate-build-static.yml publish jobs ran inline (one script for
both targets here, so the two cannot drift): 64-bit little-endian ELF, the
wanted machine, EXEC or static-pie DYN with an entry point, real program
headers, no PT_INTERP, no DT_NEEDED.
"""
import struct
import sys

path, want, label, refused, refused_label = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5]


def refuse(why):
    print(f"REFUSING: {path}: {why}", file=sys.stderr)
    sys.exit(1)


try:
    b = open(path, "rb").read()
except OSError as e:
    refuse(f"cannot read it ({e})")
if len(b) < 64 or b[:4] != b"\x7fELF":
    refuse("not an ELF file")
if b[4] != 2 or b[5] != 1:
    refuse("not a 64-bit little-endian ELF")
e_type, e_machine = struct.unpack_from("<HH", b, 16)
if e_machine == refused:
    refuse(f"machine {e_machine} is {refused_label}, not {label} ({want}): the wrong target's binary")
if e_machine != want:
    refuse(f"machine {e_machine}, not {label} ({want})")
if e_type not in (2, 3):
    refuse(f"ELF type {e_type}, not an executable (EXEC or static-pie DYN)")
# A DYN with no PT_INTERP and no DT_NEEDED is also what a shared library with
# no dependencies looks like; a static-pie executable is the one with an entry
# point (runcove-unurk.1).
(e_entry,) = struct.unpack_from("<Q", b, 24)
if e_entry == 0:
    refuse("no entry point (e_entry 0): a shared object, not an executable")
(e_phoff,) = struct.unpack_from("<Q", b, 32)
e_phentsize, e_phnum = struct.unpack_from("<HH", b, 54)
# The positive check: real program headers, so a file that carries none cannot
# pass for one with no interpreter and no NEEDED.
if e_phnum == 0 or e_phentsize != 56 or e_phoff + e_phnum * 56 > len(b):
    refuse("no readable program headers")
types, dynamic = [], []
for i in range(e_phnum):
    p_type, _flags, p_offset, _vaddr, _paddr, p_filesz = struct.unpack_from("<IIQQQQ", b, e_phoff + i * 56)
    types.append(p_type)
    if p_type == 2:
        dynamic.append((p_offset, p_filesz))
if 1 not in types:
    refuse("no PT_LOAD segment")
if 3 in types:
    refuse("it has a program interpreter (PT_INTERP)")
needed = 0
for off, size in dynamic:
    if off + size > len(b):
        refuse("its dynamic segment runs past the end of the file")
    for j in range(0, size - size % 16, 16):
        tag, _val = struct.unpack_from("<qQ", b, off + j)
        if tag == 0:
            break
        if tag == 1:
            needed += 1
if needed:
    refuse(f"it names {needed} shared libraries (DT_NEEDED)")
kind = "static-pie" if e_type == 3 else "static"
print(f"{path}: {kind} {label} ELF, {e_phnum} program headers, no PT_INTERP, no DT_NEEDED")
