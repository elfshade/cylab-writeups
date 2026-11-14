#!/usr/bin/env python3
import json, hashlib

targets = json.load(open('/tmp/opencode/targets.json'))  # [g, vals, masks]
found = {}
for line in open('/tmp/opencode/bfall.out'):
    line = line.strip()
    if not line.startswith('F '): continue
    _, ti, pre = line.split()
    ti = int(ti); pre = int(pre, 16)
    found[ti] = pre

tkey = {}
for i, (g, vals, masks) in enumerate(targets):
    tkey[(g, tuple(vals), tuple(masks))] = i

shells = [l.strip() for l in open('/tmp/opencode/shells.txt') if l.strip()]
sufs = ["GpLaMjEW", "pVOjnnmk", "RGiledp6", "Mvcezxls"]
offs = [8, 2, 7, 1]

def shellcode_of_pw(pw):
    out = bytearray()
    for g in range(4):
        chunk = bytes(pw[4*g:4*g+4]) + sufs[g].encode()
        d = hashlib.md5(chunk).digest()
        out += d[offs[g]:offs[g]+4]
    return bytes(out)

solvable = []
for key in shells:
    pat = [key[i*2:i*2+2] for i in range(16)]
    chunks = []
    for g in range(4):
        vals, masks = [], []
        for j in range(4):
            t = pat[4*g+j]
            if t == '??': vals.append(0); masks.append(0)
            else: vals.append(int(t, 16)); masks.append(1)
        chunks.append((vals, masks))
    ok = True; pw = bytearray()
    for g in range(4):
        vals, masks = chunks[g]
        if any(masks):
            ti = tkey.get((g, tuple(vals), tuple(masks)))
            if ti is None or ti not in found:
                ok = False; break
            p = found[ti]
            pw += bytes([p & 0xff, (p >> 8) & 0xff, (p >> 16) & 0xff, (p >> 24) & 0xff])
        else:
            pw += b'AAAA'
    if ok and len(pw) == 16:
        sc = shellcode_of_pw(pw)
        solvable.append((key, bytes(pw), sc))

print("solvable shells:", len(solvable))
for key, pw, sc in solvable[:10]:
    print("PAT", key)
    print("PW ", pw.hex(), repr(pw))
    print("SC ", sc.hex())
print()
# save the first few passwords
with open('/tmp/opencode/solvable.txt', 'w') as f:
    for key, pw, sc in solvable:
        f.write(pw.hex() + ' ' + key + '\n')
