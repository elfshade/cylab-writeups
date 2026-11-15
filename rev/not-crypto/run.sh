#!/usr/bin/env bash
# picoMini "not crypto" (CyLab id 222) — dump the fixed output the binary compares
# our input against, via an LD_PRELOAD hook on memcmp.
set -e
cd "$(dirname "$0")"
gcc -shared -fPIC -o shim.so shim.c
python3 -c "open('/tmp/in.bin','wb').write(b'A'*64)"
LD_PRELOAD=./shim.so ./not-crypto < /tmp/in.bin 2>&1 | sed -n '1,6p'
