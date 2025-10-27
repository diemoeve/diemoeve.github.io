---
title: "HackTheBoo CTF 2025 | Rev: Digital Alchemy [medium]"
date: 2025-10-27
summary: "HackTheBoo 2025 Reverse — Digital Alchemy"
description: "Reverse-engineering an ELF to transmute lead into a flag using a two-stage transform and an LCG-driven nibble XOR."
tags:
  - HackTheBox
  - HackTheBoo 2025
  - Reverse Engineering
  - ELF
  - x86_64
categories:
  - HackTheBoo 2025
  - Reverse
draft: false
---

Morvidus the alchemist claims to have perfected the art of digital alchemy. Being paranoid, he secured his incantation with a complex algorithm, but left the code rushed and broken. Fix his amateur mistakes and claim the digital gold for yourself!

## Step 1: Explore the Challenge Files

List the contents and identify file types.

```
ls -l
file athanor
cat lead.txt
xxd lead.txt
```

Findings:

- `athanor`: 64-bit PIE ELF, stripped.
- `lead.txt`: begins with magic `MTRLLEAD`, then 4 bytes, then a payload.

Header breakdown (from `xxd`):

```
00000000: 4d54 524c 4c45 4144 972c ffbc ...  MTRLLEAD.,..
```

- Magic: `MTRLLEAD`
- Seed (big-endian): `0x97 0x2c 0xff 0xbc` → `0x972cffbc`

## Step 2: Baseline Runtime Behavior

Run the binary to observe side effects.

```
./athanor
ls -l
cat gold.txt
```

Output snippet:

```
Initializing the Athanor...
The Athanor glows brightly, revealing a secret...
```

The program writes `gold.txt` with 7 bytes: `J^Mw_~<`.

## Step 3: Static Recon of the Binary

Pull strings and inspect `.rodata`.

```
strings -a athanor | head -n 50
objdump -s -j .rodata athanor
```

Interesting data in `.rodata`:

- `USMWO[]\iN[QWRYdqXle[i_bm^aoc` (29 bytes)
- Filenames: `lead.txt`, `gold.txt`
- Messages, and the magic `MTRLLEAD`

Disassemble to locate the main logic.

```
objdump -M intel -d athanor | sed -n '300,420p'
```

Key observations (addresses approximate):

- 0x1251–0x1310: reads `lead.txt`, checks header, loads 4-byte seed big-endian.
- 0x13bb–0x148f: Stage 1 loop processes 29 bytes, accumulates a signed sum, and reconstructs the 29-byte key above (verification path via `strcmp`).
- 0x14d4–0x15c5: Stage 2 allocates a 0x28 buffer, copies 7 bytes from the remaining payload, then for each byte computes: `state = (0x214f*state + sum) mod 0x26688d; out[i] = in[i] ^ (state & 0xf)` and writes 7 bytes to `gold.txt`.

Attempts to use tracing were sandbox-blocked, so analysis stayed static:

```
gdb -q ./athanor      # no symbols; ptrace blocked here
strace -s 80 ./athanor # ptrace blocked in sandbox
```

## Overview Diagram

High-level flow of the transformation:

```
+---------------------+           +-----------------------------+
| lead.txt            |           | athanor (ELF, stripped)     |
|  MTRLLEAD | seed    |  ----->   |  read header + seed (BE)    |
|  payload            |           |  stage1: consume 29 bytes   |
|                     |           |    - derive 29B key         |
+---------------------+           |    - signed sum S of bytes  |
                                  |  stage2: for remaining tail |
                                  |    state = (0x214F*state+S) |
                                  |            mod 0x26688D     |
                                  |    out[i] = in[i] ^ (state  |
                                  |                 & 0xF)      |
                                  +-------------+---------------+
                                                |
                                                v
                                              (flag)
```

## Step 4: Model the Transform in Python

Recreate Stage 1 to confirm the embedded 29-byte key and compute the signed sum of the first 29 payload bytes (result: 2245).

```
from pathlib import Path
data = Path('lead.txt').read_bytes()
payload = bytearray(data[12:])
base = 0x40
key_len = 29
signed_sum = 0
idx = 0
for i in range(key_len):
    b = payload[idx]; idx += 1
    signed_sum += b if b < 0x80 else b - 0x100
    # complex per-byte transform (matches key in .rodata)
    t = base ^ ((base + i + b) & 0xff)
    h = ((t*3) >> 8) & 0xff
    t2 = (((t - h) & 0xff) >> 1) & 0xff
    t2 = (t2 + h) & 0xff
    t2 = (t2 >> 6) & 0xff
    t3 = ((t2 << 7) - t2) & 0xff
    out = (t - t3 + 1) & 0xff
print('sum =', signed_sum)
print('stage1 consumed =', idx)
```

Stage 2 on the next 7 bytes reproduces `gold.txt` but we can also apply it to the entire remaining payload to get the flag.

```
from pathlib import Path
data = Path('lead.txt').read_bytes()
seed = int.from_bytes(data[8:12], 'big')
payload = bytearray(data[12:])
base, key_len = 0x40, 29
signed_sum = sum((b if b < 0x80 else b-0x100) for b in payload[:key_len])
tail = payload[key_len:]
state = seed
res = bytearray()
for b in tail:
    state = (0x214f*state + (signed_sum & 0xffffffff)) & 0xffffffff
    state %= 0x26688d
    res.append(b ^ (state & 0xf))
print(res.decode('latin1'))
```

Output:

```
HTB{Sp1r1t_0f_Th3_C0d3_Aw4k3n3d}\x0c
```
* strip the `\x0c`
