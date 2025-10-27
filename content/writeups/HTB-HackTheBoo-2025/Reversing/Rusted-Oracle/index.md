---
title: "HackTheBoo CTF 2025 | Rev: Rusted Oracle [easy]"
date: 2025-10-27
summary: "HackTheBoo 2025 Reverse — Rusted Oracle"
description: "Reverse-engineering a 64-bit ELF to replicate a bitwise transform over QWORD constants and recover the flag."
tags:
  - HackTheBox
  - HackTheBoo 2025
  - Reverse Engineering
  - ELF
  - x86_64
  - GDB
categories:
  - HackTheBoo 2025
  - Reverse
draft: false
---

An ancient machine, a relic from a forgotten civilization, could be the key to defeating the Hollow King. However, the gears have ground almost to a halt. Can you restore the decrepit mechanism?

## Step 1: Explore the Challenge Files

List contents and identify the target binary.

```
file rusted_oracle
```

Findings:

- `rusted_oracle`: 64-bit PIE ELF, dynamically linked, not stripped.

## Step 2: Baseline Runtime Behavior

Run the binary to see prompts and interaction.

```
./rusted_oracle
printf 'test\n' | ./rusted_oracle
```

Output snippet:

```
A forgotten machine still ticks beneath the stones.
Its gears grind against centuries of rust.

[ a stranger approaches, and the machine asks for their name ]
> [ the machine falls silent ]
```

Observation: It asks for a name, then falls silent if the input is wrong.

## Step 3: Static Recon for Hints

Look for embedded strings and constants.

```
strings -a rusted_oracle | head -n 50
objdump -s -j .rodata rusted_oracle
```

Interesting `.rodata` excerpt:

```
Contents of section .rodata:
 2000 01000200 4f6e2061 20727573 74656420  ....On a rusted 
 2010 706c6174 652c2066 61696e74 206c6574  plate, faint let
 2020 74657273 20726576 65616c20 7468656d  ters reveal them
 2030 73656c76 65733a20 25730a00 4120666f  selves: %s..A fo
 ...
 20e0 00726561 6400436f 7277696e 2056656c  .read.Corwin Vel
 20f0 6c005b20 74686520 67656172 73206265  l.[ the gears be
 2100 67696e20 746f2074 75726e2e 2e2e2073  gin to turn... s
 2110 6c6f776c 792e2e2e 205d0a00 5b207468  lowly... ]..[ th
```

The name `Corwin Vell` appears near other UI text, suggesting a magic input.

## Step 4: Disassemble Control Flow

Disassemble `main` to confirm the check and follow-on logic.

```
gdb -batch -ex 'file rusted_oracle' -ex 'disassemble main'
```

Key points from `main`:

- Reads up to 0x3f bytes into a 0x40 buffer, trims trailing newline.
- `strcmp(input, CONST_AT_0x20E6)` — if zero, prints "[ the gears begin to turn... ]" and calls `machine_decoding_sequence`.
- Else prints a failure message and exits.

Given the `.rodata` placement, the expected name is `Corwin Vell`.

## Step 5: Analyze the Decoding Routine

Disassemble the function that prints the final message.

```
gdb -batch -ex 'file rusted_oracle' -ex 'disassemble machine_decoding_sequence'
```

Pseudo-logic reconstructed from the assembly (loop over 24 QWORDs at `enc = 0x4050`):

```
for i in range(24):
    v = enc[i]
    v ^= 0x524e
    v = ror64(v, 1)
    v ^= 0x5648
    v = rol64(v, 7)
    v >>= 8
    out[i] = v & 0xff
print("On a rusted plate, faint letters reveal themselves: %s" % out)
```

Dump the `enc` array from memory:

```
gdb -batch -ex 'file rusted_oracle' -ex 'x/24gx 0x4050'
```

Resulting QWORDs:

```
0x000000000000fffe
0x000000000000ff8e
0x000000000000ffd6
0x000000000000ff32
0x000000000000ff12
0x000000000000ff72
0x000000000000fe1a
0x000000000000ff1e
0x000000000000ff9e
0x000000000000fe1a
0x000000000000ff66
0x000000000000ffc2
0x000000000000fe6a
0x000000000000ffd2
0x000000000000fe0e
0x000000000000ff6e
0x000000000000ff6e
0x000000000000fe4e
0x000000000000fe5a
0x000000000000fe5a
0x000000000000fe1a
0x000000000000fe5a
0x000000000000ff2a
0x0000000000000000
```

## Step 6: Recreate the Transform and Recover the Flag

Implement the exact bitwise pipeline in Python and run it over the constants. A trailing padding byte is discarded.

Create the decoder:

```
ENC_VALUES = [
    0x000000000000fffe,
    0x000000000000ff8e,
    0x000000000000ffd6,
    0x000000000000ff32,
    0x000000000000ff12,
    0x000000000000ff72,
    0x000000000000fe1a,
    0x000000000000ff1e,
    0x000000000000ff9e,
    0x000000000000fe1a,
    0x000000000000ff66,
    0x000000000000ffc2,
    0x000000000000fe6a,
    0x000000000000ffd2,
    0x000000000000fe0e,
    0x000000000000ff6e,
    0x000000000000ff6e,
    0x000000000000fe4e,
    0x000000000000fe5a,
    0x000000000000fe5a,
    0x000000000000fe1a,
    0x000000000000fe5a,
    0x000000000000ff2a,
    0x0000000000000000,
]

MASK64 = 0xFFFFFFFFFFFFFFFF

def decode(values):
    out = []
    for v in values:
        v ^= 0x524E
        v = ((v >> 1) | ((v & 1) << 63)) & MASK64  # ror 1
        v ^= 0x5648
        v = ((v << 7) & MASK64) | (v >> (64 - 7))  # rol 7
        v >>= 8
        out.append(v & 0xFF)
    return bytes(out[:-1])

if __name__ == '__main__':
    print(decode(ENC_VALUES).decode('ascii'))
PY
```

```
python3 exploit.py
```

Output:

```
HTB{sk1pP1nG-C4ll$!!1!}
```
