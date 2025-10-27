---
title: "HackTheBoo CTF 2025 | Crypto: Sign and Run [medium]"
date: 2025-10-27
summary: "HackTheBoo 2025 Crypto — Sign and Run"
description: "Reverse-engineering the Iron Scribe service and brute-forcing its 32-bit CRC seal to recover the flag."
tags:
  - HackTheBox
  - HackTheBoo 2025
  - Cryptography
  - RSA
  - Python
categories:
  - HackTheBoo 2025
  - Crypto
draft: false
---

At the edge of Hollow Mere stands an ancient automaton known as the Iron Scribe - a machine that writes commands in living metal and executes only those sealed with a valid mark. The Scribe's master key was lost ages ago, but its forges still hum, stamping glyphs of permission into every order it receives. Willem approaches the machine's console, where it offers a bargain: "Sign your words, and I shall act. Present a forged seal, and be undone." To awaken the Scribe's obedience, one must understand how its mark is made... and how to make it lie.

## Step 1 – Understanding the Scribe

Connecting with `nc 46.101.173.67 32368` shows a banner with a 2048-bit RSA modulus every session. Reading `server.py`:

```
pt = bytes_to_long(cmd)
ct = pow(pt, d, N)
sig = crc32(long_to_bytes(ct))
print(f"Encrypted signature: {pow(sig, e, N)}")
```

During `invoke`, the service recomputes that same 32-bit `sig` and compares it with the user-supplied seal. Nothing more.. no PKCS#1 padding, no blind signing, just an RSA-encrypted CRC32. That means the only “secret” is a 32-bit integer; once you invert `pow(sig, e, N)` you can run arbitrary commands.

## Step 2 – Early Attempts

I tried several angles before brute-forcing:

- Attempted to send raw binary/UTF-8 commands hoping to influence `bytes_to_long`; the server happily accepted anything but always hashed the RSA “decryption” with CRC32.
- Dug through older RSA write-ups (blind signatures, PKCS#1 laxness, multiplicative tricks). All require the service to issue signatures on chosen messages. Here, you only ever get RSA applied to the *CRC*, not the command itself, so there’s nothing algebraic to exploit.

So despite the lore hinting at “forging a mark,” the only viable solution I found is to brute-force the 32-bit CRC directly.

## Step 3 – High-Throughput Brute Force

I wrote the brute-forcer in C using GMP:

```
mpz_powm_ui(result, base, 65537, N);
if (mpz_cmp(result, target) == 0) { ... }
```

Each thread walks a dedicated slice of the 0..2^32 range, and a shared flag stops the pool once any thread finds the match. Compiled with `gcc brute_gmp.c -O3 -march=native -lgmp -lpthread`, this reaches ~1.5M powmods/sec per core on my machine.

`exploit.py` keeps the socket alive while `brute_gmp` runs. As soon as a candidate seal is found, it sends `invoke cat</flag.txt <sig>` over that same connection and prints the flag. 

_I won't upload the code here, as I believe there is a quicker soltuion, but for that you will have to look for the official writeup from HTB_

## Step 4 – Results

After far too many retries—and eventually renting a beefier VPS because my own machine would have taken roughly 4× longer—the brute-force finally succeeded:

```
[+] Found signature: 4161569746
[+] Time taken: 3772.00 seconds (62.87 minutes)
```
```
HTB{w3_sh0u1d_m3333333t_1n_th3_m1dd13!!!!!_cc66053315777e798944cdbf28cf9836}
```

## Closing Thoughts

Despite the flavor text hinting at an elegant “forgery”, the practical exploit is a high-speed search over 2^32 RSA encryptions. It works, but it feels more like a hardware contest. I’m still waiting for the official HTB write-up to see whether there’s a smarter way.
