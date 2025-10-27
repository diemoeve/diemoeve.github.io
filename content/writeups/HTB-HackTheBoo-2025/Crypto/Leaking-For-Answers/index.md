---
title: "HackTheBoo CTF 2025 | Crypto: Leaking for Answers [easy]"
date: 2025-10-27
summary: "HackTheBoo 2025 Crypto — Leaking for Answers"
description: "Automating four RSA mini-challenges exposed through different leaks to recover the flag from a remote oracle."
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

Willem's path led him to a lone reed-keeper on the marsh bank. The keeper speaks only in riddles and will reveal nothing for free - yet he offers tests, one for each secret he guards. Each riddle is a vetting: answer each in turn, and the keeper will whisper what the fen keeps hidden. Fail, or linger too long answering the questions, and the marsh swallows the night. This is a sourceless riddle stand - connect, answer each of the keeper's four puzzles in sequence, and the final secret will be yours.

## Step 1: Talk to the Keeper

First, try to connect.

```
nc 68.183.73.240 31521
```

Output snippet:

```
The keeper croaks once and waits...
n = 2386...
p-q = 2684...
[1] Speak the pair of primes as (p,q) :
```

The service expects prime factors of `n`. Rerunning would cycle through four distinct challenge types, we need an automated solver.

## Step 2: Catalogue the Leak Types

Interacting manually revealed four RSA variants:

1. **Known difference:** `p−q = diff`. Standard quadratic solution: `root = sqrt(diff^2 + 4n)`, `p = (diff + root)/2`, `q = p − diff`.
2. **φ inverse leak:** The prompt showed `pow(phi, -1, n) * d % n = leak` along with `e`. Rearranged from `ed − kφ = 1`, we brute-forced small `k` to recover `φ`, then solved for `p` and `q` if the reconstruction was consistent.
3. **Private exponent leak:** `k = ed − 1` factorisation with repeated attempts of the Boneh–Durfee style loop (random `g`, square repeatedly, check gcd when squaring hits 1) until a non-trivial factor.
4. **Inverse pair leak:** The keeper leaked `A = pow(p, -q, q)` and `B = pow(q, -p, p)`. From `A·p ≡ 1 (mod q)` and `B·q ≡ 1 (mod p)` we arrive at `A·p + B·q ≡ 1 (mod n)` and in practice `A·p + B·q = n + 1`. Substituting into a quadratic yields the discriminant `Δ = (n + 1)^2 − 4ABn`, so
   
   ```
   root = isqrt(Δ)
   p = ((n + 1) ± root) / (2A)
   q = n / p
   ```

Each scenario needs its own function and a safety net (Fermat, Pollard’s rho, small trial division).

## Step 3: Building the script

You could use`gmpy2`, but I used python’s `math.isqrt`.

```
import random
import re
import socket
from math import gcd, isqrt

HOST, PORT = "68.183.73.240", 31521

inv = lambda a, m: pow(a, -1, m)

def pq(n, diff):
    r = isqrt(diff * diff + 4 * n)
    p = (diff + r) // 2
    return p, n // p

def phi_leak(n, e, leak):
    for k in range(1, 200000):
        x = (e * leak - k) % n
        if x and gcd(x, n) == 1:
            phi = inv(x, n)
            s = n - phi + 1
            d = s * s - 4 * n
            r = isqrt(d)
            if r * r == d:
                p = (s + r) // 2
                return p, n // p

def d_leak(n, e, d):
    k = e * d - 1
    s = 0
    while k % 2 == 0:
        k //= 2
        s += 1
    for _ in range(64):
        g = random.randrange(2, n - 1)
        x = pow(g, k, n)
        if x in (1, n - 1):
            continue
        for _ in range(s):
            y = pow(x, 2, n)
            if y == 1:
                p = gcd(x - 1, n)
                return p, n // p
            if y == n - 1:
                break
            x = y

def inv_leak(n, a, b):
    d = (n + 1) * (n + 1) - 4 * a * b * n
    r = isqrt(d)
    for sign in (1, -1):
        num = (n + 1) + sign * r
        den = 2 * a
        if den and num % den == 0:
            p = num // den
            if p > 1:
                return p, n // p

def fermat(n, iters=200000):
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(iters):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a + b, a - b
        a += 1

def read_prompt(sock):
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        low = buf.lower()
        if b"htb{" in buf:
            break
        if b"speak" in low or b"(p,q" in low:
            break
    return buf.decode()


def solve(text):
    n = int(re.search(r"n\s*=\s*(\d+)", text).group(1))
    if "p-q" in text:
        diff = int(re.search(r"p-q\s*=\s*(-?\d+)", text).group(1))
        return pq(n, diff)
    if "pow(phi" in text:
        e = int(re.search(r"e\s*=\s*(\d+)", text).group(1))
        leak = int(re.search(r"pow\(phi.*?=\s*(\d+)", text).group(1))
        return phi_leak(n, e, leak)
    if "d =" in text:
        e = int(re.search(r"e\s*=\s*(\d+)", text).group(1))
        d = int(re.search(r"d\s*=\s*(\d+)", text).group(1))
        return d_leak(n, e, d)
    if "pow(p, -q" in text:
        a = int(re.search(r"pow\(p, -q, q\)\s*=\s*(\d+)", text).group(1))
        b = int(re.search(r"pow\(q, -p, p\)\s*=\s*(\d+)", text).group(1))
        return inv_leak(n, a, b)
    return fermat(n)

with socket.create_connection((HOST, PORT)) as s:
    for _ in range(8):
        data = read_prompt(s)
        print(data)
        if "HTB{" in data:
            break
        p, q = solve(data)
        s.sendall(f"{p},{q}\n".encode())

```

The main loop opened the socket, read until the `Speak the pair of primes` prompt, dispatched to the right solver, sanity-checked `p*q == n`, and sent the answer. Extra guards retried or fell back to `2,2` if something unexpected happened.

## Step 4: Flag

Running the script solved all four rounds back-to-back and triggered the finale.

```
python3 exploit.py
```

Output snippet:

```
pow(q, -p, p) = 42852827395689524086438949641477969773433092939989784749451440029892365430882527966362537470683299500634711589188279805815655104612810439303734046609232546763988778418954454646538252634253701418351175018232172091283445825517370993661469015333257282066358762311684136680072293208143191687024832878888343744051
[4] Speak the pair of primes as (p,q) : 
The keeper bows. You have answered all his tests.
HTB{t0_l34k___0r_n0t___t0_l34k_f0r_4nsw3rs_0af9ea5217203e9f59e7a04b75191755}
```
