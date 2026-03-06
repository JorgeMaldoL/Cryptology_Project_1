# Project 1 – Byte-wise Vigenère Cipher

## Overview

This project implements key generation, encryption, decryption, and cryptanalysis
for a byte-wise Vigenère cipher operating over the full 256-byte alphabet.

---

## Files

| File | Description |
|------|-------------|
| `keygen` | Generate a cryptographically secure key |
| `encrypt` | Encrypt any file with a Vigenère key |
| `decrypt` | Decrypt a Vigenère ciphertext |
| `crack.py` | Crack an unknown Vigenère key via IoC + frequency analysis |
| `crack_run_output.txt` | Recorded output from cracking `mystery.enc` |

---

## Key Generation

```
$ chmod u+x keygen
$ ./keygen 10 keyfilename
```

`keygen` takes a key length and output filename. It uses Python's `secrets`
module, which internally reads from `/dev/urandom` on Linux/macOS — a
cryptographically secure entropy source. The key is written as raw bytes
(not hex or ASCII), so it cannot be opened meaningfully in a text editor.
Use `xxd keyfilename` to inspect it.

---

## Encryption

```
$ chmod u+x encrypt
$ ./encrypt plaintext keyfile > ciphertextfile
```

`encrypt` reads the plaintext and key as raw bytes. For each byte position `i`:

```
c_i = (p_i + k[i mod n]) mod 256
```

where `n` is the key length. Output goes to `stdout` so you can redirect it
to a file. Works on any file type (text, binary, images, etc.).

---

## Decryption

```
$ chmod u+x decrypt
$ ./decrypt ciphertext keyfile > recovered_plaintext
```

`decrypt` reverses the cipher. Since addition mod 256 is invertible, the
decryption formula is simply:

```
p_i = (c_i - k[i mod n]) mod 256
```

This exactly recovers the original file byte-for-byte.

### Round-trip test

```bash
./keygen 16 mykey
./encrypt rt_sample.txt mykey > ct
./decrypt ct mykey > recovered
diff rt_sample.txt recovered && echo "Round-trip OK"
```

---

## Cracking `mystery.enc`

### Results

| Finding | Value |
|---------|-------|
| **Key length** | **37 bytes** |
| **Book** | **Tarzan of the Apes** by Edgar Rice Burroughs (Project Gutenberg eBook #78) |
| **Key (hex)** | `54776f206d6f6e7468732061667465722074686579207765696768656420616e63686f720a` |
| **Key (ASCII)** | `Two months after they weighed anchor\n` |

The full crack output (including the first lines of recovered plaintext) is
saved in `crack_run_output.txt`.

### Method

Run the cracker:

```
$ python3 crack.py mystery.enc recovered_from_mystery.txt
```

**Step 1 — Index of Coincidence (IoC) key-length search**

For a random byte stream the IoC ≈ 1/256 ≈ 0.0039. For English prose it is
much higher (~0.065). Given a Vigenère ciphertext with key length `L`, splitting
the ciphertext into `L` streams (taking every L-th byte) produces `L` independent
Caesar ciphers, each with the statistical fingerprint of natural language.

We sweep `L` from 1 to 60, compute the average IoC across all `L` streams, and
rank the candidates. The true key length produces the highest average IoC.

For `mystery.enc` (517,267 bytes) the sweep gave:

```
top candidates:
  37 -> 0.06219
   2 -> 0.01565
   1 -> 0.01565
  ...
```

`L = 37` was a clear winner with an IoC close to that of English text.

**Step 2 — Frequency analysis per stream**

With `L = 37` confirmed, each of the 37 streams is a Caesar cipher shifted
by one unknown byte. For each stream we compute the byte-frequency distribution
and find the shift `s` that maximizes the dot-product with the expected English
byte-frequency distribution. That shift is the corresponding key byte.

**Step 3 — Decryption**

Assembling the 37 recovered shifts gives the key. Applying the inverse Vigenère
(`c_i - k[i mod 37]) mod 256`) recovers the plaintext. The first line of the
recovered text confirmed:

```
﻿The Project Gutenberg eBook of Tarzan of the Apes
```

---

## Notes on Cryptographic Security

- `secrets.token_bytes()` (Python) reads from `/dev/urandom`, which is seeded
  by the OS from hardware entropy sources. This is cryptographically secure.
- The Mersenne Twister (`random` module) is **not** used — its output is
  predictable given 624 outputs, making it unsuitable for key generation.
- The Vigenère cipher itself is **not** secure for real use: this exercise
  demonstrates why repeating-key stream ciphers are vulnerable to statistical
  attacks when the key is much shorter than the message.
