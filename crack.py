#!/usr/bin/env python3
"""
crack.py - Crack a byte-wise Vigenere cipher using Index of Coincidence
           and frequency analysis.

Usage: ./crack.py <ciphertext_file> [output_file]

Method:
  1. Index of Coincidence (IoC) sweep: For each candidate key length L,
     split the ciphertext into L streams (every L-th byte), compute the
     average IoC across all streams, and record the score. Key lengths
     whose average IoC is close to that of natural language score highest.

  2. Frequency analysis per stream: Once the key length is determined,
     each stream is a simple Caesar cipher (a single shift). We find the
     shift for each stream by maximizing the dot product of the stream's
     byte-frequency distribution against the expected English byte-frequency
     distribution derived from ASCII text.

  3. Key assembly and decryption: The recovered shifts form the key. We
     apply the inverse Vigenere to recover the plaintext.

The Index of Coincidence for a sequence of bytes b_0, b_1, ..., b_{m-1} is:
  IoC = sum_{v=0}^{255} f_v * (f_v - 1) / (m * (m - 1))
where f_v is the count of byte value v. For random bytes this is ~1/256 ~
0.0039. For natural language UTF-8 text it is much higher (around 0.065
for English ASCII-range bytes).
"""

import sys
import collections
from typing import List, Tuple

# ---------------------------------------------------------------------------
# English letter frequency table (bytes 0-255).
# We approximate by using standard English letter frequencies for
# ASCII letters (a-z, A-Z) and a small baseline for everything else.
# The cipher operates mod 256, so we score against this distribution.
# ---------------------------------------------------------------------------

def build_english_freq() -> List[float]:
    """
    Return a 256-element list of expected byte frequencies in English UTF-8 text.
    We use letter frequencies for a-z/A-Z and give small weight to common
    punctuation/space, and near-zero weight to everything else.
    """
    # Standard English letter frequencies (a-z), summing to ~1 over letters only.
    letter_freq = {
        'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
        'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
        'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
        'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
        'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
        'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
        'y': 0.01974, 'z': 0.00074,
    }

    freq = [0.0] * 256

    # Letters contribute about 70% of characters in typical prose.
    # Space is ~13%, newline/punctuation another ~17%.
    letter_total_weight = 0.70
    for ch, f in letter_freq.items():
        freq[ord(ch)] += f * letter_total_weight
        freq[ord(ch.upper())] += f * letter_total_weight * 0.5  # caps less common

    # Common punctuation / whitespace
    for ch, w in [(' ', 0.13), ('\n', 0.02), ('\r', 0.005),
                  (',', 0.01), ('.', 0.01), ('"', 0.005),
                  ("'", 0.005), (';', 0.002), (':', 0.002),
                  ('!', 0.001), ('?', 0.001), ('-', 0.003)]:
        freq[ord(ch)] += w

    # Normalize so it sums to 1
    total = sum(freq)
    return [f / total for f in freq]


ENGLISH_FREQ = build_english_freq()


def index_of_coincidence(data: bytes) -> float:
    """Compute the Index of Coincidence for a byte sequence."""
    m = len(data)
    if m < 2:
        return 0.0
    counts = collections.Counter(data)
    numerator = sum(c * (c - 1) for c in counts.values())
    denominator = m * (m - 1)
    return numerator / denominator


def find_key_length(ciphertext: bytes,
                    max_len: int = 60,
                    top_n: int = 8) -> List[Tuple[int, float]]:
    """
    Sweep candidate key lengths 1..max_len.
    For each length L, split ciphertext into L streams and average their IoC.
    Return the top_n candidates sorted by descending IoC score.
    """
    scores: List[Tuple[int, float]] = []
    for L in range(1, max_len + 1):
        streams = [ciphertext[i::L] for i in range(L)]
        avg_ioc = sum(index_of_coincidence(s) for s in streams) / L
        scores.append((L, avg_ioc))

    scores.sort(key=lambda x: x[1], reverse=True)
    return scores[:top_n]


def best_shift_for_stream(stream: bytes) -> int:
    """
    Given a byte stream that is a Caesar cipher (constant shift),
    find the shift s that maximizes the dot product of the stream's
    frequency distribution with ENGLISH_FREQ[v - s mod 256].

    Equivalently: for each candidate shift s, score = sum_v freq[v] * eng[(v-s)%256]
    """
    m = len(stream)
    counts = collections.Counter(stream)

    best_s = 0
    best_score = -1.0

    for s in range(256):
        score = sum(
            (count / m) * ENGLISH_FREQ[(v - s) % 256]
            for v, count in counts.items()
        )
        if score > best_score:
            best_score = score
            best_s = s

    return best_s


def crack_key(ciphertext: bytes, key_length: int) -> bytes:
    """Recover the key given the ciphertext and the key length."""
    key = bytearray(key_length)
    for i in range(key_length):
        stream = ciphertext[i::key_length]
        key[i] = best_shift_for_stream(stream)
    return bytes(key)


def vigenere_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt Vigenere ciphertext with the given key."""
    n = len(key)
    return bytes((c - key[i % n]) % 256 for i, c in enumerate(ciphertext))


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ciphertext_file> [output_file]",
              file=sys.stderr)
        sys.exit(1)

    ciphertext_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) >= 3 else "recovered_from_mystery.txt"

    with open(ciphertext_file, 'rb') as f:
        ciphertext = f.read()

    print(f"len: {len(ciphertext)}")

    # Step 1: Find key length candidates
    candidates = find_key_length(ciphertext, max_len=60, top_n=8)
    print("top candidates:")
    for L, score in candidates:
        print(f"  {L} -> {score:.5f}")

    # Use the top candidate
    key_length = candidates[0][0]
    print(f"trying L= {key_length}")

    # Step 2: Recover key
    key = crack_key(ciphertext, key_length)
    print(f"key hex: {key.hex()}")

    # Step 3: Decrypt and write output
    plaintext = vigenere_decrypt(ciphertext, key)
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"wrote {output_file}")

    # Show a preview
    try:
        preview = plaintext[:500].decode('utf-8', errors='replace')
        print(preview)
    except Exception:
        pass


if __name__ == '__main__':
    main()
