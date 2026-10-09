#!/usr/bin/env python3
"""Writes cases.txt: for each of the 20 builds, 14 file sizes (around the 64-byte block and the 0x4000 boundaries) with a random
16-byte value string (no 0 bytes, as useast's are). Deterministic (seed 20261009)."""
import random
r = random.Random(20261009)
sizes = [0, 1, 3, 4, 5, 63, 64, 65, 127, 128, 1000, 5000, 16384, 50000]
with open('cases.txt', 'w') as f:
    for nn in range(20):
        for sz in sizes:
            f.write('%02d %d %s\n' % (nn, sz, bytes(r.randrange(1, 256) for _ in range(16)).hex()))
