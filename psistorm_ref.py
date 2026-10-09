#!/usr/bin/env python3
"""Reference implementation of psistorm-PMAC-NN CheckRevision in plain Python (standard library only), driven by builds/*.json.
Slow (pure Python) but short; psistorm.c is the same algorithm in C.

    from psistorm_ref import check_revision
    version, checksum, exe_info = check_revision(4, value_string_bytes, [file1_bytes, file2_bytes, file3_bytes])
"""
import json, os, struct

M = 0xFFFFFFFF
_here = os.path.dirname(os.path.abspath(__file__))
_cache = {}


def load_build(nn):
    if nn not in _cache:
        b = json.load(open(os.path.join(_here, 'builds', 'psistorm-PMAC-%02d.json' % nn)))
        _cache[nn] = ([int(x, 16) for x in b['init']], b['rot_c'],
                      [(s['word'], s['tt'], int(s['k'], 16), s['rot']) for s in b['steps']])
    return _cache[nn]


def rotl(x, n):
    x &= M; n &= 31
    return ((x << n) | (x >> (32 - n))) & M if n else x


def f(tt, x, y, z):
    """Any three-input boolean function, applied bitwise: bit j of tt is the result for (x,y,z) = (j&1, j>>1&1, j>>2&1)."""
    r = 0
    for j in range(8):
        if (tt >> j) & 1:
            r |= (x if j & 1 else ~x) & (y if j & 2 else ~y) & (z if j & 4 else ~z)
    return r & M


def compress(build, h, x):
    _, rot_c, steps = build
    def line(st):
        a, b, c, d, e = h
        for word, tt, k, rot in st:
            t = (rotl(a + f(tt, b, c, d) + x[word] + k, rot) + e) & M
            a, e, d, c, b = e, d, rotl(c, rot_c), b, t
        return a, b, c, d, e
    al, bl, cl, dl, el = line(steps[:80])
    ar, br, cr, dr, er = line(steps[80:])
    t = (h[1] + cl + dr) & M
    return [t, (h[2] + dl + er) & M, (h[3] + el + ar) & M, (h[4] + al + br) & M, (h[0] + bl + cr) & M]


def hash_bytes(build, data):
    """MD framing: 64-byte blocks, little-endian words, 0x80, zeros, 64-bit little-endian bit count; state words little-endian."""
    h = list(build[0])
    data = data + b'\x80' + b'\0' * ((0x37 - len(data)) & 0x3f) + struct.pack('<Q', len(data) * 8)
    for i in range(0, len(data), 64):
        h = compress(build, h, struct.unpack('<16I', data[i:i + 64]))
    return struct.pack('<5I', *h)


def hmac(build, key16, data):
    ipad = bytes(0x36 ^ (key16[i] if i < 16 else 0) for i in range(64))
    opad = bytes(0x5c ^ (key16[i] if i < 16 else 0) for i in range(64))
    return hash_bytes(build, opad + hash_bytes(build, ipad + data))


def shuffle_value_string(vs):
    """For each input byte from the last to the first: multiply the 16-byte little-endian buffer by 255, add (byte - 1). None if it needs more than 16 bytes."""
    buf = [0] * 16; pos = 0
    for x in range(len(vs), 0, -1):
        carry = 0
        for i in range(pos):
            t = buf[i] * 255 + carry; buf[i] = t & 0xFF; carry = (t >> 8) & 0xFF
        if carry:
            if pos >= 16: return None
            buf[pos] = carry; pos += 1
        adder = (vs[x - 1] - 1) & 0xFFFF
        i = 0
        while i < pos and adder > 0:
            buf[i] = (buf[i] + adder) & 0xFF
            adder = 1 if buf[i] < adder else 0
            i += 1
        if adder > 0:
            if pos >= 16: return None
            buf[pos] = adder & 0xFF; pos += 1
    return bytes(buf)


def digest_shuffle(d16):
    """Divide the 16-byte little-endian number by 255 repeatedly, emitting remainder + 1, until it is zero."""
    n = int.from_bytes(d16, 'little'); out = bytearray()
    while n:
        n, r = divmod(n, 255); out.append(r + 1)
    return bytes(out)


def check_revision(nn, value_string, files):
    """Returns (exe_version, checksum, exe_info bytes), or None if the value string does not fit the 16-byte seed."""
    seed = shuffle_value_string(value_string)
    if seed is None:
        return None
    digest = hmac(load_build(nn), seed, b''.join(files))
    tail = files[0][-4:].rjust(4, b'\0')
    return struct.unpack('<I', tail)[0], struct.unpack('<I', digest[:4])[0], digest_shuffle(digest[4:20])


def bundle_version_dword(version):
    """'1.14.3.71' -> 0x010E0347: the four components as bytes, the first in the top byte."""
    a, b, c, d = (int(x) for x in version.split('.'))
    return (a << 24) | (b << 16) | (c << 8) | d


def check_revision_xmac(nn, value_string, exe_bytes, bundle_version):
    """Intel Mac (psistorm-XMAC-NN, Diablo II 1.14.x): the same hash over the main executable alone (file 2 and file 3 are not
    hashed); the exe version is the app's CFBundleVersion, not the file tail. Returns (exe_version, checksum, exe_info bytes),
    or None if the value string does not fit."""
    r = check_revision(nn, value_string, [exe_bytes])
    if r is None:
        return None
    return bundle_version_dword(bundle_version), r[1], r[2]
