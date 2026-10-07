#!/usr/bin/env python3
"""Tests for psistorm.c and psistorm_ref.py.

  python3 tests/run_tests.py [DIR]

Compiles psistorm.c for each of the 20 builds and checks it against synthetic-vectors.json and against psistorm_ref.py.
With DIR (a directory holding the Mac Diablo 1.09 data forks `Diablo`, `Storm`, `Battle.net`, optionally with .rsrc or .data
appended) it also checks real-client-vector-04.json; the files are Blizzard's and are not in this repository, their SHA-256s are
in the vector. Needs a C compiler."""
import hashlib, json, os, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
sys.path.insert(0, root)
import psistorm_ref as ref

tmp = tempfile.mkdtemp(prefix='psistorm-')
syn = json.load(open(os.path.join(root, 'synthetic-vectors.json')))
paths = []
for k, spec in enumerate(syn['files']):
    p = os.path.join(tmp, 'file%d' % k)
    open(p, 'wb').write(bytes((i * spec['mul'] + spec['add']) % 256 for i in range(spec['length'])))
    paths.append(p)
vs = syn['value_string_hex']
contents = [open(p, 'rb').read() for p in paths]

def build(nn):
    exe = os.path.join(tmp, 'ps%02d' % nn)
    subprocess.check_call(['cc', '-O2', '-Wall', '-DPS_CLI', '-DPS_BUILD_HEADER="psistorm_build_%02d.h"' % nn,
                           os.path.join(root, 'c', 'psistorm.c'), '-I', os.path.join(root, 'c'), '-o', exe])
    return exe

def fmt(v, c, i): return 'version=%08x checksum=%08x info=%s' % (v, c, i.hex())

bad = 0
for case in syn['cases']:
    nn = case['build']
    exe = build(nn)
    want = 'version=%s checksum=%s info=%s' % (case['exe_version'], case['checksum'], case['exe_info_hex'])
    got = subprocess.run([exe, *paths, vs], capture_output=True, text=True).stdout.strip()
    r = ref.check_revision(nn, bytes.fromhex(vs), contents) if nn in (0, 4, 14, 19) else None   # the reference is slow: 4 builds
    ok_ref = r is None or fmt(*r) == want
    print('build %02d: C %s, reference %s' % (nn, 'ok' if got == want else 'MISMATCH', 'skipped' if r is None else ('ok' if ok_ref else 'MISMATCH')))
    bad += (got != want) + (not ok_ref)

if len(sys.argv) > 1:
    v = json.load(open(os.path.join(root, 'real-client-vector-04.json')))
    real = []
    for f in v['files_in_hash_order']:
        found = [os.path.join(sys.argv[1], f['name'] + s) for s in ('', '.rsrc', '.data') if os.path.exists(os.path.join(sys.argv[1], f['name'] + s))]
        if not found: sys.exit('real vector: %s not found in %s' % (f['name'], sys.argv[1]))
        data = open(found[0], 'rb').read()
        if hashlib.sha256(data).hexdigest() != f['sha256']: sys.exit('real vector: %s is not the expected file' % found[0])
        real.append(found[0])
    a = v['answer']
    want = 'version=%08x checksum=%08x info=%s' % (int(a['exe_version'], 16), int(a['checksum'], 16), a['exe_info_hex'])
    got = subprocess.run([build(4), *real, v['challenge']['value_string_hex']], capture_output=True, text=True).stdout.strip()
    print('real client vector (build 04):', 'MATCH' if got == want else 'MISMATCH'); bad += got != want
else:
    print('real client vector: skipped (no file directory given)')
print('FAILURES: %d' % bad)
sys.exit(1 if bad else 0)
