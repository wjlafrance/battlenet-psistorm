#!/usr/bin/env python3
"""Tests for psistorm.c and psistorm_ref.py.

  python3 tests/run_tests.py [DIR]

Compiles psistorm.c for each of the 20 builds and checks it against synthetic-vectors.json and against psistorm_ref.py.
With DIR (a directory holding the data forks of Mac Diablo 1.09 (`Diablo`, `Storm`, `Battle.net`) or Mac Warcraft II 2.02 (`Warcraft II BNE`, `Storm`, `Battle.net`), optionally with .rsrc or .data
appended) it also checks real-client-vector-04.json / real-client-vector-02-w2bn.json (whichever set is there); the files are Blizzard's and are not in this repository, their SHA-256s are
in the vector. A DIR holding Intel Mac Diablo II's `Diablo II` executable (1.14.1.68 or 1.14.3.71, found by SHA-256) also checks the real-client-vector-xmac-d2dv-NN.json files.
The recorded runs of the real psistorm-XMAC libraries (xmac-harness/results.txt, 280 cases) are always checked. Needs a C compiler."""
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
    for vf in ('real-client-vector-04.json', 'real-client-vector-02-w2bn.json'):
        v = json.load(open(os.path.join(root, vf)))
        build_nn = v.get('build', 4)
        real = []
        for f in v['files_in_hash_order']:
            found = [os.path.join(sys.argv[1], f['name'] + s) for s in ('', '.rsrc', '.data') if os.path.exists(os.path.join(sys.argv[1], f['name'] + s))]
            if not found: break
            if hashlib.sha256(open(found[0], 'rb').read()).hexdigest() != f['sha256']: break   # another product's Storm / Battle.net
            real.append(found[0])
        if len(real) < len(v['files_in_hash_order']):
            print('%s: skipped (files not in %s)' % (vf, sys.argv[1])); continue
        a = v['answer']
        want = 'version=%08x checksum=%08x info=%s' % (int(a['exe_version'], 16), int(a['checksum'], 16), a['exe_info_hex'])
        got = subprocess.run([build(build_nn), *real, v['challenge']['value_string_hex']], capture_output=True, text=True).stdout.strip()
        print('real client vector (build %02d, %s):' % (build_nn, v['client']['product'] if 'client' in v else '?'), 'MATCH' if got == want else 'MISMATCH'); bad += got != want
else:
    print('real client vectors: skipped (no file directory given)')

# Intel Mac (XMAC): only the main executable is hashed (file 2 and file 3 are empty) and the exe version is not the file tail,
# so only checksum and exe info are compared with the C code.
empty = os.path.join(tmp, 'empty'); open(empty, 'wb').close()

binaries = {}

def xmac_checksum_info(nn, exe_path, vs_hex):
    if nn not in binaries: binaries[nn] = build(nn)
    out = subprocess.run([binaries[nn], exe_path, empty, empty, vs_hex], capture_output=True, text=True).stdout.strip()
    kv = dict(x.split('=') for x in out.split())
    return int(kv['checksum'], 16), kv['info']

if len(sys.argv) > 1:
    exes = {}
    for dirpath, _, names in os.walk(sys.argv[1]):
        for n in names:
            if n in ('Diablo II', 'Diablo II.data', 'Diablo II.rsrc'):
                p = os.path.join(dirpath, n)
                exes[hashlib.sha256(open(p, 'rb').read()).hexdigest()] = p
    for vf in sorted(f for f in os.listdir(root) if f.startswith('real-client-vector-xmac-d2dv-')):
        v = json.load(open(os.path.join(root, vf)))
        f0 = v['files_in_hash_order'][0]
        if f0['sha256'] not in exes:
            print('%s: skipped (Diablo II %s not in %s)' % (vf, f0['info_plist_CFBundleVersion'], sys.argv[1])); continue
        a = v['answer']
        nn = v['build']
        chk, info = xmac_checksum_info(nn, exes[f0['sha256']], v['challenge']['value_string_hex'])
        r = ref.check_revision_xmac(nn, bytes.fromhex(v['challenge']['value_string_hex']), open(exes[f0['sha256']], 'rb').read(), f0['info_plist_CFBundleVersion'])
        ok = (chk == int(a['checksum'], 16) and info == a['exe_info_hex'] and r[0] == int(a['exe_version'], 16)
              and r[1] == chk and r[2].hex() == info)
        print('real XMAC vector (build %02d, Diablo II %s, server: %s):' % (nn, f0['info_plist_CFBundleVersion'], v['server_result']), 'MATCH' if ok else 'MISMATCH'); bad += not ok

# The real psistorm-XMAC-NN libraries, run on a Mac in a fake Diablo II bundle (xmac-harness/): the hashed file is the harness
# executable followed by `size` bytes of a repeating line.
hx = os.path.join(root, 'xmac-harness')
base = open(os.path.join(hx, 'harness-exe-i386'), 'rb').read()
pad = b'abcdefghij0123456789\n'
cases = good = 0
for line in open(os.path.join(hx, 'results.txt')):
    p = line.split()
    if len(p) < 7 or line.startswith('head:'): continue
    nn, size, vs_hex = int(p[0]), int(p[1]), p[2]
    kv = dict(x.split('=') for x in p[3:])
    f1 = os.path.join(tmp, 'x%02d_%d' % (nn, size))
    open(f1, 'wb').write(base + (pad * (size // len(pad) + 1))[:size])
    chk, info = xmac_checksum_info(nn, f1, vs_hex)
    cases += 1; good += kv['ret'] == '1' and int(kv['checksum'], 16) == chk and kv['info'] == info
print('real psistorm-XMAC libraries (xmac-harness/results.txt): %d of %d cases match the C code' % (good, cases))
bad += (cases != 280) + (good != cases)
print('FAILURES: %d' % bad)
sys.exit(1 if bad else 0)
