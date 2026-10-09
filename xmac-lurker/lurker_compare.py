#!/usr/bin/env python3
"""Compares the code of the 20 psistorm-XMAC-NN libraries function by function (decompiler output from decompile_all.sh).

  lurker_compare.py DIR     DIR holds x00.c .. x19.c

1. The Lurker functions are found by what they call (bundle identity, task_threads, posix_spawn, mach_vm_protect, ...) and their
   normalized code is compared across all 20 builds.
2. Every function of build 05 is searched, by normalized code, in the other 19 builds.
Normalization: global slots become the host offset stored in them, variables are renamed by first appearance, function and data names
and layout-only constants (0x1000 to 0xFFFF) are masked; constants below 0x1000 and above 0xFFFF are kept."""
import collections, hashlib, os, re, sys

def parse(path):
    text = open(path).read()
    return {m.group(1): (int(m.group(2), 16), int(m.group(3)), m.group(4))
            for m in re.finditer(r'// ===== (\S+) @ ([0-9a-f]+)  size (\d+) =====\n(.*?)(?=\n// ===== |\Z)', text, re.S)}

ANCHORS = {
    '_CheckRevision':                        lambda n, s: n == '_CheckRevision',
    'bundle identifier and version':         lambda n, s: '_CFBundleGetIdentifier' in s and not n.startswith('_'),
    'self-delete (dladdr, unlink)':          lambda n, s: '_unlink' in s and '_dladdr' in s and len(s) < 400,
    'Diablo II hook (task_threads)':         lambda n, s: '_task_threads' in s and not n.startswith('_'),
    'prepatch runner (posix_spawn, large)':  lambda n, s: '_posix_spawn' in s and not n.startswith('_') and len(s) > 3000,
    'prefs path helper (.prefs)':            lambda n, s: '.prefs' in s and '/Battle.net' in s,
    'Warcraft III patch (mach_vm_protect)':  lambda n, s: '_mach_vm_protect' in s and not n.startswith('_'),
    'Warcraft III detour target (spawn)':    lambda n, s: '_posix_spawn' in s and not n.startswith('_') and len(s) <= 3000,
}

def find(funcs, pred):
    return [n for n, (a, sz, s) in funcs.items() if pred(n, s)]

def slot_map(hook_text):
    m = {}
    for g in re.finditer(r'(PTR_[A-Za-z0-9_]+|DAT_[0-9a-f]+) = \(?[a-z]*\)?\(?(iVar\d+)\)?( \+ (0x[0-9a-f]+))?U?;', hook_text):
        m[g.group(1)] = 'H[%s]' % (g.group(4) or 'base')
    for g in re.finditer(r'\*\(.*?\)(PTR_[A-Za-z0-9_]+) = \(?[a-z]* ?\)?\(?(iVar\d+) \+ (0x[0-9a-f]+)U?\)?;', hook_text):
        m[g.group(1)] = 'H[%s]' % g.group(3)
    return m

def normalize(text, slots):
    t = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    for k, v in slots.items(): t = t.replace(k, v)
    t = re.sub(r'thunk_FUN_[0-9a-f]+|FUN_[0-9a-f]+', 'FUNC', t)
    t = re.sub(r'LAB_[0-9a-f]+', 'LAB', t)
    t = re.sub(r'(?<![A-Za-z_\[])DAT_[0-9a-f]+', 'DATA', t)
    t = re.sub(r'PTR___stack_chk_guard_[0-9a-f]+', 'STACKGUARD', t)
    t = re.sub(r'PTR_(?:LAB|FUNC)(?:_[0-9a-f]+)?', 'PTRCODE', t)
    t = re.sub(r'\(int\)&UNK_[0-9a-f]+|\(int\)FUNC\b', '(int)CODEADDR', t)
    t = re.sub(r'PTR_[A-Za-z0-9_]+_[0-9a-f]{8}', 'PTRSLOT', t)
    names = {}
    def rename(m):
        names.setdefault(m.group(0), 'v%d' % len(names)); return names[m.group(0)]
    t = re.sub(r'\b(?:local_[0-9a-f]+|uStack_[0-9a-f]+|aiStack_[0-9a-f]+|auStack_[0-9a-f]+|in_stack_[0-9a-f]+|extraout_[A-Z]+|unaff_[A-Z]+|[a-z]{1,3}Var\d+|param_\d+)\b', rename, t)
    def mask(m):
        v = int(m.group(0), 16)
        return m.group(0) if v < 0x1000 else ('0xADDR' if v < 0x10000 else m.group(0))
    return re.sub(r'\s+', ' ', re.sub(r'0x[0-9a-fA-F]+', mask, t))

def main(d):
    libs = {nn: parse(os.path.join(d, 'x%02d.c' % nn)) for nn in range(20)}
    slots = {nn: slot_map(f[find(f, ANCHORS['Diablo II hook (task_threads)'])[0]][2]) for nn, f in libs.items()}
    short = lambda t, nn: hashlib.sha256(normalize(t, slots[nn]).encode()).hexdigest()[:10]
    ok = True
    print('Lurker functions, normalized code compared across the 20 builds:')
    for label, pred in ANCHORS.items():
        groups = collections.defaultdict(list); sizes = set()
        for nn, f in libs.items():
            found = find(f, pred)
            if len(found) != 1: groups['missing/ambiguous'].append(nn); continue
            a, sz, t = f[found[0]]
            groups[short(t, nn)].append(nn); sizes.add(sz)
        same = len(groups) == 1 and 'missing/ambiguous' not in groups
        ok &= same
        print('  %-40s %s  size %s  %s' % (label, 'identical in all 20' if same else 'DIFFERS: %s' % dict(groups), sorted(sizes), ''))
    ref = 5
    H = {nn: {short(t, nn) for n, (a, sz, t) in f.items() if not (n.startswith('_') and sz <= 6)} for nn, f in libs.items()}
    rows = [(n, sz, sum(short(t, ref) in H[nn] for nn in range(20))) for n, (a, sz, t) in libs[ref].items() if not (n.startswith('_') and sz <= 6)]
    print('\nEvery function of build %02d (%d, without 6-byte import stubs) searched in all 20 builds by normalized code:' % (ref, len(rows)))
    print('  identical in all 20: %d' % sum(c == 20 for _, _, c in rows))
    for n, sz, c in sorted(rows):
        if c != 20: print('  not identical: %-14s size %5d  matched in %2d of 20 builds' % (n, sz, c))
    return ok

if __name__ == '__main__':
    sys.exit(0 if main(sys.argv[1]) else 1)
