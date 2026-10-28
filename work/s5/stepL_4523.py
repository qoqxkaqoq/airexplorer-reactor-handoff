# -*- coding: utf-8 -*-
"""stepL: disassemble 06004523 (GenerateAdaptableExtractor) around IL 0x46d throw point.
Also 06004521 (PlanRunner) @0x48. Identify the exact throw pattern."""
import zipfile, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)

def load(tok):
    d = z.read('m_%s.bin' % tok)
    return d[24:]

def show(tok, lo, hi, label):
    il = load(tok)
    print('=== %s %s ilsize=%d (0x%x) ===' % (tok, label, len(il), len(il)))
    ins = disasm(il)
    print('instructions: %d' % len(ins))
    # validate boundary for target offsets
    offs = set(o for o, _, _, _, _ in ins)
    for t in (0x46d, 0x48, 0x287):
        print('  boundary 0x%x: %s' % (t, t in offs))
    for o, name, opb, no, tg in ins:
        if lo <= o <= hi:
            print('  IL_%04x: %-14s %s' % (o, name, opb.hex() if opb else ''))

# throw point context
show('06004523', 0x430, 0x4b0, 'GenerateAdaptableExtractor around throw 0x46d')
print()
# what is at 0x287 (the recursive call site)
show('06004523', 0x270, 0x2a0, 'GenerateAdaptableExtractor around 0x287')
print()
show('06004521', 0x30, 0x60, 'PlanRunner around 0x48')

# scan 06004523 for ALL throw instructions + newobj patterns
il = load('06004523')
print()
print('=== all throw sites in 06004523 ===')
ins = disasm(il)
for i, (o, name, opb, no, tg) in enumerate(ins):
    if name == 'throw':
        prev = ins[i-1]
        prev2 = ins[i-2] if i >= 2 else None
        print('  IL_%04x throw | prev IL_%04x %s %s | prev2 IL_%04x %s' % (
            o, prev[0], prev[1], prev[2].hex() if prev[2] else '',
            prev2[0] if prev2 else -1, prev2[1] if prev2 else ''))
