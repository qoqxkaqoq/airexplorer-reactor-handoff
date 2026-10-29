#!/usr/bin/env python3
# step194: extract 4192 body from il_all.bin and disassemble fully
import struct, sys
sys.path.insert(0, '/root/repo_git/work')
import importlib.util
spec = importlib.util.spec_from_file_location('flat', '/root/repo_git/work/flat.py')
flat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flat)

idx = {}
for line in open('/root/repo_git/work/s5/mem5/il_index.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), p[2], p[3], int(p[4]))  # size, type, name, offset

bin_ = open('/root/repo_git/work/s5/mem5/il_all.bin', 'rb').read()
print('il_all.bin size:', len(bin_))

def get_body(tok):
    size, ty, nm, off = idx[tok]
    return bin_[off:off+size], size, ty, nm

# verify 4192
tok = 0x06004192
body, size, ty, nm = get_body(tok)
print(f'4192 {ty}.{nm} size={size}')
open('/root/work/step194/4192_body.bin','wb').write(body)

# disassemble full
ins = flat.parse(body)
with open('/root/work/step194/4192_disasm.txt','w') as f:
    for off, name, k, op, plen in ins:
        if k == 'tok': s = f'{name} 0x{op:08X}'
        elif k == 'str': s = f'{name} 0x{op:08X}'
        elif k == 'var': s = f'{name} v{op}'
        elif k in ('br1','br4'): s = f'{name} IL_{op:04X}'
        elif k == 'sw': s = f'{name} ({len(op)} tgts) {[hex(t) for t in op[:6]]}'
        elif k == 'i': s = f'{name} {op} (0x{op&0xFFFFFFFF:X})'
        elif k == 'i8': s = f'{name} {op}'
        elif k == 'b': s = f'{name} {op}'
        elif k == 'n': s = name
        else: s = f'{name} {op}'
        f.write(f'{off:04X}: {s}\n')
print('ins count:', len(ins))
