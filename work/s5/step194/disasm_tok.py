#!/usr/bin/env python3
import struct, sys, importlib.util
spec = importlib.util.spec_from_file_location('flat', '/root/repo_git/work/flat.py')
flat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flat)

idx = {}
for line in open('/root/repo_git/work/s5/mem5/il_index.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        try: idx[int(p[0],16)] = (int(p[1]), p[2], p[3], int(p[4]))
        except: pass
bin_ = open('/root/repo_git/work/s5/mem5/il_all.bin','rb').read()

def disasm(tok, out=None):
    if tok not in idx: return print(f'{tok:08X} NOT IN DUMP')
    size, ty, nm, off = idx[tok]
    body = bin_[off:off+size]
    ins = flat.parse(body)
    lines = [f'=== 0x{tok:08X} {ty}.{nm} ({size}B, {len(ins)} ins) ===']
    for o, name, k, op, plen in ins:
        if k == 'tok': s = f'{name} 0x{op:08X}'
        elif k in ('br1','br4'): s = f'{name} IL_{op:04X}'
        elif k == 'var': s = f'{name} v{op}'
        elif k == 'i': s = f'{name} {op} (0x{op&0xFFFFFFFF:X})'
        elif k == 'n': s = name
        else: s = f'{name} {op}'
        lines.append(f'{o:04X}: {s}')
    txt = '\n'.join(lines)
    if out: open(out,'w').write(txt)
    else: print(txt)

if __name__ == '__main__':
    for a in sys.argv[1:]:
        disasm(int(a,16))
