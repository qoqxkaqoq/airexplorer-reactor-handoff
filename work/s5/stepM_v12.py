# -*- coding: utf-8 -*-
"""stepM: find who stores local 12 (V_12) in 06004523 + EH clauses + who branches to 0x46d."""
import zipfile, sys, struct
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)
il = z.read('m_06004523.bin')[24:]
ins = disasm(il)

# 1) all stores to local 12: stloc.s(0x13) 0x0c  |  fe0e stloc 0x000c
print('=== stores to V_12 (local 12) in 06004523 ===')
idx = {o: i for i, (o, n, b, no, t) in enumerate(ins)}
for i, (o, name, opb, no, tg) in enumerate(ins):
    is_store = False
    if name == 'stloc.s' and opb and opb[0] == 0x0c: is_store = True
    if name == 'fe.stloc' and opb and struct.unpack('<H', opb)[0] == 0x0c: is_store = True
    if name == 'stloc.2' : pass  # local 2, not 12
    if is_store:
        # context: 6 instr before + 3 after
        lo = max(0, i-6)
        print('--- store @IL_%04x ---' % o)
        for j in range(lo, min(len(ins), i+4)):
            m = ins[j]
            print('    IL_%04x: %-14s %s' % (m[0], m[1], m[2].hex() if m[2] else ''))

# 2) who branches to 0x46d
print()
print('=== branch sources targeting 0x46d ===')
for o, name, opb, no, tg in ins:
    for t in tg:
        if t == 0x46d:
            print('  IL_%04x %s -> 0x46d' % (o, name))

# 3) EH clauses for 06004523
print()
print('=== EH clauses 06004523 ===')
zn = zipfile.ZipFile('/workspace/repo_git/work/eh_official.zip')
names = zn.namelist()
cand = [n for n in names if '06004523' in n]
print('files:', cand)
for n in cand:
    d = zn.read(n)
    # 28B CORINFO greeting: Flags, TryOffset, TryLength, HandlerOffset, HandlerLength, ClassToken/FilterOffset
    for k in range(0, len(d) - 27, 28):
        f, to, tl, ho, hl, ct = struct.unpack_from('<IiiiiI', d, k)
        if f == 0 and to == 0: continue
        print('  flags=%d try=0x%x..0x%x handler=0x%x..0x%x classtok=0x%08x' % (
            f, to, to+tl, ho, ho+hl, ct))

# 4) locate newobj ANY followed by stloc V_12 within 06004523 (separated form, any ctor)
print()
print('=== newobj followed by stloc->V_12 (any distance <=6 instr) ===')
for i, (o, name, opb, no, tg) in enumerate(ins):
    if name == 'newobj':
        for j in range(i+1, min(i+7, len(ins))):
            n2 = ins[j][1]; b2 = ins[j][2]
            if n2 == 'stloc.s' and b2 and b2[0] == 0x0c:
                print('  newobj@IL_%04x tok=%s -> stloc V_12 @IL_%04x (gap %d)' % (o, opb.hex(), ins[j][0], j-i))
                break
            if n2 == 'fe.stloc' and b2 and struct.unpack('<H', b2)[0] == 0x0c:
                print('  newobj@IL_%04x tok=%s -> fe.stloc V_12 @IL_%04x (gap %d)' % (o, opb.hex(), ins[j][0], j-i))
                break
            if n2 == 'throw':
                break

# 5) ALL newobj in 06004523 (any target)
print()
print('=== all newobj in 06004523 ===')
for o, name, opb, no, tg in ins:
    if name == 'newobj':
        print('  IL_%04x: newobj %s' % (o, opb.hex()))
