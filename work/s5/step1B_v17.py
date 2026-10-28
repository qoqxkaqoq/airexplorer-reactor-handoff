# -*- coding: utf-8 -*-
"""step1B: full v17 writer list in 4528 with case-block membership + guarding branches."""
import sys, struct, zipfile, bisect
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
il28 = z.read('m_06004528.bin')[24:]
ins = disasm(il28)
idx = {o: i for i, (o, *_ ) in enumerate(ins)}

# switch casemap (case index -> target)
SW = 0x45B1
i = idx[SW]
off, nm, opb, nxt, tg = ins[i]
casemap = tg  # case k -> target
t2c = {}
for k, t in enumerate(casemap):
    t2c.setdefault(t, []).append(k)
ts = sorted(t2c)
def block_of(o):
    k = bisect.bisect_right(ts, o) - 1
    return ts[k] if k >= 0 else None
def cases_of(o):
    return t2c.get(block_of(o))

def ctx(i, n=10):
    out = []
    k = i - 1
    while k >= 0 and len(out) < n:
        p = ins[k]
        out.append('%04X %s %s' % (p[0], p[1], p[2].hex()))
        k -= 1
    return ' | '.join(reversed(out))

print('== writers of v17 ==')
for ii, (off, nm, opb, nxt, tg) in enumerate(ins):
    is17 = (nm == 'fe.stloc' and opb == b'\x17\x00') or (nm == 'stloc.s' and opb == b'\x17')
    if not is17: continue
    # feed value
    feed = []
    k = ii - 1
    while k >= 0 and len(feed) < 3:
        p = ins[k]
        feed.append('%s %s' % (p[1], p[2].hex()))
        if p[1].startswith('ldc') or p[1] == 'fe.ldloc' or p[1].startswith('ldloc') or p[1] == 'add':
            break
        k -= 1
    # absolute value?
    val = None
    if feed and feed[0].startswith('ldc.i4 '):
        v = int(feed[0].split()[1], 16)
        val = struct.unpack('<I', struct.pack('<I', v))[0]
    bo = block_of(off)
    print('@%04X block@%s cases=%s val=%s <- %s' % (
        off, ('%04X' % bo) if bo is not None else 'None', t2c.get(bo), ('%d' % val) if val is not None else '?',
        ' | '.join(reversed(feed))))

print()
print('== conditional branches whose target or fallthrough leads near a v17=34/35 store ==')
# direct: find stores with val 34/35 first
w35 = []
for ii, (off, nm, opb, nxt, tg) in enumerate(ins):
    is17 = (nm == 'fe.stloc' and opb == b'\x17\x00') or (nm == 'stloc.s' and opb == b'\x17')
    if not is17: continue
    k = ii - 1
    p = ins[k]
    if p[1] == 'ldc.i4':
        v = struct.unpack('<I', opb if False else p[2])[0] if len(p[2]) == 4 else 0
        if v in (34, 35, 0x22, 0x23):
            w35.append((off, v, ii))
print('absolute v17=34/35 stores:', [(hex(o), v) for o, v, _ in w35] or 'NONE')

# v0f writers landing such that v0f+C=35 possible: skip; check adds to v17 with v0f source
print()
print('== v17 <- (v0f + C) sites ==')
for ii, (off, nm, opb, nxt, tg) in enumerate(ins):
    is17 = (nm == 'fe.stloc' and opb == b'\x17\x00') or (nm == 'stloc.s' and opb == b'\x17')
    if not is17: continue
    k = ii - 1
    p = ins[k]
    if p[1] != 'add': continue
    c = None
    if k-1 >= 0 and ins[k-1][1] == 'ldc.i4':
        c = struct.unpack('<i', ins[k-1][2])[0]
        src = 'v0f'
        if k-2 >= 0 and ins[k-2][1] == 'fe.ldloc' and ins[k-2][2] != b'\x0f\x00':
            src = 'other'
    else:
        src = 'v0f?'
        c = None
    bo = block_of(off)
    print('@%04X block@%s %s + %s -> v17' % (off, ('%04X' % bo) if bo is not None else 'None', src, hex(c) if c is not None else '?'))
