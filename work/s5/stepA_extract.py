# -*- coding: utf-8 -*-
"""stepA: extract key method bodies from dump, locate 68 newobj TemplatePredicate+throw
points in DefineSetSet (06004528), dump context around each; global scan for the pattern."""
import zipfile, struct, io, sys

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)
names = set(z.namelist())

def body(tok):
    n = 'm_%s.bin' % tok
    if n not in names: return None
    raw = z.read(n)
    # header 24B: [tok:4][ilsize:4][maxstack:4][ehcnt:4][locals@16][x@20]
    tok_, ilsize, maxstack, ehcnt = struct.unpack_from('<IIII', raw, 0)
    locals_ = struct.unpack_from('<I', raw, 16)[0]
    il = raw[24:]
    assert len(il) == ilsize, (tok, len(il), ilsize)
    return dict(tok=tok, ilsize=ilsize, maxstack=maxstack, ehcnt=ehcnt, locals=locals_, il=il)

dss = body('06004528')
print('DefineSetSet 06004528: ilsize=%d maxstack=%d ehcnt=%d locals=0x%08x' %
      (dss['ilsize'], dss['maxstack'], dss['ehcnt'], dss['locals']))

PAT = bytes.fromhex('738F4400067A')  # newobj 0600448F; throw
offs = []
i = 0
il = dss['il']
while True:
    j = il.find(PAT, i)
    if j < 0: break
    offs.append(j)
    i = j + 1
print('patch points in 06004528 IL: %d' % len(offs))

# context: 24B before each point, decode nothing fancy, just hex + a few common opcodes
def snip(il, off, back=20, fwd=10):
    s = max(0, off - back)
    return il[s:off].hex() + ' [' + il[off:off+len(PAT)].hex() + '] ' + il[off+len(PAT):off+len(PAT)+fwd].hex()

for k, off in enumerate(offs[:8] + offs[-4:]):
    print('%2d IL@0x%04x: %s' % (k, off, snip(il, off)))

# verify against baseline disk tail: RVA 0x41FF88 fo 0x41E188 tail = fo+20, tail = IL[8:]
base = open('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe', 'rb').read()
TAIL = 0x41E19C
ok = bad = 0
for off in offs:
    if off < 8: continue
    d = base[TAIL + off - 8: TAIL + off - 8 + 6]
    if d == PAT: ok += 1
    else:
        bad += 1
        print('MISMATCH IL@0x%04x disk@0x%x: %s' % (off, TAIL + off - 8, d.hex()))
print('baseline tail verify: ok=%d bad=%d' % (ok, bad))

# what is 0600448F (TemplatePredicate ctor)?
for t in ('0600448F',):
    b = body(t)
    if b:
        print('%s: ilsize=%d maxstack=%d ehcnt=%d il=%s' % (t, b['ilsize'], b['maxstack'], b['ehcnt'], b['il'][:96].hex()))

# global scan across all dumps
hit = {}
for n in z.namelist():
    if not n.startswith('m_'): continue
    raw = z.read(n)
    ilb = raw[24:]
    c = ilb.count(PAT)
    if c: hit[n] = c
print('global scan: %d methods contain the pattern, total %d' % (len(hit), sum(hit.values())))
for k in sorted(hit): print('  %s x%d' % (k, hit[k]))
