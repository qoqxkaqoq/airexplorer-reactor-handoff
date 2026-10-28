# -*- coding: utf-8 -*-
"""step23b: inspect 0600419C/060041A5 — dump body presence + EH from eh_official.zip
(28B CORINFO clauses) + leave-in-try audit."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

zb = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
nb = {n.lower(): n for n in zb.namelist()}
ze = zipfile.ZipFile('/workspace/repo_git/work/eh_official.zip')
ne = {n.lower(): n for n in ze.namelist()}
print('eh zip entries sample:', ze.namelist()[:3], 'total', len(ze.namelist()))

for tok in ('0600419c', '060041a5'):
    print('==', tok, '==')
    k = 'm_' + tok + '.bin'
    if k not in nb:
        print('  body MISSING FROM DUMP')
    else:
        b = zb.read(nb[k])
        tokv, ilsize, maxstack, ehcnt, prex, loctok = struct.unpack_from('<IIIIII', b, 0)
        print('  hdr tok=%08x ilsize=%d maxstack=%d ehcnt=%d prex=%d loctok=%08x' % (tokv, ilsize, maxstack, ehcnt, prex, loctok))
        code = b[24:24 + ilsize]
        leaves = []
        for ins in disasm(code):
            off, name, opb, nxt, tgts = ins
            if name in ('leave', 'fe.leave'):
                leaves.append((off, tgts))
            if name == 'endfinally':
                print('  endfinally @%04x' % off)
        print('  leaves: %d' % len(leaves), ' '.join('%04x' % o for o, t in leaves[:20]))
    # EH from eh zip: try common name patterns
    eh = None
    for cand in ('e_' + tok + '.bin', tok + '.bin', 'm_' + tok + '.eh', tok + '.eh', 'e_' + tok):
        if cand.lower() in ne:
            eh = ze.read(ne[cand.lower()]); print('  eh file:', cand, len(eh)); break
    if eh is None:
        hits = [n for n in ze.namelist() if tok[2:] in n or tok in n]
        print('  eh lookup fail; sample names:', ze.namelist()[:5], 'hits:', hits[:3])
    else:
        ncl = len(eh) // 28 if len(eh) % 28 == 0 else len(eh) // 24
        step = 28 if len(eh) % 28 == 0 else 24
        print('  eh size=%d -> clause=%dB count=%d' % (len(eh), step, ncl))
        trys = []
        for c in range(ncl):
            fl, t_off, t_len, h_off, h_len, cls, pad = struct.unpack_from('<IIIIIII', eh, c * 28) if step == 28 else struct.unpack_from('<IIIIIII', eh, c * 24)
            print('  EH%d flags=%x try=[%04x..%04x) hand=[%04x..%04x) tok=%08x' % (c, fl, t_off, t_off + t_len, h_off, h_off + h_len, cls))
            trys.append((t_off, t_len))
        if k in nb:
            for off, tgts in leaves:
                inside = any(t <= off < t + l for t, l in trys)
                print('  leave@%04x inside_try=%s' % (off, inside))
