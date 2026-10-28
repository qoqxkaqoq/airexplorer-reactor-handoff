# -*- coding: utf-8 -*-
"""step23: inspect 0600419C (DefineEfficientProfiler) + 060041A5 (VerifyProcessor) dump bodies:
presence, ilsize, eh count, EH clauses, leave/endfinally audit; also parse on-disk stub state."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}

for tok in ('0600419c', '060041a5'):
    k = 'm_' + tok + '.bin'
    print('==', tok, '==')
    if k not in names:
        print('  MISSING FROM DUMP')
        continue
    b = z.read(names[k])
    ilsize, maxstack, ehcnt, prex, loctok = struct.unpack_from('<IIIIQ', b, 4)
    print('  ilsize=%d maxstack=%d ehcnt=%d prex=%d loctok=%016x' % (ilsize, maxstack, ehcnt, prex, loctok))
    code = b[24:24 + ilsize]
    # audit leave / endfinally / eh ranges
    leaves, endfins = [], []
    for ins in disasm(code):
        off, name, opb, nxt, tgts = ins
        if name == 'leave' or name == 'fe.leave':
            leaves.append((off, tgts))
        if name == 'endfinally':
            endfins.append(off)
    print('  leaves=%d endfinally=%d' % (len(leaves), len(endfins)))
    if ehcnt:
        start = 24 + ilsize
        if start % 4: start += 4 - (start % 4)
        for c in range(ehcnt):
            fl, t_off, t_len, h_off, h_len, cls = struct.unpack_from('<IIIIII', b, start + c * 24)
            print('  EH%d flags=%x try=[%04x..%04x) hand=[%04x..%04x) cls=%08x' % (c, fl, t_off, t_off + t_len, h_off, h_off + h_len, cls))
        # check leaves inside try ranges
        for off, tgts in leaves:
            inside = any(t_off <= off < t_off + t_len for (t_off, t_len) in
                         [(struct.unpack_from('<IIIIII', b, start + c * 24)[1],
                           struct.unpack_from('<IIIIII', b, start + c * 24)[2]) for c in range(ehcnt)])
            print('  leave@%04x inside_try=%s targets=%s' % (off, inside, [hex(t) for t in tgts[:3]]))
    # first 40 bytes of IL
    print('  il head:', code[:40].hex())

# locals token check: what does loctok point to
print()
print('== on-disk method RVA/state ==')
pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables
for tok in (0x0600419c, 0x060041a5):
    r = md.MethodDef.rows[(tok & 0xFFFFFF) - 1]
    print('  %08x %s rva=0x%x implflags=%x' % (tok, str(r.Name), r.Rva, r.ImplFlags))
