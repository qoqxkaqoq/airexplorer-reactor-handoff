# -*- coding: utf-8 -*-
"""step1D: parse runtime fat bodies + EH clauses of 4528/4523/42F4 from official memdump."""
import sys, struct, zipfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm
import dnfile

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

mem = open('/workspace/repo_git/work_a1_pack/memdump/module_text.bin', 'rb').read()
BASE = 0x2000

def rt(tok):
    rid = tok & 0xFFFFFF
    rva = md.MethodDef.rows[rid-1].Rva
    if not rva: return None
    o = rva - BASE
    if o < 0 or o + 12 > len(mem): return None
    b0 = mem[o]
    if (b0 & 3) == 2:
        return (rva, 1, b0 >> 2, None, mem[o+1:o+1+(b0>>2)], b'')
    flags = struct.unpack_from('<H', mem, o)[0]
    hsize = (flags >> 12) * 4
    csize = struct.unpack_from('<I', mem, o+4)[0]
    il = mem[o+hsize:o+hsize+csize]
    eh = mem[o+hsize+csize:]
    return (rva, 0, csize, hsize, il, eh)

def parse_eh(eh, small):
    if small:
        # tiny: no EH
        return []
    hdr = eh[0]
    if (hdr & 0x40):  # fat clauses
        cnt = struct.unpack_from('<I', eh, 4)[0]
        out = []
        for k in range(cnt):
            f, tryo, tryl, ho, hl, ct = struct.unpack_from('<IIIIII', eh, 8 + 24*k)
            out.append((f, tryo, tryl, ho, hl, ct, 'fat'))
        return out
    else:  # small clauses
        cnt = (hdr >> 8)  # hmm: small: DataLength byte-pair (flags<<8 | count)
        cnt = struct.unpack_from('<H', eh, 0)[0] >> 8
        out = []
        for k in range(cnt):
            f, tryo, tryl, ho, hl, ct = struct.unpack_from('<HHBHBI', eh, 4 + 12*k)
            out.append((f, tryo, tryl, ho, hl, ct, 'small'))
        return out

for tok in (0x06004528, 0x06004523, 0x060042F4):
    r = rt(tok)
    if not r:
        print(tok, 'no rva/body'); continue
    rva, tiny, csize, hsize, il, eh = r
    print('== %08X rva=0x%X codesize=%d ehbytes=%d' % (tok, rva, csize, len(eh)))
    if tiny:
        print('   tiny, no EH'); continue
    clauses = parse_eh(eh, False)
    print('   %d EH clauses:' % len(clauses))
    for (f, tryo, tryl, ho, hl, ct, kind) in clauses:
        print('     flags=%X try=[%04X..%04X) handler=[%04X..%04X) tok=%08X (%s)' % (
            f, tryo, tryl, ho, ho+hl, ct, kind))
    # save runtime body for later
    open('/tmp/s5/rt_%08x.bin' % tok, 'wb').write(il)
