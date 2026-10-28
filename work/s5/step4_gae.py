# -*- coding: utf-8 -*-
"""step4: GAE(06004523) catch state machine full trace + 452E switch + 0600448F ctor chain."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}

def dump_body(tok):
    k = 'm_' + tok + '.bin'
    if k not in names:
        return None
    b = z.read(names[k])
    tokv, ilsize, maxstack, ehcnt, prex, loctok = struct.unpack('<6I', b[:24])
    return b[24:24+ilsize], (tokv, ilsize, maxstack, ehcnt, prex, loctok)

print('== 452E switch targets ==')
il, _ = dump_body('0600452e')
for ins in disasm(il):
    if ins[1] == 'switch' and ins[4]:
        tg = ins[4]
        print('  switch@%04X %d cases: %s' % (ins[0], len(tg), ' '.join('%04X' % t for t in tg)))

print('== GAE 06004523 in dump? ==')
gae = dump_body('06004523')
if gae:
    il, hdr = gae
    print('  ilsize=%d eh=%d loctok=%08x' % (hdr[1], hdr[3], hdr[5]))
else:
    print('  NOT IN DUMP -> use memdump')

print('== 0600448F (TemplatePredicate ctor) ==')
b8f = dump_body('0600448f')
if b8f:
    for ins in disasm(b8f[0]):
        print('  ' + fmt(ins))

print('== DefineActiveEvent / DirectDefinition tokens lookup ==')
for tok in ('06004524', '06004525', '06004526', '06004527', '06004529', '0600452a', '0600452b'):
    k = 'm_' + tok + '.bin'
    print('  %s dump: %s' % (tok, 'YES' if k in names else 'no'))

# 0600448F memdump body calls which tokens?
# memdump: work_a1_pack/memdump/module_text.bin, mem[i] <-> RVA 0x2000+i
import os
MEM = '/workspace/repo_git/work_a1_pack/memdump/module_text.bin'
if os.path.exists(MEM):
    mem = open(MEM, 'rb').read()
    print('== memdump loaded %d bytes (VA 0x400000 base, .text starts RVA 0x2000) ==' % len(mem))

    def mem_body(rva, maxsz=4096):
        # method body at RVA: tiny (b&3==2, size=b>>2) or fat
        off = rva - 0x2000
        if off < 0 or off >= len(mem):
            return None, None
        b0 = mem[off]
        if b0 & 3 == 2:
            sz = b0 >> 2
            return mem[off+1:off+1+sz], ('tiny', sz)
        flags_size = struct.unpack_from('<I', mem, off)[0]
        sz = (flags_size >> 8) & 0xFFFFFF
        hsz = (flags_size & 0xF) * 4 if False else 12
        hdrsz = ((flags_size >> 12) & 0xF) * 4
        return mem[off+hdrsz:off+hdrsz+sz], ('fat', sz, 'eh' if flags_size & 8 else '')

    # 0600448F rva=0x41cbac (vault says). check memdump RVA slot via dnfile
    import dnfile
    pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
    md = pe.net.mdtables
    for tok in (0x0600448f, 0x06004523, 0x06004550, 0x06004559, 0x06004566, 0x0600452e, 0x06004528):
        r = md.MethodDef.rows[(tok & 0xFFFFFF) - 1]
        rva = r.Rva
        print('  %08x diskrva=0x%x' % (tok, rva), end='')
        if rva:
            body, info = mem_body(rva)
            print(' membody=%s %s' % (info, body[:16].hex() if body else ''))
        else:
            print(' membody=-')
