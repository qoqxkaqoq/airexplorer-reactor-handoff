#!/usr/bin/env python3
# a11_pe.py — shared helpers: PE parse (sections/exports/RVA->file), nearest-export resolve, capstone disasm.
import struct

class PE:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        d = self.d
        self.path = path
        self.e_lfanew = struct.unpack_from('<I', d, 0x3c)[0]
        self.machine = struct.unpack_from('<H', d, self.e_lfanew+4)[0]
        self.nsec = struct.unpack_from('<H', d, self.e_lfanew+6)[0]
        opt = self.e_lfanew + 24
        self.opt = opt
        self.magic = struct.unpack_from('<H', d, opt)[0]
        self.bits = 64 if self.magic == 0x20b else 32
        self.imagebase = struct.unpack_from('<Q', d, opt+24)[0] if self.bits==64 else struct.unpack_from('<I', d, opt+28)[0]
        self.sizeopt = struct.unpack_from('<H', d, self.e_lfanew+20)[0]
        self.entry = struct.unpack_from('<I', d, opt+16)[0]
        sec0 = opt + self.sizeopt
        self.sections = []
        for i in range(self.nsec):
            o = sec0 + 40*i
            nm = d[o:o+8].rstrip(b'\0').decode('ascii','replace')
            vs, va, rs, ra = struct.unpack_from('<IIII', d, o+8)
            self.sections.append((nm, va, vs, ra, rs))
        self.exports = []
        self._parse_exports()
    def rva2off(self, rva):
        for nm, va, vs, ra, rs in self.sections:
            if va <= rva < va + max(vs, rs):
                return ra + (rva - va)
        return None
    def _parse_exports(self):
        d = self.d
        dd = self.opt + (112 if self.bits==64 else 96)
        erva, esz = struct.unpack_from('<II', d, dd)  # data dir 0: export dir rva,size
        if not erva: return
        o = self.rva2off(erva)
        nfun, nnam = struct.unpack_from('<II', d, o+20)[0:2]
        ordbase = struct.unpack_from('<I', d, o+16)[0]
        afrv, anrv, aorv = struct.unpack_from('<III', d, o+28)
        af = self.rva2off(afrv); ao = self.rva2off(aorv); an = self.rva2off(anrv)
        names = {}
        for i in range(nnam):
            nrva = struct.unpack_from('<I', d, an+4*i)[0]
            no = self.rva2off(nrva)
            end = d.index(b'\0', no)
            nmv = d[no:end].decode('ascii','replace')
            ordv = struct.unpack_from('<H', d, ao+2*i)[0]
            frva = struct.unpack_from('<I', d, af+4*ordv)[0]
            names[frva] = nmv
        self.exports = sorted(names.items())
    def nearest(self, rva):
        best = None
        for frva, nm in self.exports:
            if frva <= rva and (best is None or frva > best[0]):
                best = (frva, nm)
        if best is None: return ('?', 0, rva)
        return (best[1], best[0], rva - best[0])
    def read_rva(self, rva, n):
        o = self.rva2off(rva)
        if o is None: return None
        return self.d[o:o+n]

def disasm(pe, rva, back=0x40, fwd=0x80, base=None):
    """disassemble [rva-back, rva+fwd); annotate rva with '<<<' """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_64 if pe.bits==64 else CS_MODE_32)
    start = rva - back
    o = pe.rva2off(start)
    if o is None: return 'rva %x unmapped' % rva
    code = pe.d[o:o+back+fwd]
    out = []
    for ins in md.disasm(code, start):
        mark = ' <<< HERE' if ins.address <= rva < ins.address + ins.size else ''
        b = base + ins.address if base else ins.address
        nm, fr, off = pe.nearest(ins.address)
        out.append('%016x  %-34s %s!%s+%x%s' % (b, ins.mnemonic + ' ' + ins.op_str, pe.path.split('\\')[-1], nm, off, mark))
    return '\n'.join(out)
