# -*- coding: utf-8 -*-
"""step25: sanity-check m1b_full.exe vs baseline — sections, entry, cor20, payload integrity."""
import hashlib
import dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
M1B = '/workspace/repo_git/tools3/unpacker/out/m1b_full.exe'

def info(p):
    pe = dnfile.dnPE(p)
    secs = [(str(s.Name).rstrip('\x00'), s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
            for s in pe.sections]
    return pe, secs, len(open(p, 'rb').read())

pb, sb, lb = info(BASE)
pm, sm, lm = info(M1B)
print('size: baseline=%d m1b=%d' % (lb, lm))
print('%-6s %-30s %-30s' % ('sec', 'baseline', 'm1b'))
for i in range(max(len(sb), len(sm))):
    a = sb[i] if i < len(sb) else None
    b = sm[i] if i < len(sm) else None
    fa = '%s va=%06x vs=%06x raw=%06x/%06x' % a if a else '-'
    fb = '%s va=%06x vs=%06x raw=%06x/%06x' % b if b else '-'
    print('%-6s %-30s %-30s' % (i, fa, fb))
print('entry: baseline=%08x m1b=%08x' % (pb.optional_hdr.AddressOfEntryPoint, pm.optional_hdr.AddressOfEntryPoint))

# cor20 resources (the 6 pseudo resources / payload live there?)
c20b = pb.net.struct, pb.net.metadata
c20m = pm.net.struct
print('cor20: baseline resources_rva=%08x size=%x' % (pb.net.struct.Resources_Rva, pb.net.struct.Resources_Size))
print('cor20: m1b       resources_rva=%08x size=%x' % (pm.net.struct.Resources_Rva, pm.net.struct.Resources_Size))

# compare .text payload region byte-by-byte in chunks (report first differences)
bdata = open(BASE, 'rb').read()
mdata = open(M1B, 'rb').read()
sec_b = {s[0]: s for s in sb}
sec_m = {s[0]: s for s in sm}
for name in sec_b:
    if name not in sec_m:
        print('section %s MISSING in m1b' % name)
        continue
    nb, nm = sec_b[name], sec_m[name]
    rb = bdata[nb[3]:nb[3] + nb[4]]
    rm = mdata[nm[3]:nm[3] + nm[4]]
    n = min(len(rb), len(rm))
    diffs = 0
    first = -1
    for i in range(n):
        if rb[i] != rm[i]:
            diffs += 1
            if first < 0:
                first = i
    print('sec %-8s rawsize b=%d m=%d diffbytes=%d first@%x' % (name, len(rb), len(rm), diffs, first if first >= 0 else 0))
