# -*- coding: utf-8 -*-
"""step57: extract res[0] ErrorReceiver.ValidatorViewer + res[5] GlobalValidator.FactoryValidator,
then test the VERIFIED seedless PRNG keystream (decrypt_prng.py, v9=0) on them.
Known plaintexts: 0600212A IL=027B3D0C00042A (7B), 06002157 IL=027B4B0C00042A (7B),
06002127=20B, 06002133=946B, 06002145=471B, 06000CEE=581B."""
import struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
import dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
data = open(BASE, 'rb').read()
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables

# --- cor20 resource dir parse (same as step35) ---
cor20 = pe.net.struct
res_rva = cor20.ResourcesRva
res_size = cor20.ResourcesSize
print('resources RVA=0x%X size=0x%X' % (res_rva, res_size))
# --- manifest resources via ManifestResource table (authoritative) ---
base = pe.get_offset_from_rva(res_rva)
entries = []
for mr in mdt.ManifestResource.rows:
    off = mr.Offset
    doff = base + off
    dlen = struct.unpack_from('<I', data, doff)[0]
    entries.append((str(mr.Name), doff + 4, dlen))
for j, (nm, doff, sz) in enumerate(entries):
    print('res[%d] %-48s off=0x%X size=0x%X(%d)' % (j, nm, doff, sz, sz))

TARGET = {'ErrorReceiver.ValidatorViewer': 'res0', 'GlobalValidator.FactoryValidator': 'res5'}
outs = {}
for j, (nm, doff, sz) in enumerate(entries):
    if nm in TARGET:
        tag = TARGET[nm]
        raw = data[doff:doff+sz]
        path = '/workspace/repo_git/work/s5/%s_%s.bin' % (tag, nm.split('.')[-1])
        open(path, 'wb').write(raw)
        outs[tag] = raw
        print('extracted %s: %s %d bytes md5=%s' % (tag, path, len(raw), __import__('hashlib').md5(raw).hexdigest()))

# --- PRNG XOR test ---
sys.path.insert(0, '/workspace/repo_git/work')
import decrypt_prng as P

KNOWN = {
 0x0600212A: bytes.fromhex('027B3D0C00042A'),
 0x06002157: bytes.fromhex('027B4B0C00042A'),
}

def find_all(hay, needle, limit=8):
    hits, start = [], 0
    while len(hits) < limit:
        k = hay.find(needle, start)
        if k < 0: break
        hits.append(k)
        start = k + 1
    return hits

for tag in ('res0', 'res5'):
    raw = outs.get(tag)
    if raw is None: continue
    print('\n=== %s len=%d head=%s' % (tag, len(raw), raw[:16].hex()))
    # decrypt with seedless PRNG keystream (v9=0), full resource
    dec = P.decrypt(raw)
    path = '/workspace/repo_git/work/s5/%s_prng0.dec' % tag
    open(path, 'wb').write(dec)
    for tok, il in KNOWN.items():
        hits = find_all(dec, il)
        print('  %s plaintext 0600%04X %s -> hits in dec: %s' % (tag, tok & 0xFFFFFF, il.hex(), hits))
    # IL-likeness: count of 0x2A (ret) density at 4-byte-aligned offsets? just entropy-ish stats
    from collections import Counter
    c = Counter(dec)
    print('  dec byte stats: 00=%d 2A(ret)=%d 7B(ldfld)=%d top3=%s' % (c[0], c[0x2A], c[0x7B], c.most_common(3)))
    # head preview
    print('  dec head 64B:', dec[:64].hex())
