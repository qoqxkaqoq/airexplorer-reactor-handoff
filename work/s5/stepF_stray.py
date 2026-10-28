# -*- coding: utf-8 -*-
"""stepF: analyze duplicate mapped offsets + stray raw occurrences."""
import zipfile, json, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)
base = open('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe', 'rb').read()
sm = json.load(open('/tmp/s5/site_map.json'))
mapped, missing, stray = sm['mapped'], sm['missing'], sm['stray']

vault = {}
for line in open('/workspace/repo_git/work/c2_pack/vault_index.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) > 4 and p[1].lower().startswith('0600'):
        vault[p[1].lower()] = int(p[0], 16)

from collections import Counter
dsk = Counter(d for _, _, _, d in mapped)
dups = {d: c for d, c in dsk.items() if c > 1}
print('unique disk offsets from mapping:', len(dsk), ' duplicated offsets:', len(dups))
for d, c in list(dups.items())[:10]:
    toks = [(t, hex(o), k) for t, o, k, dd in mapped if dd == d]
    print('  dup @0x%x x%d: %s' % (d, c, toks))
    # do those methods have identical IL at the site?
    ils = []
    for t, o, k, _ in [(t, o, k, dd) for t, o, k, dd in mapped if dd == d]:
        il = z.read('m_%s.bin' % t)[24:]
        ils.append((t, il[max(0,o-8):o+14].hex()))
    same = len(set(x[1] for x in ils)) == 1
    print('     identical context:', same, ils[0][1])

print()
print('=== strays ===')
# reverse map: stray -> is it a vault tail offset of some method+trap?
trap_by_tok = {}
for n in z.namelist():
    if n.startswith('m_'):
        il = z.read(n)[24:]
        offs = []
        pos = 0
        while True:
            j = il.find(bytes.fromhex('738F4400067A'), pos)
            if j < 0: break
            offs.append(j); pos = j + 1
        if offs: trap_by_tok[n[2:-4].lower()] = offs
for s in stray:
    hit = None
    for tok, offs in trap_by_tok.items():
        if tok in vault:
            tail = (vault[tok] - 0x1E00) + 20
            for o in offs:
                if tail + o - 8 == s:
                    hit = (tok, hex(o)); break
        if hit: break
    # what's around it?
    print('stray @0x%x  rev-vault-tail: %s  ctx: %s' % (s, hit, base[s-8:s].hex() + '|' + base[s:s+14].hex()))
