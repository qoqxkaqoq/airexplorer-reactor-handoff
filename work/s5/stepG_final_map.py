# -*- coding: utf-8 -*-
"""stepG: definitive site mapping. Window-match every dump site, prefer vault RVA,
resolve tripwires (6B bodies) to unclaimed strays. Output final patch list."""
import zipfile, json, sys
Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)
base = open('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe', 'rb').read()
PAT = bytes.fromhex('738F4400067A')

vault = {}
for line in open('/workspace/repo_git/work/c2_pack/vault_index.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) > 4 and p[1].lower().startswith('0600'):
        vault[p[1].lower()] = int(p[0], 16)

raw = []
i = 0
while True:
    j = base.find(PAT, i)
    if j < 0: break
    raw.append(j); i = j + 1

# preload all dump ILs (tok_lower -> il)
ilmap = {}
for n in z.namelist():
    if not n.startswith('m_'): continue
    ilmap[n[2:-4].lower()] = z.read(n)[24:]

# collect all dump sites
sites = []  # (tok, off, ilsize)
for tok, il in ilmap.items():
    pos = 0
    while True:
        off = il.find(PAT, pos)
        if off < 0: break
        pos = off + 1
        sites.append((tok, off, len(il)))

claimed = {}   # disk_off -> (tok, off, how)
unresolved = []
for tok, off, ilsize in sites:
    dil = ilmap[tok]
    w0 = max(0, off - 8)
    win = dil[w0:off + 8]
    occ = []
    k = 0
    while True:
        j = base.find(win, k)
        if j < 0: break
        occ.append(j + (off - w0)); k = j + 1
    got = None
    if tok in vault:
        exp = (vault[tok] - 0x1E00) + 20 + off - 8
        if exp in occ: got = (exp, 'vault')
    if got is None:
        if len(occ) == 1:
            got = (occ[0], 'uniq-win')
        elif len(occ) > 1:
            # check which occurrences are already claimed by vault-mapped sites of OTHER tokens
            free = [o for o in occ if o not in claimed]
            if len(free) == 1:
                got = (free[0], 'free-win')
            else:
                unresolved.append((tok, off, occ, free))
    if got:
        claimed[got[0]] = (tok, off, got[1])

print('sites: %d  claimed: %d  unresolved: %d' % (len(sites), len(claimed), len(unresolved)))
for tok, off, occ, free in unresolved[:20]:
    print('  UNRESOLVED %s IL@0x%x occ=%s free=%s' % (tok, off, [hex(x) for x in occ], [hex(x) for x in free]))

used = set(claimed)
stray = [r for r in raw if r not in used]
print('raw: %d  unclaimed strays: %d' % (len(raw), len(stray)))
for s in stray:
    print('  STRAY @0x%06x pre=%s post=%s' % (s, base[s-6:s].hex(), base[s+6:s+12].hex()))

json.dump({'claimed': {str(k): v for k, v in claimed.items()},
           'unresolved': [(t, o, occ, free) for t, o, occ, free in unresolved],
           'stray': stray}, open('/tmp/s5/site_map2.json', 'w'))
