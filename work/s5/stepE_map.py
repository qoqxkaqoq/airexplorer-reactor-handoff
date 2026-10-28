# -*- coding: utf-8 -*-
"""stepE: map all 189 trap sites (dump IL offsets) -> baseline disk offsets."""
import zipfile, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)
base = open('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe', 'rb').read()
PAT = bytes.fromhex('738F4400067A')

# vault index: tok -> rva
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
rawset = set(raw)

mapped = []
missing = []
for n in sorted(z.namelist()):
    if not n.startswith('m_'): continue
    tok = n[2:-4].lower()
    il = z.read(n)[24:]
    pos = 0
    while True:
        off = il.find(PAT, pos)
        if off < 0: break
        pos = off + 1
        ctx = il[max(0, off-4):off+10]  # 14B window
        # candidate disk offsets
        cands = []
        if tok in vault:
            tail = (vault[tok] - 0x1E00) + 20
            cands.append(('vault', tail + off - 8))
        # inline: ilstart unknown -> search 16B window in baseline
        win = il[max(0, off-8):off+8]
        k = base.find(win)
        cnt = base.count(win)
        if k >= 0:
            ilstart = k + (off - max(0, off-8)) - (8 if off >= 8 else 0)
            # recompute precisely: window starts at il[w0], w0=off-8 (if off>=8)
            w0 = off - 8 if off >= 8 else 0
            ilstart = k - w0
            cands.append(('inline', ilstart + off))
        got = None
        for kind, d in cands:
            if 0 <= d <= len(base) - 6 and base[d:d+6] == PAT:
                got = (kind, d)
                break
        if got:
            mapped.append((tok, off, got[0], got[1]))
        else:
            missing.append((tok, off, cands, cnt))

print('mapped:', len(mapped), ' missing:', len(missing))
mtoks = {}
for tok, off, cands, cnt in missing:
    mtoks[tok] = mtoks.get(tok, 0) + 1
print('missing by method:', mtoks)
for tok, off, cands, cnt in missing[:12]:
    print('  %s IL@0x%x cands=%s wincount=%d' % (tok, off, [(k, hex(d)) for k, d in cands], cnt))
# how many raw occurrences are NOT covered by mapped sites (stray pattern bytes elsewhere?)
used = set(d for _, _, _, d in mapped)
stray = [r for r in raw if r not in used]
print('raw occurrences not matched to dump sites:', len(stray), [hex(r) for r in stray[:10]])
import json
json.dump({'mapped': mapped, 'missing': missing, 'stray': stray}, open('/tmp/s5/site_map.json', 'w'))
