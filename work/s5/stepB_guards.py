# -*- coding: utf-8 -*-
"""stepB: decode guards for the 68 traps in DefineSetSet + V_12 logic in 06004192 + 060041EE body."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

Z = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(Z)
def il_of(tok):
    raw = z.read('m_%s.bin' % tok)
    return raw[24:]

PAT = bytes.fromhex('738F4400067A')

il = il_of('06004528')
ins = disasm(il)
# validate: pattern offsets are instruction starts
starts = set(i[0] for i in ins)
offs = []
i = 0
while True:
    j = il.find(PAT, i)
    if j < 0: break
    offs.append(j); i = j + 1
bad = [o for o in offs if o not in starts]
print('linear decode: %d instrs, pattern starts matched: %d/%d' % (len(ins), len(offs)-len(bad), len(offs)))

# branch-target map: target -> list of (src_off, src_name)
tgts = {}
for off, nm, opb, nxt, tg in ins:
    for t in tg:
        tgts.setdefault(t, []).append((off, nm))

print('=== trap incoming branches (each trap: who branches to newobj or into its args?) ===')
for o in offs:
    incomers = []
    for probe in range(o-24, o+6):
        for so, sn in tgts.get(probe, []):
            incomers.append((so, sn, probe))
    # dedupe, keep nearest before pattern
    txt = '; '.join('%04X %s->%04X' % (s, n, p) for s, n, p in incomers)
    print('trap@%04X in: %s' % (o, txt if txt else '<none>'))

# dump source context of the first 6 traps' incoming branches
print('=== source context for first traps ===')
byoff = {i[0]: i for i in ins}
seq = [i[0] for i in ins]
idx_of = {o: k for k, o in enumerate(seq)}
seen_src = set()
for o in offs[:6] + offs[32:34]:
    for probe in range(o-24, o+6):
        for so, sn in tgts.get(probe, []):
            if so in seen_src: continue
            seen_src.add(so)
            k = idx_of[so]
            print('--- src %04X for trap@%04X (probe %04X) ---' % (so, o, probe))
            for kk in range(max(0, k-6), k+2):
                print('   ', fmt(ins[kk]))
