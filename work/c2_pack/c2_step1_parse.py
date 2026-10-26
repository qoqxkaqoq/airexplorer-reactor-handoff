#!/usr/bin/env python3
# c2_step1_parse.py — C-line step 2: parse dec_Viewer.bin entry table, validate against
# the official JIT dump (dump_official_16598.zip, same md5 as baseline), write
# vault_entries/ + vault_index.tsv + c2_step1.json
#
# Entry rhythm (reverse-engineered this session, validated below):
#   [RVA:4][t1:4][fat0:4 = maxstack<<16|fatflags16][t2:4][locals:4 (0 or 0x11xxxxxx)]
#   [body8:8 = ticket4 + realIL chunk4]
#   then a run of blocks [ptr:4][ndw:4][ndw dwords] until the next entry's RVA.
# Entry length = distance to next validated anchor (observed 48..232+).
import struct, sys, json, zipfile, collections

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
sys.path.insert(0, W + r'\work_a1')
import mref

EXE = W + r'\airexplorer-reactor-handoff\exes\AirExplorer_baseline_verified.exe'
VAULT = W + r'\work_a1\dec_Viewer.bin'
ZIP = W + r'\airexplorer-reactor-handoff\work\dump_official_16598.zip'
OUT = W + r'\work\c2_pack'

refs, meths, FS, rows, streams, si, bi = mref.load(EXE)
rva2tok = {}
for t, (r, n) in meths.items():
    if r:
        rva2tok.setdefault(r, t)
nz_methods = sum(1 for t, (r, n) in meths.items() if r)
print('MethodDefs total=%d nonzeroRVA=%d rva0=%d' % (len(meths), nz_methods, len(meths) - nz_methods))

d = open(EXE, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3C)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]
optsz = struct.unpack_from('<H', d, pe + 20)[0]
def r2o(rva):
    for i in range(nsec):
        o = pe + 24 + optsz + i * 40
        vsz, va, rsz, raw = struct.unpack_from('<4I', d, o + 8)
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None

v = open(VAULT, 'rb').read()
FATV = {0x3003, 0x300B, 0x3013, 0x301B}

# ---- anchored scan over whole vault ----
anchors = []
for p in range(0, len(v) - 20, 4):
    rva = struct.unpack_from('<I', v, p)[0]
    if rva not in rva2tok:
        continue
    f0 = struct.unpack_from('<I', v, p + 8)[0]
    if (f0 & 0xFFFF) not in FATV:
        continue
    lo = struct.unpack_from('<I', v, p + 16)[0]
    if not (lo == 0 or (lo >> 24) == 0x11):
        continue
    anchors.append(p)
print('validated anchors:', len(anchors))
dup = [rva for rva, c in collections.Counter(
    struct.unpack_from('<I', v, p)[0] for p in anchors).items() if c > 1]
print('duplicate RVAs among anchors:', len(dup), dup[:5])

# ---- parse entries + block tails ----
entries = []
bad_block = 0
for i, p in enumerate(anchors):
    rva, t1, f0, t2, loc = struct.unpack_from('<5I', v, p)
    ticket, chunk = v[p + 20:p + 24], v[p + 24:p + 28]
    end = anchors[i + 1] if i + 1 < len(anchors) else len(v)
    # walk blocks from p+28
    q = p + 28
    blocks = []
    ok = True
    while q + 8 <= end:
        ptr, ndw = struct.unpack_from('<II', v, q)
        if ndw > 0x100 or q + 8 + ndw * 4 > end:
            ok = False
            break
        blocks.append((ptr, ndw, v[q + 8:q + 8 + ndw * 4]))
        q += 8 + ndw * 4
    if not ok or q != end:
        bad_block += 1
    entries.append(dict(pos=p, end=end, rva=rva, t1=t1, fat0=f0, t2=t2, locals=loc,
                        ticket=ticket.hex(), chunk=chunk.hex(), blocks=blocks, ok=ok))

print('entries:', len(entries), 'entries with clean block-tail parse:', sum(1 for e in entries if e['ok']), 'bad:', bad_block)
gaps = collections.Counter(e['end'] - e['pos'] for e in entries)
print('entry size histogram top:', gaps.most_common(10))
blockshapes = collections.Counter()
for e in entries:
    blockshapes[tuple(b[1] for b in e['blocks'])] += 1
print('block-shape top:', blockshapes.most_common(6))

# ---- validation vs official JIT dump ----
z = zipfile.ZipFile(ZIP)
dump = {}
for nm in z.namelist():
    if nm.startswith('m_') and nm.endswith('.bin'):
        tok = int(nm[2:-4], 16)
        dd = z.read(nm)
        d_tok, ilsize, maxstack, ehcnt, prex, loctok = struct.unpack_from('<6I', dd, 0)
        dump[tok] = dict(il=dd[24:24 + ilsize], ilsize=ilsize, maxstack=maxstack,
                         eh=ehcnt, locals=loctok, tok=d_tok)
print('dump bodies:', len(dump))

n_overlap = n_chunk = n_fat = n_loc = n_slot = n_full = 0
mismatch_examples = []
for e in entries:
    tok = rva2tok[e['rva']]
    dd = dump.get(tok)
    if not dd:
        continue
    n_overlap += 1
    il = dd['il']
    if bytes.fromhex(e['chunk']) == il[4:8]:
        n_chunk += 1
    if ((e['fat0'] >> 16) & 0xFFFF) == dd['maxstack']:
        n_fat += 1
    if e['locals'] == dd['locals']:
        n_loc += 1
    # full-body reconstruction: ticket? + vault 4B + slot tail from +20
    fo = r2o(e['rva'])
    tail = d[fo + 20:fo + 20 + max(0, dd['ilsize'] - 8)]
    if bytes.fromhex(e['chunk']) + tail == il[4:]:
        n_slot += 1
    elif len(mismatch_examples) < 3:
        mismatch_examples.append((e['rva'], tok))
print('overlap vault∩dump =', n_overlap)
print('  chunk(4B)==il[4:8] :', n_chunk)
print('  fat0.maxstack==dump:', n_fat)
print('  locals==dump       :', n_loc)
print('  vault4B+slot20 == il[4:] full reassembly:', n_slot)
print('  mismatch examples:', [(hex(r), '%08X' % t) for r, t in mismatch_examples])

# ---- write artifacts ----
import os
with open(OUT + r'\vault_index.tsv', 'w') as f:
    f.write('rva\ttok\tname\tpos\tsize\tfat0\tmaxstack\tlocals\tticket\tchunk\tnblocks\tblockshapes\tclean\n')
    for e in entries:
        tok = rva2tok[e['rva']]
        f.write('%06X\t%08X\t%s\t%d\t%d\t%08X\t%d\t%08X\t%s\t%s\t%d\t%s\t%d\n' % (
            e['rva'], tok, meths[tok][1], e['pos'], e['end'] - e['pos'], e['fat0'],
            (e['fat0'] >> 16) & 0xFFFF, e['locals'], e['ticket'], e['chunk'],
            len(e['blocks']), ','.join(str(b[1]) for b in e['blocks']), 1 if e['ok'] else 0))
for e in entries:
    open(OUT + r'\vault_entries\%06X.bin' % e['rva'], 'wb').write(v[e['pos']:e['end']])

json.dump(dict(
    total_methods=len(meths), nonzero_rva=nz_methods,
    anchors=len(anchors), dup_rvas=len(dup),
    entries_clean=sum(1 for e in entries if e['ok']),
    entry_size_hist={str(k): c for k, c in gaps.most_common()},
    dump_bodies=len(dump),
    overlap=n_overlap, val_chunk=n_chunk, val_fat=n_fat, val_locals=n_loc,
    val_full_reassembly=n_slot,
    vault_rvas=sorted(e['rva'] for e in entries),
), open(OUT + r'\c2_step1.json', 'w'))
print('wrote vault_index.tsv / vault_entries/ / c2_step1.json')
