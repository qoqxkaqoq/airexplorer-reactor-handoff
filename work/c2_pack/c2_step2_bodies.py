#!/usr/bin/env python3
# c2_step2_bodies.py — extract all recoverable method bodies to work/c2_pack/bodies/
# (named by RVA), compute coverage vs total MethodDefs. Sources, in priority order:
#   S1 dump_official_16598.zip  (official JIT full sweep, same md5 as baseline) -> full CIL
#   S2 exe .text slot            (plaintext fat/tiny bodies, not vault/Necrobit-stubbed) -> full body
#   S3 vault entry (dec_Viewer.bin) alone -> PARTIAL: realIL = [4B hole] + chunk4 + slot tail
# Outputs: bodies/*.bin, bodies_manifest.tsv, c2_coverage.json
import struct, sys, json, zipfile, collections, os

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
sys.path.insert(0, W + r'\work_a1')
import mref

EXE = W + r'\airexplorer-reactor-handoff\exes\AirExplorer_baseline_verified.exe'
VAULT = W + r'\work_a1\dec_Viewer.bin'
ZIP = W + r'\airexplorer-reactor-handoff\work\dump_official_16598.zip'
OUT = W + r'\work\c2_pack'
BODIES = OUT + r'\bodies'

refs, meths, FS, rows, streams, si, bi = mref.load(EXE)
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

# slot bounds by sorted MethodDef RVAs
import bisect
rvas_sorted = sorted(set(r for r, n in meths.values() if r))
def slot_end(rva):
    i = bisect.bisect_right(rvas_sorted, rva)
    return rvas_sorted[i] if i < len(rvas_sorted) else 0x929BA4

# vault index from step1
step1 = json.load(open(OUT + r'\c2_step1.json'))
vault = {r for r in step1['vault_rvas']}
vmap = {}
for line in open(OUT + r'\vault_index.tsv').read().splitlines()[1:]:
    f_ = line.split('\t')
    vmap[int(f_[0], 16)] = f_

# dump
z = zipfile.ZipFile(ZIP)
dump = {}
ehs = {}
for nm in z.namelist():
    if nm.startswith('m_') and nm.endswith('.bin'):
        tok = int(nm[2:-4], 16)
        dd = z.read(nm)
        d_tok, ilsize, maxstack, ehcnt, prex, loct = struct.unpack_from('<6I', dd, 0)
        dump[tok] = dict(il=dd[24:24 + ilsize], ilsize=ilsize, maxstack=maxstack, eh=ehcnt)
    elif nm.startswith('m_') and nm.endswith('.eh'):
        ehs[int(nm[2:-3], 16)] = z.read(nm)

def slot_body(rva):
    """parse plaintext fat/tiny body at slot; None if stub/invalid"""
    fo = r2o(rva)
    if fo is None:
        return None
    b0 = d[fo]
    kind = b0 & 3
    if kind == 2:
        size = b0 >> 2
        return d[fo:fo + 1 + size]
    if kind != 3:
        return None
    hsize = (d[fo + 1] >> 4) * 4
    if hsize not in (12, 16):
        return None
    codesize = struct.unpack_from('<I', d, fo + 4)[0]
    if codesize > 0x100000:
        return None
    end = fo + hsize + codesize
    body = d[fo:end]
    # EH section
    if b0 & 8:
        sect = (end + 3) & ~3
        if sect + 4 > len(d):
            return None
        sflags = d[sect]
        if sflags & 0x40:
            ssize = struct.unpack_from('<I', d, sect)[0] >> 8
            body = d[fo:sect + ssize]
    span = r2o(slot_end(rva)) or 0x936000
    if fo + len(body) > span:
        return None
    # Necrobit fat stub magic: code starts with ldc.i4 (0x20)
    if len(body) > hsize and body[hsize] == 0x20:
        return None
    return body

cat = collections.Counter()
manifest = []
toks_sorted = sorted(meths)
for tok in toks_sorted:
    rva, name = meths[tok]
    if not rva:
        cat['rva0_nobody'] += 1
        continue
    src = None
    if tok in dump:
        il = dump[tok]['il']
        open(BODIES + r'\%06X.bin' % rva, 'wb').write(il)
        src = 'dump_full'
        cat['dump_full'] += 1
    elif rva in vault:
        # vault-backed: exe slot is a Necrobit stub (tiny stub + zeros + IL tail).
        # real IL = [4B ticket hole] + vault chunk4 + slot tail to slot end.
        fo = r2o(rva)
        tail = d[fo + 20:r2o(slot_end(rva))]
        chunk = bytes.fromhex(vmap[rva][9])
        open(BODIES + r'\%06X.partial.bin' % rva, 'wb').write(chunk + tail)
        src = 'vault_partial'
        cat['vault_partial'] += 1
    else:
        sb = slot_body(rva)
        if sb is not None:
            open(BODIES + r'\%06X.bin' % rva, 'wb').write(sb)
            src = 'slot_plaintext'
            cat['slot_plaintext'] += 1
        else:
            fo = r2o(rva)
            head = d[fo:fo + 8].hex()
            src = 'unrecoverable(slot=%s)' % head
            cat['unrecoverable'] += 1
    manifest.append((rva, tok, name, src))

with open(OUT + r'\bodies_manifest.tsv', 'w') as f:
    f.write('rva\ttok\tname\tsource\n')
    for rva, tok, name, src in manifest:
        f.write('%06X\t%08X\t%s\t%s\n' % (rva, tok, name, src))

total = len(meths)
full = cat['dump_full'] + cat['slot_plaintext']
print('total MethodDefs          :', total)
print('rva==0 (no body)          :', cat['rva0_nobody'])
print('nonzero RVA               :', total - cat['rva0_nobody'])
print('full IL from JIT dump     :', cat['dump_full'])
print('full body from exe slot   :', cat['slot_plaintext'])
print('FULL RECOVERABLE          :', full, '(%.2f%% of all, %.2f%% of nonzero-RVA)' % (
    100.0 * full / total, 100.0 * full / (total - cat['rva0_nobody'])))
print('partial (vault chunk+tail):', cat['vault_partial'])
print('unrecoverable             :', cat['unrecoverable'])
print('vault entries             :', len(vault), '(overlap with dump: 4341 per c2_step1.json)')
json.dump(dict(total=total, rva0=cat['rva0_nobody'], nonzero=total - cat['rva0_nobody'],
               dump_full=cat['dump_full'], slot_plaintext=cat['slot_plaintext'],
               full_recoverable=full, vault_partial=cat['vault_partial'],
               unrecoverable=cat['unrecoverable'], vault_entries=len(vault),
               eh_files=len(ehs)),
          open(OUT + r'\c2_coverage.json', 'w'), indent=1)
print('bodies dir file count:', len(os.listdir(BODIES)))
