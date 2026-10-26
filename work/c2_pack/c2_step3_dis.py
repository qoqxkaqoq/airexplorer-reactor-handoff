#!/usr/bin/env python3
# c2_step3_dis.py — disassemble the 重点 methods with work_a1/ildis.py's engine.
# ildis.OPS1 is corrected for 0x11..0x1F (ldloc.s/ldloca.s/stloc.s/ldnull/ldc.i4.m1..8/
# ldc.i4.s — original table was shifted; verified against airexplorer-reactor-handoff/work/flat.py
# which the previous session used for all a3_dis_*.txt outputs). Tokens annotated via mref;
# ldstr via #US heap; EH from dump_official_16598.zip m_<tok>.eh.
import struct, sys, zipfile, os
sys.path.insert(0, r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff\work_a1')
sys.path.insert(0, r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff\airexplorer-reactor-handoff\work')
import ildis, mref

W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
EXE = W + r'\airexplorer-reactor-handoff\exes\AirExplorer_baseline_verified.exe'
ZIP = W + r'\airexplorer-reactor-handoff\work\dump_official_16598.zip'
OUT = W + r'\work\c2_pack\dis'

# --- opcode-table correction (verified against flat.py canonical table) ---
FIX = {0x11: ('ldloc.s', 1), 0x12: ('ldloca.s', 1), 0x13: ('stloc.s', 1), 0x14: ('ldnull', 0),
       0x15: ('ldc.i4.m1', 0), 0x16: ('ldc.i4.0', 0), 0x17: ('ldc.i4.1', 0), 0x18: ('ldc.i4.2', 0),
       0x19: ('ldc.i4.3', 0), 0x1A: ('ldc.i4.4', 0), 0x1B: ('ldc.i4.5', 0), 0x1C: ('ldc.i4.6', 0),
       0x1D: ('ldc.i4.7', 0), 0x1E: ('ldc.i4.8', 0), 0x1F: ('ldc.i4.s', 1), 0x27: ('jmp', 4),
       0x70: ('cpobj', 4), 0x71: ('ldobj', 4), 0x76: ('conv.r.un', 0), 0x7A: ('throw', 0),
       0xC2: ('refanyval', 4), 0xC6: ('mkrefany', 4), 0xE0: ('conv.u', 0)}
ildis.OPS1.update(FIX)
TOKOPS = {'call', 'callvirt', 'newobj', 'ldfld', 'ldflda', 'stfld', 'ldsfld', 'ldsflda',
          'stsfld', 'ldtoken', 'isinst', 'castclass', 'box', 'unbox.any', 'newarr', 'initobj',
          'constrained.', 'ldftn', 'ldvirtftn', 'ldelema', 'stelem', 'ldelem', 'stobj', 'sizeof',
          'ldstr'}

refs, meths, FS, rows, streams, si, bi = mref.load(EXE)
d = open(EXE, 'rb').read()
usoff, ussz = streams.get('#US', (0, 0))
def us(tok):
    # this exe's #US heap is obfuscated/interleaved; decode best-effort: try LE/BE at
    # several alignments, keep the longest printable-ASCII prefix (annotation only)
    off = (tok & 0x00FFFFFF) >> 2
    o = usoff + off
    best = ''
    for start in (o, o - 1, o + 1, o - 2):
        if start < 0 or start + 2 > len(d): continue
        raw = d[start:start + 160]
        for how in ('le', 'be'):
            chars = raw.decode('utf-16-le' if how == 'le' else 'utf-16-be', 'ignore')
            run = ''
            for ch in chars:
                if 0x20 <= ord(ch) < 0x7f or ch in '\r\n\t':
                    run += ch
                else:
                    break
            if len(run) > len(best):
                best = run
    return best if len(best) >= 4 else None

# typeref#NNN -> full name (mref prints 'typeref#N::name' only)
RSz = 4 if any(rows.get(t, 0) > 0xFFFF for t in (0x00, 0x1A, 0x23, 0x01)) else 2
tto = streams['#~'][0]
rowdata = tto + 24 + 4 * len(rows)
starts = {}; o = rowdata
for b in sorted(rows):
    starts[b] = o; o += FS.get(b, 0) * rows[b]
soff = streams['#Strings'][0]
def _s(i):
    e = d.find(b'\0', soff + i); return d[soff + i:e].decode('utf8', 'replace')
trstart = starts[0x01]
def trname(rid):
    r = trstart + (rid - 1) * FS[0x01]
    ni = struct.unpack_from('<I' if si == 4 else '<H', d, r + RSz)[0]
    nsi = struct.unpack_from('<I' if si == 4 else '<H', d, r + RSz + si)[0]
    ns = _s(nsi); n = _s(ni)
    return (ns + '.' + n) if ns else n
import re as _re
_TRPAT = _re.compile(r'typeref#(\d+)')
def pretty_ref(label):
    m = _TRPAT.match(label)
    if m: return trname(int(m.group(1))) + label[label.index('::'):]
    return label
def tokname(t):
    tab = t >> 24
    if tab == 0x06:
        m = meths.get(t)
        return 'MethodDef:%s' % (m[1] if m else '?')
    if tab == 0x0A: return 'MemberRef:' + pretty_ref(refs.get(t, '?'))
    if tab == 0x04: return 'Field:%04X' % (t & 0xFFFFFF)
    if tab == 0x01: return 'TypeRef:' + trname(t & 0xFFFFFF)
    if tab == 0x02: return 'TypeDef#%d' % (t & 0xFFFFFF)
    if tab == 0x1B: return 'TypeSpec'
    if tab == 0x11: return 'StandAloneSig'
    if tab == 0x70: return 'UserString'
    return ''

z = zipfile.ZipFile(ZIP)
man = {}
for line in open(W + r'\work\c2_pack\bodies_manifest.tsv').read().splitlines()[1:]:
    f_ = line.split('\t'); man[int(f_[1], 16)] = (int(f_[0], 16), f_[2], f_[3])
vault_ix = {}
for line in open(W + r'\work\c2_pack\vault_index.tsv').read().splitlines()[1:]:
    f_ = line.split('\t'); vault_ix[int(f_[0], 16)] = f_

def get_body(tok):
    rva, nm = meths.get(tok, (0, '?'))
    ent = man.get(tok)
    hdr = {}
    src = ent[2] if ent else 'missing'
    if tok in z.namelist() or ('m_%08X.bin' % tok) in z.namelist():
        dd = z.read('m_%08X.bin' % tok)
        _, ilsize, maxstack, ehcnt, prex, loct = struct.unpack_from('<6I', dd, 0)
        return dd[24:24 + ilsize], src, dict(ilsize=ilsize, maxstack=maxstack, eh=ehcnt)
    for p, kind in ((r'%s\work\c2_pack\bodies\%06X.bin' % (W, rva), 'slot'),
                    (r'%s\work\c2_pack\bodies\%06X.partial.bin' % (W, rva), 'vault-partial')):
        if os.path.exists(p):
            b = open(p, 'rb').read()
            return b, kind, dict(ilsize=len(b), note='raw %s bytes (fat/tiny hdr included if slot)' % kind)
    return None, 'none', {}

def eh_of(tok):
    nm = 'm_%08X.eh' % tok
    if nm in z.namelist():
        return z.read(nm)
    return None

def dis_file(tok, extra=''):
    rva, nm = meths.get(tok, (0, '?'))
    il, src, hdr = get_body(tok)
    path = OUT + r'\%08X_%s.il' % (tok, nm.replace('/', '_'))
    with open(path, 'w', encoding='utf8') as f:
        f.write('# token=%08X rva=%06X name=%s source=%s %s\n' % (tok, rva, nm, src, extra))
        if rva in vault_ix:
            v = vault_ix[rva]
            f.write('# vault: fat0=%s maxstack=%s locals=%s ticket=%s chunk=%s blocks=%s\n' %
                    (v[4], v[5], v[6], v[8], v[9], v[10]))
        f.write('# %s\n' % hdr)
        ehd = eh_of(tok)
        if ehd:
            f.write('# EH clauses (%d bytes):\n' % len(ehd))
            for o in range(0, len(ehd) - 27, 28):
                cw = struct.unpack_from('<7I', ehd, o)
                f.write('#   flags=%d try=[%04X+%04X) handler=[%04X+%04X) classOrFilter=%08X pad=%08X\n' % cw)
        if il is None:
            f.write('# NO BODY AVAILABLE\n')
            return path, 0
        for off, s in ildis.disasm(il):
            ann = ''
            parts = s.split(' ')
            if parts[0] in TOKOPS and len(parts) > 1:
                try:
                    t = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1])
                    if parts[0] == 'ldstr':
                        sv = us(t)
                        if sv is not None: ann = '   ; "%s"' % sv[:80]
                    else:
                        ann = '   ; %s' % tokname(t)
                except ValueError: pass
            f.write('  IL_%04X  %s%s\n' % (off, s, ann))
    return path, len(il) if il else 0

TARGETS = {
    'validator': [0x06004192, 0x0600419C, 0x06004198, 0x060041A2, 0x060041A3],
    'debugger': [0x06004194],
    'gfp': [0x060028BF, 0x060028C0, 0x060028C1, 0x06002AF6, 0x06001260, 0x06002CC2, 0x06002F2F, 0x06003D01, 0x060004AA],
    'proc_reflection': [0x060041FF, 0x06004200, 0x06004201, 0x06004208, 0x0600420B, 0x0600420E, 0x0600422D, 0x0600423E],
}
summary = []
for grp, toks in TARGETS.items():
    for tok in toks:
        path, ilen = dis_file(tok, 'grp=%s' % grp)
        rva, nm = meths.get(tok, (0, '?'))
        print('%-16s %08X %-38s il=%5d -> %s' % (grp, tok, nm, ilen, os.path.basename(path)))
        summary.append(dict(grp=grp, tok='%08X' % tok, rva='%06X' % rva, name=nm, il=ilen, file=path))
import json
json.dump(summary, open(W + r'\work\c2_pack\c2_step3.json', 'w'), indent=1)
print('done:', len(summary), 'files in', OUT)
