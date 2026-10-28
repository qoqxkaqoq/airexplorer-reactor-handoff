#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step109: where does 4528 get its expectation values?
a7c verdict: only 041EE body bytes changed (semantics identical) -> 4528 fires.
4528 has zero crypto/file MemberRef and never calls 4192/41EE directly ->
either it reads memory bytes via a callee (dA6wGcPgJA = Reactor runtime?) or
a callee does the check. Dump the suspects + check DB coverage of guard net.
"""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
import dnfile

EXE = '/workspace/repo_git/exes/AirExplorer_a1.exe'
DB = '/workspace/repo_git/work/s5/mem5/res0_plain_a1.bin'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

pe = dnfile.dnPE(EXE)
md = pe.net.mdtables
N = len(md.MethodDef.rows)

def rva_of(tok):
    r = tok & 0xFFFFFF
    return md.MethodDef.rows[r - 1].Rva if r <= N else 0

# --- parse res0 DB (header 24B, then [rva][n][4n dwords]) ---
db = open(DB, 'rb').read()
print('[db] size=%d head=%s' % (len(db), db[:24].hex()))
off = 24
entries = {}
while off < len(db):
    rva, n = struct.unpack_from('<II', db, off)
    off += 8
    dw = list(struct.unpack_from('<%dI' % n, db, off))
    off += 4 * n
    entries[rva] = dw
print('[db] entries=%d consumed=%d/%d' % (len(entries), off, len(db)))

# --- coverage: guard net + 4528 family + 5 targets ---
print('\n=== Q1: DB coverage ===')
TOKS = {
    '060041EE VerifyHashShim': 0x060041EE,
    '06004192 InstGlobalCalc': 0x06004192,
    '06004194 (sibling)':      0x06004194,
    '060041CF 4192helper':     0x060041CF,
    '06004528 GenAdaptExtra':  0x06004528,
    '0600457d dA6wGcPgJA':     0x0600457d,
    '0600457f PatchCommand':   0x0600457f,
    '06004581 EncapsJoinedTr': 0x06004581,
    '0600452e WriteLocator':   0x0600452e,
    'P3 06002127': 0x06002127, 'P4 06002133': 0x06002133, 'P5 06002145': 0x06002145,
    'P1 0600212A': 0x0600212A, 'P2 06002157': 0x06002157,
}
for name, tok in sorted(TOKS.items()):
    rva = rva_of(tok)
    fo = pe.get_offset_from_rva(rva) if rva else 0
    e = entries.get(rva)
    if e is None:
        print('%-26s rva=0x%06x fo=0x%06x  NOT-IN-DB  file[0:12]=%s'
              % (name, rva, fo, bytes(pe.__data__[fo:fo+12]).hex()))
    else:
        nz = sum(1 for d in e if d)
        print('%-26s rva=0x%06x  IN-DB ndw=%d nonzero=%d  dw[:6]=%s'
              % (name, rva, len(e), nz, ' '.join('%08x' % d for d in e[:6])))

# --- 4528's 178 callees: DB coverage + file stub vs dump-body ---
print('\n=== Q2: 4528 callees DB coverage (06:004xxx from step106 list) ===')
CALLEES = [0x60042bb,0x60042bd,0x60042be,0x6004318,0x600431b,0x6004375,0x6004378,0x600437d,
0x6004385,0x60043e5,0x60043e8,0x60043e9,0x60043ea,0x60043ec,0x60043ed,0x60043ee,0x60043ef,
0x60043f0,0x60043f1,0x60043f2,0x60043f3,0x60043f4,0x60043f5,0x60043f6,0x60043f7,0x60043f8,
0x60043f9,0x60043fa,0x60043fb,0x60043fc,0x60043fd,0x60043fe,0x60043ff,0x6004400,0x6004401,
0x6004402,0x6004403,0x6004404,0x6004405,0x6004406,0x6004407,0x6004408,0x6004409,0x600440a,
0x600440b,0x600440c,0x600440d,0x600440e,0x600440f,0x6004410,0x6004411,0x6004412,0x6004413,
0x6004414,0x6004415,0x6004416,0x6004417,0x6004418,0x6004419,0x600441a,0x600441b,0x600441c,
0x600441d,0x600441e,0x6004420,0x6004421,0x6004422,0x6004423,0x6004424,0x6004425,0x6004426,
0x6004427,0x6004428,0x6004429,0x600442a,0x6004432,0x6004435,0x6004436,0x6004437,0x600448f,
0x600449c,0x60044a1,0x60044af,0x60044bd,0x60044cb,0x60044fb,0x60044ff,0x6004504,0x6004509,
0x6004529,0x600452c,0x600452e,0x600452f,0x6004532,0x6004535,0x6004537,0x6004538,0x6004539,
0x600453a,0x600454b,0x600454c,0x600454e,0x6004550,0x6004552,0x6004553,0x6004555,0x6004556,
0x6004557,0x6004558,0x6004559,0x600455b,0x600455d,0x6004566,0x6004571,0x600457d,0x600457f,
0x6004580,0x6004581,0x60045b0,0x600463c,0x6004650,0x600468c,0x60047ac,0x60047b8,0x60047f0,
0x6004840,0x6004ef0,0x6004f8c,0x60050c8,0x6005214,0x6005218,0x6005648,0x600564c,0x600611c,
0x6006120,0x60077a4,0x60077b0,0x60077bc,0x60077c0,0x60077c4,0x60077c8,0x60077dc,0x6007804,
0x600780c,0x6007818,0x600781c,0x6007824,0x6007828,0x600782c,0x6007830,0x6007834,0x6007838,
0x600783c,0x6007840,0x6007844,0x6007848,0x600784c]
in_db = stub = real = 0
suspects = []
for tok in CALLEES:
    rva = rva_of(tok)
    if not rva:
        continue
    fo = pe.get_offset_from_rva(rva)
    b0 = pe.__data__[fo]
    if b0 & 3 == 2:
        csize = b0 >> 2
        body = bytes(pe.__data__[fo+1:fo+1+csize])
        if body in (b'\x00\x00\x00\x2a', b'\x2a', b'\x16\x2a', b'\x17\x2a', b'\x1a\x2a', b'\x1b\x2a') or \
           (csize <= 6 and body.endswith(b'\x2a') and set(body[:-1]) <= {0}):
            stub += 1
        else:
            real += 1
            suspects.append((tok, rva, body.hex()))
    else:
        real += 1  # fat: assume real in file
        suspects.append((tok, rva, bytes(pe.__data__[fo:fo+12]).hex()))
    if rva in entries:
        in_db += 1
print('[callees] total=%d in-db=%d file-stub=%d file-real=%d' % (len(CALLEES), in_db, stub, real))
print('[callees] real-body suspects (file has true body, not stub):')
for t, r, h in suspects[:12]:
    print('   %08X rva=%06x head=%s' % (t, r, h))

# --- Q3: dump dA6wGcPgJA + Invoke + key high-freq callees from official dump ---
print('\n=== Q3: suspect bodies from official dump ===')
il = open(ALL, 'rb').read()
bodies = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))
from flat import parse
for tk in (0x0600457d, 0x06004509, 0x0600457f, 0x06004581):
    if tk not in bodies:
        print('%08X: not in dump' % tk)
        continue
    clen, pos = bodies[tk]
    code = il[pos:pos+clen]
    try:
        ins = list(parse(code))
    except Exception as ex:
        print('%08X parse fail: %s (size=%d)' % (tk, ex, clen))
        continue
    print('\n--- %08X: size=%d ins=%d ---' % (tk, clen, len(ins)))
    for e in ins[:60]:
        print('   ', e)
