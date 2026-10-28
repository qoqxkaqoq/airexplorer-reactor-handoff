# -*- coding: utf-8 -*-
"""step56: signatures + declaring types + statics of key Reactor methods
(0600419C res[0] reader, 06004196 res[5], 0600418C AES factory, 060042AC,
06004264 RandomDecryptor, 06004218-31 helpers, 06004192 sentinel).
Purpose: design probe2 mode=mem reflection invocation args."""
import struct, sys, dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables

ET_NAMES = {
0x01:'void',0x02:'bool',0x03:'char',0x04:'i1',0x05:'u1',0x06:'i2',0x07:'u2',
0x08:'i4',0x09:'u4',0x0a:'i8',0x0b:'u8',0x0c:'r4',0x0d:'r8',0x0e:'string',
0x16:'typedref',0x18:'IntPtr',0x19:'UIntPtr',0x1c:'object'}

class R:
    def __init__(s, b): s.b, s.i = b, 0
    def u8(s):
        v = s.b[s.i]; s.i += 1; return v
    def cint(s):
        v = s.u8()
        if v & 0x80 == 0: return v
        if v & 0xC0 == 0x80: return ((v & 0x3F) << 8) | s.u8()
        if v & 0xE0 == 0xC0: return ((v & 0x1F) << 24) | (s.u8() << 16) | (s.u8() << 8) | s.u8()
        raise ValueError('bad cint 0x%02x' % v)
    def tok(s):
        v = s.cint(); return v


def sb(x):
    v = getattr(x, 'value', None)
    if isinstance(v, (bytes, bytearray)): return v
    vb = getattr(x, 'value_bytes', None)
    if isinstance(vb, (bytes, bytearray)): return vb
    rd = getattr(x, 'raw_data', None)
    if isinstance(rd, (bytes, bytearray)): return rd
    raise TypeError(type(x))

def tokname(tok):
    t, rid = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x02:
            r = mdt.TypeDef.rows[rid-1]
            return (r.TypeNamespace + '.' if r.TypeNamespace else '') + r.TypeName
        if t == 0x01:
            r = mdt.TypeRef.rows[rid-1]
            return (r.TypeNamespace + '.' if r.TypeNamespace else '') + r.TypeName
        if t == 0x1B:
            r = mdt.TypeSpec.rows[rid-1]
            return 'TypeSpec<' + sb(r.Signature).hex()[:24] + '>'
    except Exception as e:
        return 'tok%08X(?%s)' % (tok, e)
    return 'tok%08X' % tok

def parse_type(r):
    et = r.cint()
    if et in ET_NAMES: return ET_NAMES[et]
    if et in (0x11, 0x12): return tokname(r.tok())
    if et == 0x1d: return parse_type(r) + '[]'
    if et == 0x10: return 'ref ' + parse_type(r)
    if et == 0x0f: return '*' + parse_type(r)
    if et == 0x13: return '!!%d' % r.cint()
    if et == 0x1e: return '!!m%d' % r.cint()
    if et == 0x15:  # GENERICINST
        k = r.u8(); base = parse_type(r)
        n = r.cint(); args = ','.join(parse_type(r) for _ in range(n))
        return base + '<' + args + '>'
    if et == 0x14:  # ARRAY
        t = parse_type(r); rank = r.cint()
        return t + '[%d]' % rank
    if et == 0x1c: return 'object'
    return 'et0x%02x' % et

def method_sig(blob):
    r = R(blob)
    conv = r.u8()
    static = not (conv & 0x20)
    if conv & 0x40: r.cint()  # generic param count
    n = r.cint()
    ret = parse_type(r)
    ps = []
    for _ in range(n):
        try: ps.append(parse_type(r))
        except Exception as e: ps.append('?%s' % e); break
    return ('static ' if static else 'instance '), ret, ps

def owner_of(rid):
    for i, td in enumerate(mdt.TypeDef.rows):
        ml = td.MethodList
        rids = [(m.row_index if hasattr(m, 'row_index') else 0) for m in ml] if isinstance(ml, list) else []
        if rid in rids:
            return '0x%04X %s.%s' % (i+1, td.TypeNamespace, td.TypeName)
    return '?'

def field_owner(rid):
    for i, td in enumerate(mdt.TypeDef.rows):
        fl = td.FieldList
        rids = [(f.row_index if hasattr(f, 'row_index') else 0) for f in fl] if isinstance(fl, list) else []
        if rid in rids:
            return '0x%04X %s.%s' % (i+1, td.TypeNamespace, td.TypeName)
    return '?'

TARGETS = [0x0600419C, 0x06004196, 0x0600418C, 0x060042AC, 0x06004264, 0x06004192,
           0x060042AF, 0x060041FA, 0x060041D1]
TARGETS += list(range(0x06004218, 0x06004232))
for t in TARGETS:
    rid = t & 0xFFFFFF
    m = mdt.MethodDef.rows[rid-1]
    try:
        st, ret, ps = method_sig(sb(m.Signature))
        sig = '%s%s (%s)' % (st, ret, ', '.join(ps))
    except Exception as e:
        sig = 'PARSE-FAIL %s' % e
    print('0600%04X %-42s %-28s sig=%s' % (rid, m.Name, owner_of(rid), sig))

print()
# static fields of interest: 0x04001FD0 (_ExtractorVisitors) + fields of 0600419C owner
for frid in (0x1FD0,):
    f = mdt.Field.rows[frid-1]
    sig = sb(f.Signature).hex()
    print('0400%04X %-42s owner=%s sig=%s' % (frid, f.Name, field_owner(frid), sig))

# list statics of owner types of the two readers
for tgt in (0x0600419C, 0x06004196):
    rid = tgt & 0xFFFFFF
    td_idx = owner_of(rid)
    print('\nstatics of reader-owner %s:' % td_idx)
    ti = int(td_idx.split()[0].replace('0x',''), 16)
    td = mdt.TypeDef.rows[ti-1]
    fl = td.FieldList
    rids = sorted(set((f.row_index if hasattr(f, 'row_index') else 0) for f in fl) - {0})
    for r in rids:
        f = mdt.Field.rows[r-1]
        sig = sb(f.Signature).hex()
        print('  0400%04X %-42s sig=%s' % (r, f.Name, sig))
