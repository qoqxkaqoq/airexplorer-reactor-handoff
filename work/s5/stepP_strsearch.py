# -*- coding: utf-8 -*-
"""stepP: find ldstr tokens for ' ' (space) / 'AirExplorer ' style message parts in #US,
then search all dump bodies + disk for those tokens (exception message construction sites)."""
import zipfile, struct, sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
import dnfile
pe = dnfile.dnPE(BASE)
us = pe.net.user_strings

# scan #US raw: find entries whose decoded text is ' ' or contains 'AirExplorer'
data = pe.net.metadata.streams[b'#US'].__data__ if b'#US' in pe.net.metadata.streams else None
if data is None:
    # dnfile exposes streams dict by name
    for k, v in pe.net.metadata.streams.items():
        if str(k).upper() == b'#US' or (hasattr(v, '__data__') and getattr(v, 'name', '') == '#US'):
            data = v.__data__
print('US stream size:', len(data) if data else 'N/A')

def decode_us(off):
    # returns (token, text)
    tok = 0x70000000 | off
    b = data[off]
    if b & 1: return None
    # compressed length
    if b & 0x80 == 0:
        ln = b >> 1; hdr = 1
    elif b & 0xC0 == 0x80:
        ln = ((b & 0x3F) << 8) | data[off+1]; hdr = 2
    else:
        ln = ((b & 0x1F) << 24) | (data[off+1] << 16) | (data[off+2] << 8) | data[off+3]; hdr = 4
    raw = data[off+hdr:off+hdr+ln]
    if ln: raw = raw[:-1]  # trailing flag byte
    try:
        return tok, raw.decode('utf-16-le', errors='replace')
    except Exception:
        return tok, None

hits = {}
if data:
    i = 1
    n = len(data)
    while i < n:
        r = decode_us(i)
        if r and r[1] is not None:
            t = r[1]
            if t == ' ' or 'AirExplorer' in t or t.strip() == '':
                hits.setdefault(repr(t), []).append(r[0])
        # advance
        b = data[i]
        if b & 0x80 == 0: ln = b >> 1; hdr = 1
        elif b & 0xC0 == 0x80: ln = ((b & 0x3F) << 8) | data[i+1]; hdr = 2
        else: ln = ((b & 0x1F) << 24) | (data[i+1] << 16) | (data[i+2] << 8) | data[i+3]; hdr = 4
        i += hdr + ln + (1 if ln else 0)
        i = (i + 3) & ~3 if False else i  # no alignment in #US
for k, v in sorted(hits.items()):
    print(repr(k), ['0x%08x' % x for x in v[:8]], 'x%d' % len(v))
import json
json.dump({k: v for k, v in hits.items()}, open('/tmp/s5/us_hits.json', 'w'))
