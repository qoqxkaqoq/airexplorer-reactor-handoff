#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step74b: scan InstantiateGlobalCalculator (06004192) for throw sites + call targets."""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

il = open(ALL, 'rb').read()
idx = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), int(p[4]))

def body(tok):
    clen, pos = idx[tok]
    return il[pos:pos + clen]

def scan(tok):
    b = body(tok)
    ins = parse(b)
    off = {}
    for e in ins:
        off[e[0]] = e
    throws = [e for e in ins if e[1] in ('throw', 'rethrow')]
    ldstrs = [e for e in ins if e[1] == 'ldstr']
    news = [e for e in ins if e[1] == 'newobj']
    calls = {}
    for e in ins:
        if e[1] in ('call', 'callvirt'):
            calls[e[2]] = calls.get(e[2], 0) + 1
    print('[%s] len=%d ins=%d throw=%d ldstr=%d newobj=%d uniq_call=%d' %
          (hex(tok), len(b), len(ins), len(throws), len(ldstrs), len(news), len(calls)))
    for t in throws:
        i = ins.index(t)
        ctx = ins[max(0, i - 6):i + 1]
        print('  THROW@%04x:' % t[0], ' | '.join('%s %s' % (c[1], c[2] if c[1] != 'ldc.i4' else '') for c in ctx))
    for t in ldstrs[:20]:
        print('  LDSTR@%04x tok=%s' % (t[0], hex(t[2]) if isinstance(t[2], int) else t[2]))
    for t in news[:20]:
        print('  NEWOBJ@%04x tok=%s' % (t[0], hex(t[2]) if isinstance(t[2], int) else t[2]))
    print('  CALLS:', ' '.join('%s:x%d' % (hex(k), v) for k, v in sorted(calls.items())))
    return calls

scan(0x06004192)
