#!/usr/bin/env python3
# check_export.py — verify mainlib export: size preservation, keystream structure, plaintext format.
import struct, sys, zlib

W = '/workspace/airexplorer-reactor-handoff/work'
res = open(W + '/res_ValidatorGenerator.DefinitionError.bin', 'rb').read()
try:
    din = open('/tmp/mainlib_deflate-input.bin', 'rb').read()
except FileNotFoundError:
    print('NO EXPORT YET'); sys.exit(1)
print(f'resource   = {len(res)} bytes')
print(f'defl-input = {len(din)} bytes')
print('size-preserving decrypt:', len(res) == len(din))

# keystream hypothesis: plain_word = cipher_word ^ ks_word  =>  ks = res ^ din
if len(res) == len(din):
    ks = bytes(a ^ b for a, b in zip(res, din))
    # structure probes
    head = ks[:64]
    print('ks head:', head.hex())
    # block repeat probe: find period of 32B key array
    blk = ks[:32]
    repeats = sum(1 for i in range(0, min(len(ks), 4096), 32) if ks[i:i+32] == blk)
    print(f'ks 32B-block[0..32) repeats in first 4K: {repeats}/128')
    # distinct 32B blocks in first 64K
    blocks = {ks[i:i+32] for i in range(0, min(len(ks), 65536), 32)}
    print(f'distinct 32B blocks in first 64K: {len(blocks)}/2048')
    # entropy of ks
    from collections import Counter
    c = Counter(ks[:262144])
    ent = -sum((v/262144) * __import__('math').log2(v/262144) for v in c.values())
    print(f'ks entropy (first 256K): {ent:.3f} bits/byte')

try:
    plain = open('/tmp/mainlib_plain.bin', 'rb').read()
except FileNotFoundError:
    print('NO INFLATE YET'); sys.exit(0)
print(f'plain      = {len(plain)} bytes')
print('plain head:', plain[:32].hex())
if plain[:2] == b'MZ':
    print('>>> PLAINTEXT IS A PE ASSEMBLY <<<')
    pe = struct.unpack_from('<I', plain, 0x3C)[0]
    print(f'PE sig @0x{pe:X}:', plain[pe:pe+4])
    nsec = struct.unpack_from('<H', plain, pe + 6)[0]
    optsz = struct.unpack_from('<H', plain, pe + 20)[0]
    print(f'sections={nsec} opthdr={optsz}')
    for i in range(nsec):
        o = pe + 24 + optsz + 40 * i
        name = plain[o:o+8].rstrip(b'\0').decode(errors='replace')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', plain, o + 8)
        print(f'  {name:8} va=0x{va:X} vsz=0x{vsz:X} raw=0x{ro:X} rsz=0x{rsz:X}')
    # find CLI header via data directory 14
    dd = pe + 24 + 96 + 14 * 8
    cli_rva, cli_sz = struct.unpack_from('<II', plain, dd)
    print(f'CLI header rva=0x{cli_rva:X} size={cli_sz}')
else:
    # maybe method-body table: dump first 96 bytes hex + ascii
    for i in range(0, 96, 16):
        chunk = plain[i:i+16]
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'{i:04X}  {chunk.hex(" ")}  {asc}')
