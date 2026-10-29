#!/usr/bin/env python3
# tolerant flat.py variant: stops at unknown opcode instead of raising
import struct, sys, importlib.util
spec = importlib.util.spec_from_file_location('flat', '/root/repo_git/work/flat.py')
flat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flat)

def parse_tolerant(il):
    ins = []
    i = 0; n = len(il)
    while i < n:
        off = i
        b = il[i]
        if b == 0xFE:
            if i+1 >= n: break
            name, k = flat.TWO.get(il[i+1]) or (None, None)
            if name is None:
                print(f'!! unknown FE {il[i+1]:02X} at {off:04X}, stop'); break
            plen = 2; i += 2
        else:
            name, k = flat.ONE.get(b) or (None, None)
            if name is None:
                print(f'!! unknown op {b:02X} at {off:04X}, stop'); break
            plen = 1; i += 1
        try:
            if k == 'sw':
                cnt = struct.unpack_from('<i', il, i)[0]
                base = i + 4 + cnt*4
                targets = [base + struct.unpack_from('<i', il, i+4+4*t)[0] for t in range(cnt)]
                ins.append((off, name, 'sw', targets, plen)); i += 4 + cnt*4
            elif k == 'br1':
                d = struct.unpack_from('<b', il, i)[0]; ins.append((off, name, 'br1', i+1+d, plen)); i += 1
            elif k == 'br4':
                d = struct.unpack_from('<i', il, i)[0]; ins.append((off, name, 'br4', i+4+d, plen)); i += 4
            elif k == 'b': ins.append((off,name,'b',struct.unpack_from('<b',il,i)[0],plen)); i+=1
            elif k == 'i': ins.append((off,name,'i',struct.unpack_from('<i',il,i)[0],plen)); i+=4
            elif k == 'i8': ins.append((off,name,'i8',struct.unpack_from('<q',il,i)[0],plen)); i+=8
            elif k == 'var1': ins.append((off,name,'var',il[i],plen)); i+=1
            elif k == 'var2': ins.append((off,name,'var',struct.unpack_from('<H',il,i)[0],plen)); i+=2
            elif k in ('tok','str'): ins.append((off,name,k,struct.unpack_from('<I',il,i)[0],plen)); i+=4
            else:
                sz = flat.KSZ[k]; ins.append((off,name,k,il[i:i+sz].hex() if sz else None,plen)); i+=sz
        except Exception as e:
            print(f'!! operand err at {off:04X}: {e}'); break
    return ins

if __name__ == '__main__':
    path, stateVar, swVar, outpath = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    il = open(path,'rb').read()
    ilSize = len(il)
    ins = parse_tolerant(il)
    print(f'parsed {len(ins)} ins, ilSize={ilSize}, covered={ins[-1][0] if ins else 0:X}/{ilSize:X}')
    byoff = {x[0]: x for x in ins}
    disp_map = {}   # dispatch_off -> (targets)
    for ix,x in enumerate(ins):
        if x[1]=='switch' and ix>0 and ins[ix-1][1]=='ldloc' and ins[ix-1][3]==swVar:
            disp_map[x[0]] = x[3]
    disp_offs = sorted(disp_map)
    disp_heads = set()
    for d in disp_map:
        # find preceding ldloc instruction offset
        prev = [x[0] for x in ins if x[0] < d][-1]
        disp_heads.add(prev)
    print('dispatch points:', [hex(d) for d in disp_offs], {hex(d): len(t) for d,t in disp_map.items()})
    print('dispatch heads:', [hex(h) for h in sorted(disp_heads)])
    if not disp_map: print('no switch'); sys.exit(1)
    vars_ = {}; out = []; emitted = set(); pending = [(0,'entry')]; guard = 2000000
    while pending and guard > 0:
        guard -= 1
        start, why = pending.pop()
        if start in emitted: continue
        emitted.add(start)
        out.append(f'=== BLOCK IL_{start:04X} ({why}) ===')
        ip = start
        while True:
            x = byoff.get(ip)
            if x is None:
                out.append('  <end boundary>'); break
            off, name, k, op, plen = x
            L = flat.ins_len(x)
            if name == 'ldloc' and op == swVar:
                nxt = byoff.get(ip+L)
                if nxt and nxt[1] == 'switch' and nxt[0] in disp_map:
                    tg = disp_map[nxt[0]]
                    sv = vars_.get(swVar)
                    if sv is not None and 0 <= sv < len(tg):
                        tgt = tg[sv]
                        out.append(f';; dispatch@{nxt[0]:04X} v{swVar}={sv} -> IL_{tgt:04X}')
                        if tgt in emitted: out.append('  ;; back-edge stop'); break
                        emitted.add(tgt); out.append(f'=== BLOCK IL_{tgt:04X} ==='); ip = tgt; continue
                    else:
                        nf = nxt[0]+5+4*len(tg)
                        out.append(f'  !! OOB v{swVar}={sv} -> fallthrough IL_{nf:04X}'); ip = nf; continue
            if name in ('stloc','stloc.s') and op in (stateVar, swVar):
                val = flat.eval_back(byoff, ins, ip, vars_)
                if val is None: vars_.pop(op, None); out.append(f'  [stloc v{op}] ;; UNKNOWN')
                else: vars_[op] = val; out.append(f'  ;; v{op} = {val} (0x{val:X})')
                ip = ip + L; continue
            if k in ('br1','br4'):
                cond = name not in ('br','br.s','leave','leave.s')
                out.append(f'  (real) {name} IL_{op:04X}')
                if cond: pending.append((ip+L, 'fallthrough'))
                if op in disp_heads:
                    if cond:
                        nxt_ip = ip + L
                        if byoff.get(nxt_ip) is not None and nxt_ip not in emitted:
                            pending.append((nxt_ip, 'join-fallthrough'))
                    ip = op; continue
                if op in disp_map:
                    if cond:
                        out.append('  ;; join dispatch (cond)')
                        nxt_ip = ip + L
                        if byoff.get(nxt_ip) is not None and nxt_ip not in emitted:
                            pending.append((nxt_ip, 'join-fallthrough'))
                    ip = op; continue
                if op in emitted: out.append(f'  ;; join visited IL_{op:04X}'); break
                emitted.add(op); out.append(f'=== BLOCK IL_{op:04X} (branch-target) ==='); ip = op; continue
            if name in ('ret','throw','rethrow','jmp','endfinally','endfilter'):
                out.append(f'  (real) {name}'); break
            if k == 'tok': out.append(f'  {name} 0x{op:08X}')
            elif k == 'var': out.append(f'  {name} v{op}')
            elif k == 'b': out.append(f'  {name} {op}')
            elif k == 'i': out.append(f'  {name} {op} (0x{op&0xFFFFFFFF:X})')
            elif k == 'i8': out.append(f'  {name} {op}')
            elif k == 'sw': out.append(f'  {name} ({len(op)} tgts)')
            elif k == 'n': out.append(f'  {name}')
            else: out.append(f'  {name} {op}')
            ip += L
        if len(out) > 400000: out.append('!! cap'); break
    open(outpath,'w').write('\n'.join(out)+'\n')
    print(f'lines={len(out)} blocks={len(emitted)} guard_left={guard} -> {outpath}')
