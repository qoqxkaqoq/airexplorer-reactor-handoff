#!/usr/bin/env python3
# 4192 single-path deterministic walk (first call, all predicates known)
import re, importlib.util
spec = importlib.util.spec_from_file_location('flat', '/root/repo_git/work/flat.py')
flat = importlib.util.module_from_spec(spec); spec.loader.exec_module(flat)
ins = flat.parse(open('/root/work/step194/4192_body.bin','rb').read())
byoff_ins = {x[0]:x for x in ins}
idx_of = {x[0]:i for i,x in enumerate(ins)}

disp_map = {}
for ix,x in enumerate(ins):
    if x[1]=='switch' and ix>0 and ins[ix-1][1]=='ldloc' and ins[ix-1][3]==31:
        disp_map[x[0]] = x[3]

# predicates known for first call on healthy baseline exe:
# brtrue@0059 on m_Ext(null) -> FALL
# brfalse@0089 on v2(nonnull) -> FALL
# brtrue@22F7 on 41CD(v2) ok -> TAKE
# brtrue@0AF7 on File::Exists(v2)=true -> TAKE
# brtrue@0A12 on c(=0) -> FALL
# brfalse@00F1 on c(=0) -> TAKE
# brtrue@0B75 on v26 -> ?  (v26 谓词)
TAKE = {0x0059: False, 0x0089: False, 0x22F7: True, 0x0AF7: True, 0x0A12: False, 0x00F1: True}

ip, v0, v31, c = 0, 0x68537B95, 8, None
path = []
steps = 0
while steps < 60000:
    steps += 1
    x = byoff_ins.get(ip)
    if x is None: path.append(f'{ip:04X} <END>'); break
    off, name, k, op, plen = x
    L = flat.ins_len(x)
    if name == 'ldloc' and op == 31:
        nxt = byoff_ins.get(ip+L)
        if nxt and nxt[1]=='switch' and nxt[0] in disp_map:
            tg = disp_map[nxt[0]]
            if isinstance(v31,int) and 0 <= v31 < len(tg):
                path.append(f'disp[{v31}] -> {tg[v31]:04X}')
                ip = tg[v31]; continue
            else:
                nf = nxt[0]+5+4*len(tg)
                path.append(f'disp OOB v31={v31} -> fall {nf:04X}')
                ip = nf; continue
    if name in ('stloc','stloc.s'):
        val = flat.eval_back(byoff_ins, ins, off, {0: v0, 31: v31, 12: c})
        if op == 31:
            v31 = val & 0xFFFFFFFF if val is not None else None
            path.append(f'{off:04X} v31={"??" if v31 is None else f"{v31:08X}"}')
        elif op == 0:
            v0 = val & 0xFFFFFFFF if val is not None else None
            path.append(f'{off:04X} v0={"??" if v0 is None else f"{v0:08X}"}')
        elif op == 12:
            c = val if val is not None else 'RUNTIME'
            path.append(f'{off:04X} c = {c}')
        ip += L; continue
    if k in ('br1','br4'):
        cond = name not in ('br','br.s','leave','leave.s')
        if not cond:
            path.append(f'{off:04X} {name} {op:04X}')
            ip = op; continue
        take = TAKE.get(off)
        if take is None:
            # 哨兵块内 ceq 结果等: 遇到未知谓词 -> 记录并停
            path.append(f'{off:04X} {name} {op:04X} [UNKNOWN-PRED stop]')
            break
        path.append(f'{off:04X} {name} {op:04X} [{"TAKE" if take else "fall"}]')
        ip = op if take else ip+L
        continue
    if name in ('ret','throw','endfinally'):
        path.append(f'{off:04X} {name}'); break
    if name == 'leave':
        path.append(f'{off:04X} leave {op:04X}'); ip = op; continue
    if name in ('stelem.i1','stelem.i','stelem.i2','stelem.i4','stelem.ref','ldc.i4.s','conv.i4','conv.i8','conv.u8','ldloca.s','ldc.i4','ldc.i4.0','ldc.i4.1','ldc.i4.2','ldc.i4.3','ldc.i4.4','ldc.i4.5','ldc.i4.6','ldc.i4.7','ldc.i4.8','ldloc.s','ldloc','ldloc.0','ldloc.1','ldloc.2','ldloc.3','add','sub','stloc','stloc.s','stloc.0','stloc.1','stloc.2','stloc.3','nop','dup'):
        ip += L; continue
    # note interesting calls
    if k == 'tok':
        nm = {0x060041CE:'SHA1.Create',0x060041CF:'MapNameToOID',0x060041D0:'File.Exists',
              0x060041D1:'41D1(File?)',0x060041D2:'41D2',0x060041D3:'41D3',0x060041D4:'41D4',
              0x060041D5:'41D5',0x060041D6:'41D6',0x060041D7:'41D7',0x060041D8:'41D8',
              0x060041D9:'41D9',0x060041DA:'41DA',0x060041DB:'41DB',0x060041DC:'41DC',
              0x060041DD:'41DD',0x060041DE:'41DE',0x060041DF:'41DF',0x060041E0:'41E0',
              0x060041E1:'41E1',0x060041E2:'41E2',0x060041E3:'41E3',0x060041E6:'41E6',
              0x060041EB:'41EB',0x060041ED:'41ED',0x060041EE:'41EE',
              0x060041CC:'41CC',0x060041CD:'41CD',0x060041C9:'41C9',0x060041CA:'41CA'}.get(op)
        if name in ('call','callvirt','newobj') and (nm or 0x06004264 == op):
            path.append(f'    {off:04X} {name} {nm or hex(op)}')
    ip += L

print('\n'.join(path))
