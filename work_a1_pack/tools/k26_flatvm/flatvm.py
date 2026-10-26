#!/usr/bin/env python3
# flatvm.py — concrete-ish interpreter for control-flow-flattened IL (multi-dispatcher aware).
# Dynamic inputs (args, stream data, unknown calls) become DYN objects; concrete ints propagate.
# Every call with any concrete args is logged. switch resolved when state var concrete.
import struct, sys
sys.path.insert(0, r'airexplorer-reactor-handoff/work'); sys.path.insert(0, r'work_a1')
import flat

M32 = 0xFFFFFFFF

class ReturnEx(Exception):
    def __init__(self, value):
        self.value = value

class Dyn:
    _n = 0
    def __init__(self, tag='dyn'):
        Dyn._n += 1
        self.tag = '%s#%d' % (tag, Dyn._n)
    def __repr__(self): return '<%s>' % self.tag

def is_dyn(v): return isinstance(v, Dyn)

class Mem:
    """flat memory: arrays keyed by id; also byref cells"""
    def __init__(self):
        self.arrays = {}
        self.cells = {}
        self._n = 0
    def newarr(self, n):
        self._n += 1
        a = {'_id': self._n, 'len': n, 'data': {}}
        self.arrays[self._n] = a
        return ('arr', self._n)
    def get(self, a, i):
        return self.arrays[a[1]]['data'].get(i, 0)
    def set(self, a, i, v):
        self.arrays[a[1]]['data'][i] = v

class Interp:
    def __init__(self, il, args=None, maxsteps=2_000_000, maxpaths=64, verbose=False):
        self.ins = list(flat.parse(il))
        self.byoff = {x[0]: x for x in self.ins}
        self.args = args or {}
        self.maxsteps = maxsteps
        self.maxpaths = maxpaths
        self.verbose = verbose
        self.calls = []      # (iloff, tok_or_None, name, [argdescs])
        self.halts = []      # (iloff, reason)
        self.results = []

    def run(self):
        paths = [(0, {}, {}, [], 0, Mem())]  # (ip, locals, addrs, stack, steps, mem)
        done = 0
        while paths:
            ip, locals_, addrs, stack, steps, mem = paths.pop()
            steps0 = steps
            while True:
                steps += 1
                if steps > steps0 + self.maxsteps // max(1, self.maxpaths):
                    self.halts.append((ip, 'step-limit'))
                    break
                x = self.byoff.get(ip)
                if x is None:
                    self.halts.append((ip, 'end'))
                    break
                off, nm, k, op, plen = x
                try:
                    r = self.step(off, nm, k, op, locals_, addrs, stack, mem, {}, paths, ip)
                except Exception as e:
                    self.halts.append((ip, 'exc:%r' % e))
                    break
                if r == 'halt':
                    self.halts.append((ip, 'ret/halt'))
                    break
                if r is None:
                    break
                ip = r
            done += 1
            if done >= self.maxpaths:
                break
        return done

    def step(self, off, nm, k, op, locals_, addrs, stack, mem, arrays, paths, ip):
        L = flat.ins_len(self.byoff[ip])
        nxt = self.byoff.get(ip + L)
        nxt_off = nxt[0] if nxt else None
        def jmp(t): return t
        if nm in ('ldc.i4', 'ldc.i4.s'):
            stack.append(op & M32 if op >= 0 else op)
            return nxt_off
        if nm.startswith('ldc.i4.'):
            stack.append(int(nm[-1]))
            return nxt_off
        if nm == 'ldc.i4.m1':
            stack.append(-1); return nxt_off
        if nm in ('ldc.i8', 'ldc.r4', 'ldc.r8'):
            stack.append(op); return nxt_off
        if nm in ('ldarg', 'ldarg.s') or nm.startswith('ldarg.'):
            idx = op if nm in ('ldarg', 'ldarg.s') else int(nm[-1])
            stack.append(self.args.get(idx, Dyn('arg%d' % idx)))
            return nxt_off
        if nm in ('ldloc', 'ldloc.s') or nm.startswith('ldloc.'):
            idx = op if nm in ('ldloc', 'ldloc.s') else int(nm[-1])
            stack.append(locals_.get(idx, 0))
            return nxt_off
        if nm in ('stloc', 'stloc.s') or nm.startswith('stloc.'):
            idx = op if nm in ('stloc', 'stloc.s') else int(nm[-1])
            locals_[idx] = stack.pop() if stack else 0
            return nxt_off
        if nm in ('starg', 'starg.s'):
            stack.pop(); return nxt_off
        if nm == 'ldnull':
            stack.append(None); return nxt_off
        if nm == 'dup':
            stack.append(stack[-1]); return nxt_off
        if nm == 'pop':
            stack.pop(); return nxt_off
        if nm == 'ldsfld':
            if hasattr(self, 'statics'):
                stack.append(self.statics.get(op))
            else:
                stack.append(Dyn('fld%08X' % op))
            return nxt_off
        if nm == 'stsfld':
            v = stack.pop() if stack else None
            self.calls.append((off, ('stsfld', op), nm, [v]))
            if hasattr(self, 'statics'):
                self.statics[op] = v
            return nxt_off
        if nm in ('ldfld', 'ldflda'):
            if stack: stack.pop()
            stack.append(Dyn('flda%08X' % op)); return nxt_off
        if nm == 'stfld':
            if len(stack) >= 2:
                v = stack.pop(); stack.pop()
                self.calls.append((off, ('stfld', op), nm, [v]))
            return nxt_off
        if nm in ('ldstr',):
            stack.append(('str', op)); return nxt_off
        if nm == 'ldtoken':
            stack.append(('tok', op)); return nxt_off
        if nm == 'newarr':
            n = stack.pop()
            n2 = n if isinstance(n, int) else 0x100000
            a = mem.newarr(min(n2, 0x1000000))
            stack.append(a); return nxt_off
        if nm.startswith('ldelem'):
            if len(stack) >= 2:
                idx = stack.pop(); a = stack.pop()
                if isinstance(a, tuple) and a[0] == 'arr' and isinstance(idx, int):
                    stack.append(mem.get(a, idx))
                else:
                    stack.append(Dyn('elem'))
            return nxt_off
        if nm.startswith('stelem'):
            if len(stack) >= 3:
                v = stack.pop(); idx = stack.pop(); a = stack.pop()
                if isinstance(a, tuple) and a[0] == 'arr' and isinstance(idx, int):
                    mem.set(a, idx, v)
                self.calls.append((off, ('stelem', a), nm, [idx, v]))
            return nxt_off
        if nm == 'ldlen':
            if stack:
                a = stack.pop()
                if isinstance(a, tuple) and a[0] == 'arr':
                    stack.append(mem.arrays[a[1]]['len'])
                else:
                    stack.append(Dyn('len'))
            return nxt_off
        if nm in ('ldloca', 'ldloca.s') or nm.startswith('ldloca.'):
            idx = op if nm in ('ldloca', 'ldloca.s') else int(nm[-1])
            c = addrs.get(idx)
            if c is None:
                Mem._n = getattr(Mem, '_n', 0) + 1
                c = ('cell', id(locals_), idx)
                addrs[idx] = c
            stack.append(c); return nxt_off
        if nm.startswith('ldind'):
            a = stack.pop()
            v = mem.cells.get(a, 0) if isinstance(a, tuple) and a[0] == 'cell' else Dyn('ind')
            stack.append(v); return nxt_off
        if nm.startswith('stind'):
            if len(stack) >= 2:
                v = stack.pop(); a = stack.pop()
                if isinstance(a, tuple) and a[0] == 'cell':
                    mem.cells[a] = v
                self.calls.append((off, ('stind', a), nm, [v]))
            return nxt_off
        if nm in ('switch',):
            sv = stack.pop()
            if isinstance(sv, int) and 0 <= sv < len(op):
                t = op[sv]  # flat.parse resolves switch targets to absolute offsets
                return t
            else:
                return nxt_off
        if nm in BINI:
            if len(stack) >= 2:
                b = stack.pop(); a = stack.pop()
                if isinstance(a, int) and isinstance(b, int):
                    stack.append(BINI[nm](a, b))
                else:
                    stack.append(Dyn('num'))
            return nxt_off
        if nm == 'not':
            if stack:
                a = stack.pop()
                stack.append((~a) & M32 if isinstance(a, int) else Dyn('num'))
            return nxt_off
        if nm == 'neg':
            if stack:
                a = stack.pop()
                stack.append((-a) & M32 if isinstance(a, int) else Dyn('num'))
            return nxt_off
        if nm.startswith('conv'):
            if stack:
                a = stack[-1]
                if isinstance(a, int):
                    if nm in ('conv.u1', 'conv.i1'): stack[-1] = a & 0xFF if nm == 'conv.u1' else ((a & 0xFF) ^ 0x80) - 0x80
                    elif nm in ('conv.u2', 'conv.i2'): stack[-1] = a & 0xFFFF
                    elif nm in ('conv.u4', 'conv.u8', 'conv.u', 'conv.r.un'): stack[-1] = a & M32
                    elif nm in ('conv.i4', 'conv.i', 'conv.r4', 'conv.r8'):
                        v = a & M32
                        stack[-1] = v - (1 << 32) if v >= (1 << 31) else v
                    elif nm == 'conv.i8': stack[-1] = a
            return nxt_off
        if nm in ('br', 'br.s'):
            return op
        if nm.startswith('brtrue'):
            c = stack.pop()
            if c is None:
                return nxt_off
            if isinstance(c, int):
                return op if c != 0 else nxt_off
            self.dyn_branch = True
            return nxt_off
        if nm.startswith('brfalse'):
            c = stack.pop()
            if c is None:
                return op
            if isinstance(c, int):
                return op if c == 0 else nxt_off
            self.dyn_branch = True
            return nxt_off
        if nm.startswith('b') and nm not in ('br', 'br.s'):  # beq/bne/bge/bgt/ble/blt...
            if len(stack) >= 2:
                b = stack.pop(); a = stack.pop()
                if isinstance(a, int) and isinstance(b, int):
                    r = COND[nm](a, b)
                    return op if r else nxt_off
                self.dyn_branch = True
                return nxt_off
            return nxt_off
        if nm in ('call', 'callvirt', 'newobj', 'calli'):
            # pop exactly the consumed args when signature known
            self.calls.append((off, op, nm, list(stack[-6:])))
            if hasattr(self, 'call_target'):
                sig = self.call_sig(op, nm)
                if sig is None:
                    args = list(stack); consumed = len(stack)
                else:
                    np_, hasthis = sig
                    consumed = np_ + (1 if (hasthis and nm != 'newobj') else 0)
                    consumed = min(consumed, len(stack))
                    args = stack[len(stack)-consumed:] if consumed else []
                    del stack[len(stack)-consumed:]
                handled, val = self.call_target(op, args, stack, off)
                stack.append(val if val is not None else Dyn('void'))
                return nxt_off
            stack = []
            stack.append(Dyn('ret'))
            return nxt_off
        if nm == 'ret':
            if stack:
                v = stack.pop()
                self.results.append(v)
            self.calls.append((off, None, 'ret', []))
            if getattr(self, 'depth', 0) > 0:
                raise ReturnEx(self.results[-1] if self.results else None)
            return 'halt'
        if nm in ('throw', 'rethrow'):
            self.halts.append((off, nm))
            return 'halt'
        if nm in ('leave', 'leave.s'):
            return op
        if nm == 'endfinally' or nm == 'endfilter':
            self.halts.append((off, nm))
            return None
        if nm == 'nop':
            return nxt_off
        if nm in ('box', 'unbox', 'unbox.any', 'castclass', 'isinst', 'ldobj', 'cpobj', 'ldftn', 'ldvirtftn', 'initobj', 'cpblk', 'initblk', 'sizeof', 'arglist', 'localloc', 'mkrefany', 'refanyval', 'refanytype', 'ckfinite', 'cgt', 'cgt.un', 'clt', 'clt.un', 'ceq'):
            if nm in ('ceq', 'cgt', 'cgt.un', 'clt', 'clt.un'):
                if len(stack) >= 2:
                    b = stack.pop(); a = stack.pop()
                    if isinstance(a, int) and isinstance(b, int):
                        stack.append(1 if COND.get(nm if nm != 'ceq' else 'beq')(a, b) else 0)
                    else:
                        stack.append(Dyn('cmp'))
                return nxt_off
            if nm in ('castclass', 'isinst', 'box', 'unbox.any'):
                if stack: stack[-1] = Dyn('obj')
                return nxt_off
            return nxt_off
        # unknown
        self.halts.append((off, 'unk:%s' % nm))
        return None

BINI = {
    'add': lambda a, b: (a + b) & M32,
    'sub': lambda a, b: (a - b) & M32,
    'mul': lambda a, b: (a * b) & M32,
    'and': lambda a, b: a & b,
    'or': lambda a, b: a | b,
    'xor': lambda a, b: a ^ b,
    'shl': lambda a, b: (a << (b & 31)) & M32,
    'shr': lambda a, b: (a >> (b & 31)) & M32 if a >= 0 else ((a % (1 << 32)) >> (b & 31)),
    'shr.un': lambda a, b: (a & M32) >> (b & 31),
    'div': lambda a, b: int(a / b) if b else 0,
    'div.un': lambda a, b: (a & M32) // (b & M32) if (b & M32) else M32,
    'rem': lambda a, b: a - int(a / b) * b if b else 0,
    'rem.un': lambda a, b: (a & M32) % (b & M32) if (b & M32) else a & M32,
}
COND = {
    'beq': lambda a, b: a == b,
    'bne.un': lambda a, b: (a & M32) != (b & M32),
    'bge': lambda a, b: a >= b,
    'bge.un': lambda a, b: (a & M32) >= (b & M32),
    'bgt': lambda a, b: a > b,
    'bgt.un': lambda a, b: (a & M32) > (b & M32),
    'ble': lambda a, b: a <= b,
    'ble.un': lambda a, b: (a & M32) <= (b & M32),
    'blt': lambda a, b: a < b,
    'blt.un': lambda a, b: (a & M32) < (b & M32),
}
