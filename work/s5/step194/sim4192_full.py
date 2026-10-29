#!/usr/bin/env python3
# Full sentinel algorithm reconstruction driven by real exe bytes
import struct, hashlib, importlib.util
spec = importlib.util.spec_from_file_location('flat', '/root/repo_git/work/flat.py')
flat = importlib.util.module_from_spec(spec); spec.loader.exec_module(flat)

exe = open('/root/repo_git/exes/AirExplorer_baseline_verified.exe','rb').read()
ins = flat.parse(open('/root/work/step194/4192_body.bin','rb').read())
byoff = {x[0]: x for x in ins}
INSLEN = {x[0]: flat.ins_len(x) for x in ins}
disp_map = {}
for ix,x in enumerate(ins):
    if x[1]=='switch' and ix>0 and ins[ix-1][1]=='ldloc' and ins[ix-1][3]==31:
        disp_map[x[0]] = x[3]

class FakeStream:
    def __init__(self, data): self.d = data; self.pos = 0
    def seek(self, o): self.pos = o; return o
    def read(self, n):
        b = self.d[self.pos:self.pos+n]; self.pos += len(b); return b
    def tell(self): return self.pos

class Log:
    def __init__(self): self.events = []
    def e(self, s): self.events.append(s)

sha = hashlib.sha1()
log = Log()
st = FakeStream(exe)   # v20

def T(fb):   # TransformBlock wrapper
    sha.update(fb); log.e(f'  HASH += {len(fb)}B @stream_before_pos')
    return len(fb)

# --- 直接按解码的语义执行（非指令级，按块语义）---
# 块1: @03D3 41E2(SHA1, v20, 152, v18) -> read 152 & hash
b = st.read(152); T(b); log.e(f'block1 [0x00,0x98) pos={st.pos:#x}')
# @0712: ReadInt32 @0x98 (BinaryReader on same stream)
r = st.read(4); v = int.from_bytes(r, 'little'); log.e(f'@0712 ReadInt32@0x98 = {v} (0x{v:X}) magic_ok = {v==523}')
if v == 523: v7 = 112
else: v7 = 96
log.e(f'v7 = {v7}')
# @0879: Seek(152) + Read(v7)
st.seek(152)
b2 = st.read(v7)
# 清零 v18[64..67] => exe 0x98+64 = 0xD8 (checksum) if v7>=68
b2 = bytearray(b2)
for i in range(64, 68): b2[i] = 0
T(bytes(b2)); log.e(f'block2 [0x98,0x98+{v7}) cs_zeroed @exe 0xD8 pos={st.pos:#x}')
# @08B9: Read 128
b3 = bytearray(st.read(128))
# 清零 v18[32..39] => exe 0xF8+32 = 0x118 (Security DD)
for i in range(32, 40): b3[i] = 0
T(bytes(b3)); log.e(f'block3 [0xF8,0x178) secdd_zeroed @exe 0x118 pos={st.pos:#x}')
# @0908: v3 = Position ; @0911 Seek(0x86) ; @091E ReadInt16/32 -> v8 ; @0927 Seek(v3)
v3 = st.pos
st.seek(0x86)
r = st.read(2)   # 41E3: ReadInt16? nsec
v8 = int.from_bytes(r, 'little')
st.seek(v3)
log.e(f'v3(pos)={v3:#x} v8=ReadInt16@0x86={v8}')
# @0930: TransformBlock(v8*40) = section table
b4 = st.read(v8*40); T(b4); log.e(f'block4 sectable [0x178,0x178+{v8*40}) pos={st.pos:#x}')
# @0940: v25 = Position
v25 = st.pos
# 节表解析
secs = []
for i in range(v8):
    o = 0x178 + i*40
    name = exe[o:o+8].rstrip(b'\0').decode()
    vsz, rva, rsz, praw = struct.unpack_from('<IIII', exe, o+8)
    secs.append((name, praw, rsz))
    log.e(f'  sec {name} raw=0x{praw:X} size=0x{rsz:X}')
# --- 循环区解码 ---
# @049D: Seek(0x178=376)? 不——节表已在 block4。循环里的 Seek(0x178) 又来？
# 观测: @0513 Seek(v3 + v30*40 + 16); @05E0 v28 = Read...; @05B6 Seek(v27); @06C2 T(v28); @06D4..; @06EA v28 -= v4
# @067E: v24 = 41EB(v26, v10) 在循环内? -- 不合理, v24 是签名
# 重新走: @060A v17=Position; @0613..; @065E v30=0; @0666..; 循环体 @0666: v24=41EB(v26,v10)!!
# 也许循环确实每轮读 v24?? 但 v24 是 VerifyHash 参数... 每轮覆盖, 最后一轮生效!
# 按节循环模拟:
for i in range(v8):
    name, praw, rsz = secs[i]
    # @0513: Seek(v3 + v30*40 + 16) -- v3 这里是节表基址? v3=@0908 保存的 Position(0x178)
    st.seek(v3 + i*40 + 16)
    # @05E0: v28 = Read...(41E7) -- SizeOfRawData
    v28 = int.from_bytes(st.read(4), 'little')
    # @05B6: Seek(v27) -- v27 = ? 数据偏移; 节 raw ptr = praw = +20 字段
    st.seek(praw)
    v17 = st.pos
    # @067E: v24 = 41EB(v26, v10) = ReadBytes(v10)??? 不对..
    # @06C2: T(read v28)
    b = st.read(v28); T(bytes(b))
    # @06D4: Seek(pos + v4) ; @06EA: v28 -= v4 ...
log.e(f'loop done pos={st.pos:#x}')
# @0222: TransformFinalBlock(empty)
log.e(f'final. SHA1 = {sha.hexdigest()}')
print('\n'.join(log.events))
