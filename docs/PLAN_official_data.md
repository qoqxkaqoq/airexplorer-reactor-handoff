# 方案：用官方运行时数据替换"猜"出来的 locals 签名与 EH 子句

> 2026-10-23 · wb-reverser
> 三线并行：A 改 hook 重收割 ｜ B dawwinci Krypton fork ｜ C Windbg TTD

## 0. 根因回顾（为什么这三条路是对的）

v1–v66 期间手工修的两大类问题，全部源于 nbjit dump 的数据缺失：

| 缺失数据 | 手工替代方案 | 错误规模 |
|---|---|---|
| locals 签名（dump 头 `localsTok=0`） | `fixlocals` 从 cilantro 按名/序号猜 | 5126 个方法、33847 个 locals |
| EH 子句（`nbrestore` 按 28 字节自算，步长错） | `fixeh` 从 cilantro 按序号搬 | 1721 个 catch 里 1515 个类型坏 |

而这两块数据在 JIT 入口 `CORINFO_METHOD_INFO` 里**本来就有**：

```c
struct CORINFO_METHOD_INFO {
    ftn; scope; BYTE* ILCode; unsigned ILCodeSize; maxStack; EHcount;
    options; regionKind;
    CORINFO_SIG_INFO args;
    CORINFO_SIG_INFO locals;   // ★ locals.tok = 官方 StandAloneSig token (0x11xxxxxx)
};                             //     locals.pSig/cbSig = 官方 LocalVarSig blob
```

来源：
- wwh1004《.NET JIT 脱壳指南与工具源码》/ JitUnpacker-Framework（仅支持 ≤4.72）
- 0x指纹《Windbg TTD 还原 .NET JIT 保护壳探索》2025-06，实测对 .NET Reactor 6.9.0
  全开 NecroBit（体+locals 签名+EH 三保护）成功还原
- dawwinci/krypton-devirtualizer（PeterG75 Krypton 续作），NecroBit body restoration
  "reinjects them with correct locals/EH/maxstack"

## 方案 A：升级 clrjit_hook 到 v4，重跑一次收割

autoreaktor `v3/jitdump/clrjit_hook.cpp` 的 v4 已经实现：

1. **localsTok 提取**：扫描 `CORINFO_METHOD_INFO` 前 0xC0 字节找唯一的
   `0x11xxxxxx`（StandAloneSig）dword，即 `locals.tok`；
2. **官方 EH 段快照**：EH clause 区就在 IL 字节之后（4 对齐），探针定位
   kind=0x66 的 section，整段快照进 `.bin` 尾部（`preExtra` 字段记长度）；
3. dump 头升级为 6 字段：`{token, ilSize, maxStack, ehCount, preExtra, localsTok}`。

**落盘后离线即可**（无需跑程序）：

- `localsTok != 0` → dnlib `ResolveToken(0x11xxxxxx)` → 官方 StandAloneSig →
  LocalSig → 每个方法的**真 locals 类型**，替代 `fixlocals` 的猜测；
- `.bin` 尾部 `preExtra` 字节 → 官方 EH clause 表（Flags/TryOffset/.../ClassToken），
  替代 `nbrestore` 的 28 字节自算和 `fixeh` 的搬运。

现状：仓库里的 16598 个 `.bin` 是**旧版 hook** 产物（6 字段全 0/旧义，无 EH 尾段），
需要用 v4 hook 重跑一次 nbjit workflow（约 2 分钟）。
工作流已改为 checkout 本仓库 `ci/jitdump/clrjit_hook.cpp` 覆盖 autoreaktor 的同名文件。

## 方案 B：dawwinci Krypton fork（现成引擎交叉验证）

克隆 `dawwinci/krypton-devirtualizer`（PeterG75 续作），`build-all.ps1` 构建：

- `Krypton.Runner --standalone-check <exe>`：加载程序集、跑全部类型初始化器、
  JIT 预备所有方法、按异常类型分组报告——**全量体检**，直接给出"还剩哪些方法会炸"；
- `Krypton.exe <exe> --no-pause`：完整管线（VM 还原 + HiddenCallRecovery +
  NecroBit body restore，重注入带正确 locals/EH/maxstack），
  产出 `*-Devirtualized.exe`；
- 环境变量 `KRYPTON_ENABLE_NECROBIT_BODY_RESTORE=1`、`KRYPTON_ALLOW_PARTIAL_OUTPUT=1`。

注意：Krypton 主打 VM 去虚拟化，AirExplorer 未见 VM handler，但它的
NecroBit body restore 与 standalone-check 是通用能力，即使 VM 部分空转也有价值。

## 方案 C：Windbg TTD（反调试免疫的兜底）

原理：TTD 录制整个启动过程 → 时间旅行调试 → 反调试/反篡改全部失效。
bin4re 实测对 Reactor 6.9.0 三保护全开成功。

流程（x64）：

```
TTD.exe -out trace.run AirExplorer_e8runnable.exe help    # 录制到退出
cdb/windbgx 打开 trace.run → .scriptload JitScan.js
  → dx @$cursession.TTD.Calls("clrjit!CILJit::compileMethod") 枚举每次 JIT
  → SeekTo 每次调用, x64 下 info = r8
  → 读 info 前 0xC0 字节: ILCode/ILCodeSize/EHcount/locals.tok
  → 读 locals.pSig/cbSig → 官方 LocalVarSig blob
  → (可选) getEHinfo 逐个取官方 CORINFO_EH_CLAUSE
  → 输出 JSON → dnlib 写回
```

CI 无头运行用 `windbgx -c ".scriptload ...; q"`；JS 脚本见
`ci/ttd/JitScan.js`（自带，不依赖 bin4re 仓库结构）。

## 三方案的预期交汇点

无论哪条路拿到数据，后续处理完全一致：

1. `tools2/nbrestore` 升级：优先用 dump 内的官方 localsTok/EH 段；
2. 全量重建 v100：官方体 + 官方 locals + 官方 EH，**零猜测**；
3. 剩余问题（`RequestVerifierTransformer..ctor` 的 32 locals、
   `m_ProjectDecorators` 写入路径）变成纯数据替换。

## 验收不变

主窗口 `visible=True` 且客户区渲染正常（网盘内容可见），
文本模式 16/16 PASS 维持。
