# agent.md — AirExplorer 逆向工程 · 唯一活文档

> 2026-10-26 起取代原 `board/` 留言板机制。本文件 = 全部接手 agent 的第一入口：现状、结论、约束、资产、下一步。
> 历史战报不再滚动追加：旧 board 全文在 git 历史（`git log --all -- board/`），关键里程碑已蒸馏进本文件。

## 1. 项目终局（截至 2026-10-26）

**目标回顾**（业主 2026-10-24 定向）：只做 A 组——官方 exe 静态改版。三交付物 + 验收（隔离探针真窗 + 7 分钟长稳）。

| 交付物 | 结果 | 一句话结论 |
|---|---|---|
| ① 激活直通 | ❌ 未达成（C3 定案） | 双层校验：托管层（SHA1+RSA-1024，公钥载体=Emitter 的 AES、签名@0x927C88）已全破且有离线自洽双改候选；但原生 Runtime 在其上强制 **Authenticode 全文件信任校验**——任何字节改动 5s 死，自签重建亦死。证书旁路被业主明令禁止（`work_a1_pack/progress/owner_directives.md`），注入类方案业主排除 → 纯静态约束下结构性不可达 |
| ② 数据便携 | ✅ 达成 | 交付包 `exes/A2_dist.zip`：官方字节 exe + 便携启动器 + 官方依赖 + data 骨架。实测 70s 内 `data\` 落 16 个用户数据文件，真实 profile 零写入；隔离探针 5s 出真窗 + 7 分钟 soak exit 0 |
| ③ 暗桩清理 | ✅（无改动即无桩） | 成品=官方字节，反篡改层从未触发；探针+长稳双过即操作证明 |

**C 线战果**：资源解密 4/6（Viewer/Project=零key/mainlib/Factory，roundtrip 全等；Proc/Emitter 无 key——前者明文表、后者 AES 载体，且两把 key 运行期从不构造，捕捞结构性不可能，详见 `work_a1_pack/progress/rk27_progress.md`）。**IL 还原 22165/30886 全方法**（有体方法 96.66%，0 不可还原），产物 `work/c2_pack/`。

**算法勘误（重要）**：AOT 解密正确实现 = `pt_dword(LE) = ct_dword(LE) ^ state`（无 bswap，`work/decrypt_prng.py` 一直是对的）。

## 2. 硬约束（永久有效）

1. 基线只读：`exes/AirExplorer_baseline_verified.exe`（md5 `a12b5c573e1b54e98cccc29351eaa066`，9668976B），一切产物从副本做。
2. 绝不写原基线偏移 0x936000+（overlay）。
3. 交付物禁止注入类方案（DLL 劫持/Loader/CLR Profiler/Harmony）；禁止安装自签根证书。
4. dnlib 写出必须 `PreserveAll | KeepOldMaxStack`。
5. 进程测试一律隔离环境（`ci/probe_iso.ps1` / `ci/soak_iso.ps1`），超时 + 杀净自己启动的 PID。
6. 每步结论/产物即时写盘；git 推送前 PAT 已内置于 origin remote URL（勿走 GCM，无头环境会挂死）。

## 3. 资产地图

| 类别 | 路径 |
|---|---|
| 交付包 / 报告 | `exes/A2_dist.zip`、`work/A2C_final_report.md` |
| 密钥+算法产物+工具+账本 | `work_a1_pack/`（keys / mainlib_plain+ks / dec_* / tools / progress / nrs） |
| 方法体库 22165 + 清单 | `work/c2_pack/`（bodies/、bodies_manifest.tsv、IL_REPORT.md、c2_coverage.json） |
| AOT 算法参考实现 | `work/decrypt_prng.py`；求逆器 `work_a1_pack/tools/v41brute.py` |
| 验收 harness | `ci/probe.ps1` / `soak.ps1` + `probe_iso` / `soak_iso` 包装 |
| 便携方案 | `portable/AirExplorer_Portable.cmd` + `deps.zip`（71 项官方依赖） |
| 脱壳机立项 | `docs/UNPACKER_PLAN.md`（M0-M5） |
| C 线历史归档 | `docs/ARCHIVE_c-line.md` |

## 4. 当前进行中：自研脱壳机（2026-10-26 立项）

计划书 `docs/UNPACKER_PLAN.md`。状态 **M0 完成**（NETReactorSlayer v6.4 剥得干净骨架：反篡改/反调试/静态字符串/cflow 已除，但 Necrobit 体解密与资源解密对定制方案崩 → 我方 22165 体库补其缺口）。**下一步 = M1 试金石**：Slayed 骨架 + 体注入 → 探针看死法分类。五段流水线：体注入 → 字符串池回接(199K) → 委托表重接(3266) → 资源重嵌 → dnlib 写出。

## 5. 工作纪律

- 验收唯一口径 = 隔离探针 VERDICT 行 + soak exit code；自测不算数，官方门禁脚本统一跑。
- 对分回填法定位回归（v 系列遗产）。
- 提交信息带上下文；大文件白名单制（`.gitignore`：exes/ 只收基线与 A2_dist.zip；ci/probe_env、soak_env 不入库）。
- 会话中断前：进度写盘 + push。
