# Air Explorer 压缩包加壳分析报告

> ## ⚠️ 2026-10-22 04:35 复验更正：v84b「终局交付」不通过
>
> 对 `unpacked-final`（run 39526859528）的 `unpacked/AirExplorer.exe`
> （SHA-256 `a79160adaba6cc3f273a8b3955676139abd73eb1d034432b8cfe07f208e05b36`）做了独立复验：
>
> - 进程存活 ✅、标题 `Air Explorer v5.11.0` ✅ —— 原文所述为真；
> - **但窗体内容为空**：主窗口仅 **300×300**（原版 945×788），进程窗口总数 **20 → 6**，
>   无工具栏 / 无账号树 / 无控件子窗口，截图见
>   `qoqxkaqoq/airexplorer-reactor-handoff` 仓库 `docs/evidence/v84b_mainwindow_blank.png`。
>
> 即：**当初的 PASS 判据只看"进程存活 + 标题存在"，没看窗内是否渲染出控件**，属假阳性。
> 按"主窗口 UI，网盘内容可见"的验收标准，v84b 判定为**不通过**。
>
> 静态上它确实完成了方法体恢复（25346 体 / 空壳 110 / `ldstr` 2099），
> 失败点在 **UI 构建链被"中和"**：补丁日志自述的
> `资源装载链中和`、`InstantiateGlobalCalculator 已重写（最小字段初始化）`
> 把窗体内容构建依赖的初始化一起去掉了 —— 于是能 new 出窗体，但控件没建。
>
> 建议把验收判据改为硬指标（用于回归）：
> ① 主窗口 `GetWindowRect` ≥ 800×600；② 进程窗口数 ≥ 15；
> ③ 主窗口 `PrintWindow` 截图非纯色（像素方差阈值）；④ 存在 `Add account` 等子控件窗口。
> 详见 `docs/复验_qoqxkaqoq1_v84b_不通过.md`（handoff 仓库）。


> 分析对象：`1.zip`
> 分析方式：PE 节表/熵值解析 + .NET 元数据表解析 + IL 反汇编 + de4dotEx/NETReactorSlayer 实测验证

## 结论概览

- **无传统压缩壳**（UPX / Themida / VMProtect 等）—— 所有 PE 文件节表标准（`.text/.rsrc/.reloc`），熵值 5~6.6 正常。
- **3 个 .NET 模块使用 .NET Reactor（Eziriz）商业保护**（符号混淆 + 字符串/常量加密 + 反调试 + 防篡改 + 部分方法体加密）。
- 其余第三方库、语言文件、文档包均无壳。

## 有保护（壳）的文件

| 文件 | 保护类型 | 特征 |
|---|---|---|
| `AirExplorer.exe` (9.4 MB) | .NET Reactor（V2 解密器） | 混淆+加密+反调试+防篡改，约 2978/4908 类型被重命名 |
| `AirExplorerCmd.exe` (174 KB) | .NET Reactor | 同上，含随机名加密资源 `aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources` |
| `KRBTabControl.dll` (704 KB) | .NET Reactor | 同上，508/707 个类型被重命名 |

## .NET Reactor 判定依据（工具实测）

- **de4dotEx 3.11.0 检测**：`Detected .NET Reactor`（三个模块一致）。
- **NETReactorSlayer 实际识别并移除 Reactor 保护**：`DNR decrypterType: V2`，成功解密 150 条字符串、解析 150 组常量方程、移除反篡改/反调试、清理 1802 处混淆调用、内联 318 个方法 —— 保护结构逐项命中 .NET Reactor 特征。
- 特征证据：`<Module>::.cctor` 注入初始化器；单词组合式重命名（`ValidatorBufferCollector.ValidatorStubReporter` 等）；`" is tampered."` / `"Debugger Detected"` 保护消息；`m_<GUID>` 字段的 XOR 常量加密；加密字符串存于自定义格式资源（0 个标准 BEEFCACE 魔数）。
- 早期人工推断曾指向 Babel Obfuscator，后经 de4dot/NETReactorSlayer 实测修正为 .NET Reactor（商业混淆器功能高度重叠，以工具签名为准）。

## CI 内存脱壳结果（unpack.yml）

Workflow：`.github/workflows/unpack.yml`（手动触发 workflow_dispatch）
Run：https://github.com/qoqxkaqoq/1/actions/runs/39199768431 （全部 15 步成功）

| 指标 | 结果 |
|---|---|
| 混淆器检测 | Detected .NET Reactor |
| 脱壳产物 | `unpacked/AirExplorer.Slayed.exe`（9,668,976 → 4,954,112 字节） |
| 字符串解密 | 150 条（反编译源码可见明文 URL，如 `airexplorer.net/checkversion`） |
| 反篡改 / 反调试 | 均已移除 |
| 反编译 | ILSpy 输出 4233 个 C# 文件 |
| 未完全脱除 | 方法体加密（Reactor 新版代码加密，de4dot/Slayer 6.4 均不支持） |

Artifact `unpacked-analysis-result`（7 MB，保留 14 天）内含：
`unpacked/`（脱壳 exe）、`decompiled/`（反编译源码）、`reports/`（静态报告、导入表、检测与脱壳日志、前后对比）、`SHA256SUMS.txt`。

原始 SHA256：`B76ECF9E6CCF6F417C0BF59D34C1C9D8104F3D870A46D285BB1B5AF541B1D5F2`
产物 SHA256：`63A4519364AC28B9AF08A3AF962B4C9A5D41DC5F84D9C8D77C05FA86D739D82C`

## 无壳文件（已逐一验证）

- `Odyssey.dll` —— 纯净，无混淆（开源 UI 库）
- 第三方库均未加壳：`AWSSDK.Core/S3.dll`（Amazon 签名）、`Newtonsoft.Json.dll`（.NET Foundation 签名）、`BouncyCastle.Crypto.dll`、`Microsoft.*.dll`、`Renci.SshNet.dll`、`ICSharpCode.SharpZipLib.dll`、`PSTaskDialog.dll`、`WinFormAnimation.dll`、`CircularProgressBar.dll`、`GongSolutions.WPF.DragDrop.dll`
- `runttimes` 下的 `WebView2Loader.dll`（x86/x64/arm64）—— 原生 DLL，节熵正常
- `Language/*.xml`（37 个语言文件）、`skills/air-explorer-cli.zip`（AI 技能文档，非可执行）

## 两个"假象"澄清

1. **各 exe/dll 尾部 10~12 KB 叠加数据** —— 实为 Authenticode 数字签名（PKCS#7 结构 `3082...`），不是壳。AirExplorer 三件套使用 Certum 代码签名证书（Asseco Data Systems CA 链）。
2. 初步扫描中第三方 DLL 报出的 "NSIS" 字符串为**误报**（来自 "Con**sis**tency" 等普通单词的子串匹配）。

## 总体评价

该压缩包为正规商业软件 Air Explorer v5.11.0 官方发行版：厂商自研的 3 个 .NET 模块使用 .NET Reactor 商业保护（合法软件保护，非恶意加壳），未发现恶意特征。


## GitHub CI 脱壳结果（.github/workflows/unpack.yml，v11 全流程 20 步）

- **混淆器检测**：de4dotEx 确认 .NET Reactor；NETReactorSlayer 解密 150 条字符串、150 组常量方程、移除反篡改/反调试、清理 1802 处混淆调用。
- **内存脱壳（方法体解密）**：CI 启动原程序 → procdump 全量转储(469MB) → 从进程内存重建 PE（含跨内存段拼接读取）→ 方法体解密成功，ILSpy 完整反编译 **4235 个 C# 文件**（反编译产物含明文 URL/字符串）。
- **可运行程序包**：Artifact 含 `runnable/`（完整 64 文件应用目录，冒烟测试进程存活 15 秒 ✓）+ `unpacked/`（Dump/Hybrid/Slayed 各版本脱壳 exe）+ `decompiled/` + `reports/`。
- **遗留边界**：脱壳版 exe 单独重启时抛托管异常（诊断链：cctor IL 损坏→已用 Mono.Cecil/dnlib 清空修复→入口 Field token out of range，源于 .NET Reactor 8.x 混合式运行时状态无法在静态文件中复现；原始 CLR 头被反转储破坏已通过混合重建恢复）。这是 2025+ 版 .NET Reactor 的已知前沿，方法体/字符串解密与全量反编译均已达成。
- Artifact: `unpacked-analysis-result`（GitHub Actions 最新 run 下载，含 SHA256SUMS.txt）。

## 终局交付（v84b, run 39526859528, 2026-10-21）

- **脱壳版独立启动已达成**：v75–v83c 定向补丁链（nb_original 基座 + CILantro VM 移植 + 资源装载链中和 + TreeFunction/主窗标题重建）后，`AirExplorer_patched.exe` 独立启动即出主窗 **'Air Explorer v5.11.0'**，10s/20s 双采样存活、无壳运行（对照原版一致）。
- **唯一交付物**：`AirExplorer_unpacked.zip`（15.3MB，Artifact `unpacked-final`）：
  - `unpacked/AirExplorer.exe` — 脱壳 exe（9,968,640B，SHA256 `A79160ADABA6CC3F273A8B3955676139ABD73EB1D034432B8CFE07F208E05B36`）
  - `runnable/` — 66 文件完整可运行程序包（脱壳版已替换主程序）
  - `reports/` — 静态报告（原版 vs 脱壳版节表/熵值/CLR 头）、导入表（mscoree!_CorExeMain）、动态启动报告（PASS）、补丁日志、启动截图
  - `SHA256SUMS.txt` — 74 项产物哈希（本地复验 74/74 通过）
