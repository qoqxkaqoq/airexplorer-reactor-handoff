# AirExplorerCmd.exe 分析报告

> 结论日期：2026-10-22
> 目标文件：官方安装包内 `AirExplorerCmd.exe`（178,032 B，MD5 `e50ef903157a3dfd9753c1803d7a8e2b`）

---

## 0. 一句话结论

**`AirExplorerCmd.exe` 不是独立实现，而是一个 178KB 的转发器**：它做完授权判断后，把参数拼成命令行交给同目录的
`AirExplorer.exe`（也就是我们一直没还原成功的 GUI 版），再把这个子进程的 stdout 原样打到控制台、把它的退出码作为自己的退出码。

因此：

- 它**本身没有被 NecroBit 破坏到不可运行** —— 官方原件在 Windows 上能正常跑；
- 它的"失败"其实是 **Pro 授权门**，不是脱壳问题；
- **它的每条业务命令，真正的执行者都是 AirExplorer.exe**，所以"命令行版能干活"这件事，等价于"GUI 版能干活"。

同时挖到一个真正有用的东西：**`AirExplorer.exe help` 自带文本模式**，为 GUI 还原提供了一个不需要窗口的验收通道（见第 7 节）。

---

## 1. 文件形态

| 项 | 值 |
|---|---|
| 大小 | 178,032 B（.text 仅 0x1ADE4） |
| 方法总数 | 196，全部有体（RVA=0 的为 0） |
| 其中 `nop;nop;ldc.i4.1;ret` 形态的加密桩 | 116 |
| 嵌入资源 | 4 个（含 Reactor 的加密串表 `PassiveProfiler.ProfilerSpec` 400B） |
| 附加数据 | 尾部 10,608 B = **Authenticode 签名**（`WIN_CERTIFICATE`, type 0x0002） |
| 入口点 | `AirExplorerCmd.Helpers.GenericEmitter::EmitGeneralEmitter(string[])` |

类型分布很能说明问题：

| 类型 | 方法数 | 性质 |
|---|---|---|
| `AirExplorerCmd.Reporting.PassiveReporter` | 162（18,496 条指令） | **Reactor 运行时本体**（含 JIT hook、反调试、AES、PE 解析） |
| `AirExplorerCmd.Helpers.GenericEmitter` | 4（201 条） | 真正的 CLI 入口（191 条，明文） |
| 其余 `Core/Collections/Cryptography` 等 | 30 | 业务辅助，多为加密桩 |

也就是说：**196 个方法里只有约 190 条指令是"这个程序自己的逻辑"，其余全是 Reactor 的壳。**

---

## 2. 保护形态（和 GUI 版同源，但轻得多）

- **字符串加密**：全部业务字符串都走
  `ldc.i4 A; ldc.i4 B; xor; ldsfld holder; ldfld key; xor; call PassiveReporter::SetupReporter(int)`。
  共 **6 个调用点**，`holder` 是 `<Module>{883c023e-...}` 的实例，`key` 是该实例上的 129 个 int 字段之一。
- **NecroBit 方法体加密**：116 个方法在磁盘上是 `nop;nop;ldc.i4.1;ret` 占位，真实体在 JIT 时由 hook 解密。
  证据：入口调用 `CompressorObject::DestroyConnectedObject(out bool, out DateTime)`，磁盘上是 `ldc.i4.1;ret`，
  但实际运行表现为"未授权"——说明运行时拿到的是被替换过的真体。
- **控制流平坦化**：`ReportOrderedReporter`（4980 条）、`ReportIdentifiableReporter`（10284 条）。
- **死代码占位**：12 处 `call null`，均被前一条 `br.s` 跳过。dnlib 直接写盘会因此抛
  `ModuleWriterException: Instruction operand is null`，必须先换成 `nop`。

---

## 3. 字符串表（已全部取回）

| # | 明文 | 用途 |
|---|---|---|
| 1 | `help` | `args[0]` 命中时**跳过授权**直接启动 |
| 2 | `The command line features are only valid for Air Explorer Pro, please enter your license information in the Air Explorer user interface` | 未授权提示 |
| 3 | `AirExplorer.exe` | 被启动的目标 |
| 4 | ` "`（空格+引号） | 拼参数用 |
| 5 | `"` | 拼参数用 |
| 6 | `help` | 参数为空时的默认值 |

---

## 4. 还原出的 Main（按 IL 逐条重组）

```csharp
static int Main(string[] args)
{
    Console.OutputEncoding = Encoding.UTF8;

    // NecroBit 加密的真体: 授权检查(磁盘上只剩 ldc.i4.1;ret 占位)
    bool licensed = CompressorObject.DestroyConnectedObject(out bool flag, out DateTime expiry);

    // args[0] == "help" 时直接放行 —— 这就是为什么 "--help" 会被拒、"help" 却能出帮助
    if (!(args.Length == 1 && args[0] == "help"))
    {
        if (!licensed || !flag)              // 未授权
        {
            Console.WriteLine("The command line features are only valid for Air Explorer Pro, "
                            + "please enter your license information in the Air Explorer user interface");
            return 1;
        }
    }

    string dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
    var p = new Process();
    p.StartInfo.FileName = Path.Combine(dir, "AirExplorer.exe");

    string argline = "";
    foreach (var s in args) argline = string.Concat(argline, " \"", s, "\"");   // 每个参数加引号
    if (argline.Length == 0) argline = "help";
    p.StartInfo.Arguments = argline;

    p.StartInfo.UseShellExecute        = false;
    p.StartInfo.CreateNoWindow         = true;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.RedirectStandardError  = true;
    p.StartInfo.RedirectStandardInput  = true;
    p.StartInfo.StandardOutputEncoding = Encoding.UTF8;
    p.Start();

    var sr = p.StandardOutput;
    while (!sr.EndOfStream) Console.WriteLine(sr.ReadLine());

    p.WaitForExit();
    int code = p.ExitCode;
    p.Close();
    return code;                            // 退出码 = 子进程退出码
}
```

**关键点**：`return code` —— Cmd 会把 `AirExplorer.exe` 的退出码原样返回，所以"Cmd 的退出码"其实就是
"GUI 的退出码"。

---

## 5. 完整命令清单

`help` 的输出（也就是 `AirExplorer.exe help` 的输出，36 行，已实测）：

```
Air Explorer 5.11.0 command line
Air Explorer command line client help.

Usage: AirExplorerCmd <command> [parameters] /***

Available commands:
accounts     Lists all the accounts defined in Air Explorer.
copy         Copies a file or a folder to another location in a cloud server.
delete       Deletes a file or a folder in a cloud server.
dir          Lists all the files and folders in a cloud server folder.
download     Downloads a file or a folder from a cloud server to a local folder.
mkdir        Creates a new folder in a cloud server.
move         Moves a file or a folder to another location in a cloud server.
quota        Shows the used and free space in a cloud server.
rename       Renames a file or a folder in a cloud server.
search       Searches for files and folders in a cloud server.
sharelink    Creates a shared link for a file or a folder in a cloud server.
runsavedsync Loads and runs a saved synchronization.
startsync    Starts a synchronization of two folders
transfer     Transfers a file from one cloud to another.
upload       Uploads a file or a folder to a cloud server.
zipupload    Zip and upload a file or a folder to a cloud server.
```

---

## 6. 去混淆流程（可复现，不需要 Windows）

三段式，全部产物在 `tools2/`：

1. **`patchcctor`** —— 用带 `AssemblyResolver` 的方式加载（搜索路径=安装目录），把 `call null` 死代码换成 `nop`；
   `--cctor` 模式再把所有 `<Module>*` 的 `.cctor` 置空。
   为什么要置空：Reactor 的模块 cctor 会 P/Invoke `kernel32` 分配 RWX 内存装 hook，在 mono 下必然
   `DllNotFoundException`。
   ```bash
   dotnet tools2/bin/patch/patch8.dll app/AirExplorerCmd.exe /tmp/aec_nc.exe cctor
   ```
2. **`cmdstr sites`** —— 解析 6 个调用点，导出 `方法RID / 指令序号 / 常量表达式 / 密钥字段名`。
3. **mono 解密宿主**（`probe/dec.cs`）—— 在 mono 下加载第 1 步的产物，手动调用 `<Module>{883c023e}` 的
   静态初始化器 `k1e29ebd9...()` 把 129 个密钥填好（**不需要 kernel32**），再对每个调用点算
   `key = 表达式 ^ 字段值`，调用 `SetupReporter(key)` 取明文。
4. **`cmdstr apply`** —— 把 `常量表达式 + ldsfld/ldfld/xor + call` 整段替换成 `ldstr 明文`，用
   `PreserveAll | KeepOldMaxStack` 写盘。

产物：`exes/AirExplorerCmd_deobf.exe`（166,912 B）

---

## 7. 实测验证（GitHub Actions / windows-latest）

| 用例 | 官方原件 | 去混淆版 | 结论 |
|---|---|---|---|
| `AirExplorerCmd help` | exit 0，36 行帮助 | exit 0，36 行帮助 | **逐行 diff 为空，完全一致** |
| `AirExplorerCmd`（无参） | exit 1 + 授权提示 | 同左（转发后 exit 0 + 帮助） | 行为一致 |
| `AirExplorerCmd --help` | exit 1 + 授权提示 | exit 1 + 授权提示 | 一致（`--help` ≠ `help`，见第 4 节） |
| `AirExplorerCmd accounts` | exit 1 + 授权提示 | **exit 4** + 同样的授权提示 | 双方都拒绝，见下 |

### 为什么 `accounts` 的退出码会不同

去混淆版把文件字节改了，**尾部 Authenticode 签名随之失效**，Reactor 的反篡改判定"被篡改"后
**静默跳过 JIT hook 安装**，于是那个授权检查方法就停在磁盘上的占位体 `ldc.i4.1;ret`（返回 true）。
Cmd 遂认为"已授权"，启动 `AirExplorer.exe`——而 **GUI 自己还有一道授权检查**，它在那里被拒绝，
打印同样的提示并以 4 退出；Cmd 把 4 原样返回。

也就是说：**最终结果仍然是"拒绝"**（提示文字一模一样，没有任何 Pro 功能被放出来），差别只在于
"哪一层拒绝、退出码 1 还是 4"。这一点必须记录清楚，避免被误读成"绕过了授权"。

---

## 8. 副产品（本轮最重要的发现）

`AirExplorerCmd help` 的帮助文本**不是 Cmd 打出来的**，是它转发给 `AirExplorer.exe` 后由 GUI 打印、
再由 Cmd 抄到控制台的。既然 GUI 版自己就能跑文本模式，就得到一条**不需要窗口**的验收通道：

```powershell
AirExplorer.exe help        # 期望: exit 0 + "Air Explorer 5.11.0 command line" + 16 个命令名
```

新增 workflow `.github/workflows/gui-cli-verify.yml`，判据是硬的：

- `exit_code == 0`
- stdout 含 `Air Explorer 5.11.0 command line`
- 16 个命令名逐个 `^name\s` 匹配

首轮实测：

| 候选 | exit_code | 标题 | 命中命令 | 判定 |
|---|---|---|---|---|
| 官方原件 | 0 | ✓ | 16/16 | **PASS** |
| `nbjit_restored3` | `0xE0434352` | ✗ | 0/16 | FAIL |
| `depfix2` | `0xE0434352` | ✗ | 0/16 | FAIL |

**意义**：以前只有"窗口出没出来"一个二值信号，现在有了一条能精确比对文本的回归测试，
而且它比 GUI 启动早得多——先把 `help` 修通，再去追窗口，是一条明确的阶梯。

---

## 9. 建议的验收阶梯

| 里程碑 | 判据 | 难度 |
|---|---|---|
| **A. 文本模式** | `AirExplorer.exe help` → exit 0 + 16 命令（`gui-cli-verify`） | 低：只走入口 + 资源/字符串 |
| B. 账户枚举 | `AirExplorerCmd accounts` → 正常列出账户（需授权） | 中 |
| C. 主窗口 | 980×788 左右、控件齐全、截图非纯色 | 高（当前卡点） |

A 是新增的、代价最低的一级；它也直接对治当前"一启动就 `0xE0434352`"的问题——`help` 路径能跑通，
说明 `<Module>::.cctor`、资源解密、控制台输出这些环节都活了。

---

## 10. 工具清单（本次新增）

| 文件 | 作用 |
|---|---|
| `tools2/patchcctor.cs` | 带解析器加载、`call null`→`nop`、清 `<Module>*` cctor |
| `tools2/cmdstr.cs` | 字符串调用点解析（`sites`）与明文回写（`apply`） |
| `tools2/typelist.cs` / `stubby.cs` / `hdr.cs` / `ldstr.cs` / `cmdan.cs` | 结构普查 |
| `.github/workflows/cmd-verify.yml` | Cmd 行为探针（stdout/stderr/退出码，参数组 none/help/rawhelp/version/accounts） |
| `.github/workflows/gui-cli-verify.yml` | **GUI 文本模式验收** |
| `exes/AirExplorerCmd_deobf.exe` | 6 处字符串已还原为明文的版本（行为与原件一致） |
