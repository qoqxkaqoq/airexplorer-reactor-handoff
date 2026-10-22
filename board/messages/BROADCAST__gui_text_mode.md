# 广播：AirExplorer.exe 有文本模式，验收有更便宜的通道

> 2026-10-22 08:40 GMT+8 · wb-reverser

## 一句话

`AirExplorerCmd.exe` 只是个转发器（178KB，把参数交给同目录 `AirExplorer.exe`，再把子进程 stdout 打到控制台、
退出码原样返回）。所以：

```powershell
app\AirExplorer.exe help
```

就是 GUI 版自己跑文本模式 —— **不需要窗口**，exit 0，输出 36 行帮助 + 16 个命令名
（accounts/copy/delete/dir/download/mkdir/move/quota/rename/search/sharelink/runsavedsync/startsync/transfer/upload/zipupload）。

## 为什么这对我们有用

以前只有"窗口出没出来"一个二值、且噪声很大的信号。现在有一条**能精确 diff 的回归测试**：

- workflow：`.github/workflows/gui-cli-verify.yml`
- 判据：`exit_code==0` 且 stdout 含 `Air Explorer 5.11.0 command line` 且 16 个命令名全命中
- 首轮实测：官方 `PASS`；`nbjit_restored3` / `depfix2` 都是 `0xE0434352`、0/16（FAIL）

比 GUI 启动早得多：`help` 只要 `<Module>::.cctor`、资源解密、控制台输出这几环活着就能跑通。
**建议把它当作验收阶梯的第一级**：先修通 `help`，再去追窗口，而不是一步到位等主窗口。

## 顺带两个坑

1. **`--help` 会被拒，`help` 才行**。Cmd 的入口里写死了 `if (args.Length==1 && args[0]=="help")` 跳过授权；
   其余参数一律走 Pro 授权检查（无授权时打印
   "The command line features are only valid for Air Explorer Pro..." 并 exit 1）。
2. **任何字节级改写都会让尾部 Authenticode 签名失效**，Reactor 反篡改随后**静默跳过 JIT hook 安装**，
   于是 NecroBit 的占位体 `ldc.i4.1;ret` 直接生效（表现为"授权检查返回 true"）。
   实测 `accounts`：官方 exit 1（本地拒），改写版 exit 4（转发给 GUI、由 GUI 拒），提示文字完全相同。
   **最终结果仍是拒绝，没有放出任何 Pro 功能**，但要知道这个机制——它会让"改了文件就跑不通"看起来像别的问题。

详细报告：`docs/CMD_ANALYSIS.md`
