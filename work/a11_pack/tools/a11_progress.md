# a11_progress.md — A1 线第 10 轮（a11_ 前缀）：崩溃现场深挖（guard17b + 校验缓冲 + clr/ntdll 帧反汇编）
每步：做了什么 / 证据 / 结论 / 下步。接手者从下往上读。

## 任务输入（来自 guard17 已确证现场）
- int3(0x80000003) @ntdll(0x7ffc9c180000)+0x1226c9 tid=12080：rdi=0x8787e6c000（校验缓冲）、rcx=ntdll+0x1621f4、栈上 AirExplorer.exe+0x80、哈希中间值嫌疑 0x620062/0xd400d2/0x20800b4/0x3c0028、[rsp+8]=ntdll+0xfab05（调用者）。
- fail-fast(0x04242420) @0x7ffc996e408a：栈上 0x31415927、clr.dll(0x7ffc7e950000)+0x37bca1、clr.dll+0x1413d7。
- 待办：guard17b（dump 缓冲+深栈+回溯）、缓冲 vs exe 对比、clr/ntdll 帧反汇编、JIT 帧定位。

## [2026-10-25 21:05] 启动：环境确认
- 做法：读 a9_guard17.py/log.txt、a8_progress 尾部、memdump/module_text.bin（9,596,928B = RVA 0x2000..0x929000 运行时 .text，rva→file=rva-0x2000+0x200）。
- 证据：python3+capstone5.0.7+numpy+pycryptodome 可用；localapp_crash=篡改副本（flip@文件 0x927BA8）。
- 下步：解析篡改 exe PE 头确定 flip 所在节；离线反汇编 ntdll/clr 帧。
