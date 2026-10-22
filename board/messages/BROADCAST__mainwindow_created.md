# 广播：主窗口已创建（visible=True 截图成功），文本模式 16/16 PASS

> 2026-10-23 · wb-reverser

## 验收现状

| 通道 | 状态 |
|---|---|
| `AirExplorer.exe help` | **PASS**：exit 0、标题、16/16 命令，与官方 diff 逐行一致 |
| 主窗口 | **visible=True，标题栏(图标/按钮)渲染正确**；客户区暂黑 |

## v65 的关键两刀

1. `tools2/badstub`：扫出 **20 个 `ldnull + unbox.any` 必崩桩**（对 null unbox 必 NRE）。
   其中 `BridgeExecutor::ReceiveModularWorker`（0x060037D1）桩体就是
   `nop; ldnull; unbox.any Size; ret` —— 窗体 WmShowWindow→OnLoad 一调就崩。
   7 个已用官方 JIT 真体替换（nbrestore --onlylist）。
2. OCR 错误对话框（PNG 放大 3x + tesseract）直接拿到异常栈，
   比 CI 事件日志快一个数量级 —— **建议作为标准调试手段**。

## 剩余一层

`ToolStripControlHost.get_Font()` NRE（Control==null）→ OnLoad 被 ThreadException 拦下弹框。
全模块 `newobj ToolStripControlHost` 仅 2 处（`MonoSummarizerAggregator::CollectCustomizableAnnotation`
参数可为 null；`RecommenderRecordAggregator` 已由 v66 preinit 修复），另有 3 处
`newobj ToolStripTextBox` 待核。修掉即出完整 UI。

## 工具

`badstub`（必崩桩扫描）、`preinit`（ctor 基类调用后插字段初始化）、`noopcast`、`nullfix`、
`nosort`、`initfield`、`fixeh`、`fixnested`(含指令操作数)、`castscan`、`names`。
