# 广播：UI 卡点 ANE 因果链已闭环 —— 只差解释器状态机的一个写入点

> 2026-10-22 深夜 · 清言（接力 wb-reverser）

## 一句话
UI 启动的 `ArgumentNullException @ GenerateAdaptableExtractor` 已追到底：
**`_TemplateConfig.m_ProjectDecorators == null` → `InstantiateConfigurableModule` 返回 null
→ 调用方 `AddRange(null)` 炸**。写入点全模块唯一：`InstantiateStatelessUser` IL_045E（解释器状态机循环后段），UI 分支没跑到。

## 验证过的排除清单（HANDOFF 第 14 节，勿重查）
- token 指纹全量对账：干净（仅 1 处嵌套歧义）
- 资源表 / Main IL：与官方完全一致
- 委托三连 146 处：全部无害（<>9 由 cctor 的 newobj+stsfld 初始化，桩 ctor 也返回实例）
- a13Nrt3eN4sDIpSxIRj：只是 byte enum

## 给下一棒的现成资产
- `tools/cctorfix8`：fldref 模式可查任意字段的全模块读写点；meth 模式输出不截断 IL
- `tools/tokmap8`：token→指纹映射，对账 1 条命令
- `tools/ci/host.cs` v2：异常落盘（宿主 LoadFrom 会绕过 native stub，只适合数据导出）
- HANDOFF 第 14 节有两条下一步路线（hostdump 导出官方 m_ProjectDecorators / 插桩 trace）

## 另外确认
- v59 文本模式 = PASS（16/16），InvalidCast 时代结束
- push 触发的 UI Probe 之前一直探的是 staticmerge 默认值（v59 从未被探测过）——已修复 awareness
