# 复验：`qoqxkaqoq/1` 的 v84b「终局交付」不通过

> 复验时间：2026-10-22 04:31 (Asia/Shanghai)
> 复验对象：`unpacked-final` 制品（run 39526859528）中的 `unpacked/AirExplorer.exe`
> SHA-256：`a79160adaba6cc3f273a8b3955676139abd73eb1d034432b8cfe07f208e05b36`（与制品声明一致）
> 复验副本：`exes/AirExplorer_v84b_unpacked.exe`

## 结论

**不通过。** 进程存活、窗口标题正确，但**主窗口是一个 300×300 的空白窗体，没有任何控件**——
工具栏、账号树、文件列表全都不存在。按本项目验收标准（"主窗口 UI，网盘内容可见"）判定为失败。

`qoqxkaqoq/1` 的 `agents.md` 里写的「v84b 独立启动即出主窗 'Air Explorer v5.11.0'，PASS」
是**真的**（窗口确实出来了），但**判据只看了标题，没看窗内内容**，属于"假阳性验收"。

## 证据（同一 runner、同一准备流程、同一探针）

| 指标 | 原版（baseline） | v84b 脱壳版 |
|---|---|---|
| 主窗口标题 | `Air Explorer v5.11.0` | `Air Explorer v5.11.0` |
| 主窗口尺寸 | **945 × 788**（78,78 → 1023,866） | **300 × 300**（52,52 → 352,352） |
| 进程窗口总数 | **20** | **6** |
| 控件类窗口 | 有 `tooltips_class32`、`ComboBox`、`HwndWrapper[MediaContext]` 等 | 仅 `GDI+ Hook`/`IME`/`BroadcastEvent` |
| 窗体内容 | 工具栏（Explore/Accounts/Search/Synchronize/Scheduler/Options/View/Tools/Pro Version）+ Add Category、Add account、搜索框、Import/Export + 账号树 `All` | **纯空白** |
| 截图 | `docs/evidence/baseline_mainwindow.png` | `docs/evidence/v84b_mainwindow_blank.png` |
| 探针日志 | run 39670879405 | run 39670863129（`docs/evidence/v84b_probe.log`） |

窗口数 20 → 6 是最直接的量化指标：WinForms 每创建一个控件都会建子窗口句柄，控件树塌了才会只剩 6 个。

## 它不是"没脱壳"，而是"UI 构建链没恢复"

静态对比（`tools/stats`，同一套工具）：

| 版本 | 方法体数 | `ldstr` | 空壳桩 | switch |
|---|---|---|---|---|
| 原版 | 22930 | 46 | 5808 | 77 |
| nb_original | 22930 | 1331 | 1705 | 8244 |
| **v84b** | **25346** | **2099** | **110** | 9437 |

方法体恢复率已经很高（空壳只剩 110），说明 NecroBit 体恢复是成功的；
**失败点在 UI 构建**：主窗体的控件创建依赖资源/字符串/VM 解释执行的初始化链，
而 v84b 的补丁日志自己写了 `资源装载链中和`、`_ExtractorVisitors 已提升为 public`、
`InstantiateGlobalCalculator 已重写 (最小字段初始化)`——
这些"中和/最小化"把**窗体内容构建所依赖的初始化**一起去掉了。

换句话说：为了让 cctor 能过，把初始化链削成了刚好不抛异常的最小集；
进程能活、窗口能建（因为 `new MainForm()` 本身不抛），但控件没被创建。

## 复验方法（可复现）

```bash
# 1. 取制品
curl -H "Authorization: Bearer <token>" \
  https://api.github.com/repos/qoqxkaqoq/1/actions/artifacts/12363789246/zip

# 2. 用本仓库探针跑（会关闭模态框后 PrintWindow 主窗口）
#    workflow_dispatch: candidate=exes/AirExplorer_v84b_unpacked.exe
```

判据不要用"进程存活/标题存在"，要用：

1. 主窗口 `GetWindowRect` 尺寸 ≥ 800×600；
2. 进程窗口数 ≥ 15（有控件树）；
3. 主窗口 `PrintWindow` 截图**非纯色**（可用像素方差判定）；
4. 有 `Add account` / 工具栏按钮的可访问性子窗口。

本仓库 `tools/ci/probe.ps1` 已产出 1/2/3 三项数据，建议把"截图像素方差"也加进 workflow 的 PASS 判定。

## 建议的下一步（针对 UI 构建链，而不是继续调方法体）

1. 以原版为 A 侧、v84b 为 B 侧，**只比对主窗体构造链**：
   `MainForm..ctor` → 控件创建方法 → 资源键字符串 → 图标/图像加载。
2. 把 v84b 里"中和/最小化"的初始化逐项放回（`InstantiateGlobalCalculator` 用原版真体，
   而不是最小字段初始化），用 A/B 截图做回归。
3. 验收脚本改成上面 4 条硬指标，避免再出现"标题在、内容空"的假阳性。
