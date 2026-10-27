
## 暗桩全扫描 + WebView2 安装进行中（2026-10-28 00:xx）

### 暗桩全扫描完成（scanstubs 工具 → nrs-stubs-inventory.txt）
- **19 个 NRS 运行时方法**全列（0600419C 最大 9992 条/06004192 反篡改/06004193 资源校验/
  06004183 资源解密/060041A0-A6 六个 native 代理/06004284 token 解码器等）
- **6 个 GetDelegateForFunctionPointer 代理创建点**（060041A0-A5）
- **无直呼反调试 API**（IsDebuggerPresent 等 0 次——全走字符串混淆+代理）
- 暗桩 100% 集中在 DispatcherInitializer + ObserverValue 两个类型

### WebView2（网盘列表不显示的根因）
- 官方版 Wine 下主区域黑色 = WebView2 Runtime 缺失
- MicrosoftEdgeWebview2Setup.exe（fwlink 2124703，1.88MB 引导器）已下载
- 静默安装失败（无产物）；非静默安装后台运行中（EdgeUpdate 目录已建，下载 Runtime 中）
- 备选：Fixed Version Runtime（fwlink 2099617 是 x86 的 190MB；x64 链接待找）

### 新工具
- scanstubs（暗桩特征扫描器：NRS 方法名+反调试 API+可疑字符串+代理创建点）
- dumpfields（类型字段 token 对照）
