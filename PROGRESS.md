
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

## WebView2 安装进展（2026-10-28 00:xx）

- **已装**：WebView2 Runtime 109.0.1518.140（Evergreen 标准路径+注册表 pv ✓）
  —— msedgewebview2.exe 在 Program Files (x86)/Microsoft/EdgeWebView/Application/109.0.1518.140/
- **版本不足**：AirExplorer 的 WebView2 SDK=1.0.1418.22，Runtime 109 < 1418 → SDK 环境创建失败 → 主区域仍黑
- **新版 Runtime 获取受阻**：fwlink 2124703 绑定旧 109 包；edgeupdates API 无 WebView2 项；
  Fixed Version x64 的 fwlink 未找到（2099617 是 X86 190MB）；Edge Enterprise msi 是引导型无法解包
- **下一棒**：(a) 微软 CDN 直接 GUID 链接（社区已知 1418+ 的 Fixed Version cab）
  (b) 或用 X86 包的思路找 X64 对应 fwlink
  (c) 或用 WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS/WEBVIEW2_BROWSER_EXECUTABLE_FOLDER
      指向手动下载的 Fixed Version 解压目录（微软官方支持的环境变量）
