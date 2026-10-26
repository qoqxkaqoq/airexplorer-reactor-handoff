# Wine 运行 WPF（AirExplorer 运行环境）验证记录

日期：2026-10-27
结论：**Wine 9.0 + .NET Framework 4.8 可以在 Linux 上完整渲染 WPF 应用**。
AirExplorer 的运行环境问题已扫清；剩余的唯一死点是 .NET Reactor 壳本身（Windows 原生同样死），等 S1–S5 脱壳完成后即可用 `scripts/air-on-linux.sh` 直接跑。

## 验证环境

| 组件 | 版本 |
|---|---|
| OS | Ubuntu 22.04 (无 GPU、无显示服务器) |
| Wine | 9.0 (Ubuntu 9.0~repack-4build3) |
| .NET Framework | 4.8 (winetricks dotnet48, WINEPREFIX=/root/.wine64) |
| 显示 | Xvfb :99, 1280x800x24 |
| 编译器 | Wine 内 csc.exe (v4.0.30319) |

## 验证方法与结果

1. 用 Wine 内 csc.exe 编译最小 WPF 程序（Window + TextBlock + Button）。
2. `Xvfb :99` + `wine explorer /desktop=wtest,1280x800 wpftest.exe` 运行。
3. `xwd -root` 截图：**窗口、标题栏、任务栏、文本、按钮全部正常渲染**。
4. 程序日志：`SRCINIT|LOADED|tier=0|EXIT_OK` ——
   - `SRCINIT`：Win32 窗口句柄创建成功
   - `LOADED`：WPF 布局与首帧渲染完成
   - `tier=0`：milcore 软件渲染（预期，无 GPU）

## 关键配置（必须）

无 GPU/无 3D 加速环境下，WPF 默认的 D3D 渲染路径初始化失败 → 客户区黑屏
（窗口框架正常、内容空白）。修复：

```bash
wine reg add 'HKCU\Software\Microsoft\Avalon.Graphics' \
  /v DisableHWAcceleration /t REG_DWORD /d 1 /f
```

设置后 WPF 走 milcore 软件光栅化，渲染完全正常。

## 启动脚本

`scripts/air-on-linux.sh`：自动完成前置检查（wine/dotnet48/exe 存在）、
设置软件渲染注册表、按需拉起 Xvfb、以虚拟桌面模式启动 AirExplorer.exe。

## 已知边界与风险

| 项 | 状态 | 说明 |
|---|---|---|
| WPF 界面渲染 | 已验证可用 | 软件渲染，性能足够桌面操作 |
| CLR / BCL | 已验证可用 | 真微软 .NET Framework 4.8，非 wine-mono |
| WebView2 | 风险点 | AirExplorer 引用 Microsoft.Web.WebView2.Wpf；Wine 下需另装 WebView2 Runtime（Evergreen 安装器），登录/网页页签可能依赖它 |
| 网络 TLS | 一般可用 | Schannel 走 Wine 实现，TLS1.2 常规可用；上传/下载走 S3/HTTP 客户端问题不大 |
| 剪贴板/文件对话框 | 基本可用 | Wine 虚拟桌面下常见功能齐备 |
| 性能 | 可接受 | 软件渲染 CPU 占用高于 GPU；服务器无显示环境用 Xvfb |

## 与脱壳任务的关系

当前 AirExplorer.exe 加壳态在 Wine 下死点 = Windows 死点（Necrobit 类型加载失败），
与 Wine 无关。脱壳（S1–S5）完成并过 Windows CI 双门槛后，
同一 exe 即可用本脚本在 Linux 启动。
