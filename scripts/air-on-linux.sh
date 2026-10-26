#!/usr/bin/env bash
# air-on-linux.sh — 在 Linux 上用 Wine 运行 AirExplorer（WPF / .NET Framework 4.8）
#
# 已验证环境（2026-10）：Ubuntu 22.04 + Wine 9.0 + winetricks dotnet48
# 验证结论：WPF 渲染管线完整可用（窗口/文本/按钮全部正常），
#          关键是禁用 WPF 硬件加速 → 走 milcore 软件渲染（tier=0）。
#
# 用法:
#   ./air-on-linux.sh                        # 用默认目录与分辨率启动
#   ./air-on-linux.sh /path/to/appdir        # 指定 AirExplorer.exe 所在目录
#   ./air-on-linux.sh . 1600x900             # 指定目录与虚拟桌面分辨率
#   DISPLAY=:0 ./air-on-linux.sh             # 有真实 X 显示时直接用
#
set -e

APP_DIR="${1:-$HOME/.wine64/drive_c/airtest}"
GEOM="${2:-1280x800}"
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine64}"

# 1. 前置检查 ---------------------------------------------------------------
command -v wine >/dev/null 2>&1 || {
  echo "[!] 未安装 wine。需要: wine9(含 wine32) + winetricks"; exit 1; }

DOTNET_WPF="$WINEPREFIX/drive_c/windows/Microsoft.NET/Framework64/v4.0.30319/WPF"
[ -d "$DOTNET_WPF" ] || {
  echo "[!] WINEPREFIX 缺少 .NET Framework 4.8，先执行:"
  echo "    WINEPREFIX=$WINEPREFIX winetricks dotnet48"; exit 1; }

[ -f "$APP_DIR/AirExplorer.exe" ] || {
  echo "[!] 未找到 $APP_DIR/AirExplorer.exe"; exit 1; }

# 2. WPF 软件渲染（无 GPU 环境必须；有 GPU 也不影响）------------------------
wine reg add 'HKCU\Software\Microsoft\Avalon.Graphics' \
  /v DisableHWAcceleration /t REG_DWORD /d 1 /f >/dev/null 2>&1 || true

# 3. 无 X 显示时自动起 Xvfb --------------------------------------------------
if [ -z "${DISPLAY:-}" ]; then
  XVFB_DISP=:99
  if ! xdpyinfo -display "$XVFB_DISP" >/dev/null 2>&1; then
    Xvfb "$XVFB_DISP" -screen 0 "${GEOM}x24" >/tmp/xvfb_air.log 2>&1 &
    XVFB_PID=$!
    trap '[ -n "${XVFB_PID:-}" ] && kill $XVFB_PID 2>/dev/null || true' EXIT
    sleep 1
  fi
  export DISPLAY="$XVFB_DISP"
fi

# 4. Wine 虚拟桌面模式启动 ----------------------------------------------------
echo "[+] 启动 AirExplorer @ DISPLAY=$DISPLAY, 桌面 ${GEOM}"
cd "$APP_DIR"
exec wine explorer /desktop="AirExplorer,${GEOM}" AirExplorer.exe
