#!/bin/bash
# build.sh — 构建 AirExplorerUnpacker (net8.0 + NuGet dnlib) 并可选执行 S1
# 用法: ./build.sh [build|s1|pipeline]
#   build     仅构建
#   s1        构建 + 全量 S1 体注入 -> out/m1_s1_full.exe
#   pipeline  预留 (S1..S5)
set -e
cd "$(dirname "$0")"

export DOTNET_ROOT=${DOTNET_ROOT:-/usr/share/dotnet}
command -v dotnet >/dev/null 2>&1 || { echo "dotnet not found"; exit 1; }

MODE=${1:-build}

dotnet build -c Release AirExplorerUnpacker.csproj

CLI="dotnet bin/Release/net8.0/AirExplorerUnpacker.dll"
REPO_ROOT="$(cd ../.. && pwd)"
MT="$REPO_ROOT/work_a1_pack/memdump/module_text.bin"
MANIFEST="$REPO_ROOT/work/c2_pack/bodies_manifest.tsv"
ZIP="$REPO_ROOT/work/dump_official_16598.zip"
SLAYED="$REPO_ROOT/work_a1_pack/nrs/AirExplorer_test_Slayed.exe"

mkdir -p out
case "$MODE" in
  build)
    echo "[build.sh] build only"
    ;;
  s1)
    $CLI s1 "$SLAYED" "$MT" "$MANIFEST" "$ZIP" out/m1_s1_full.exe
    ;;
  *)
    echo "unknown mode: $MODE"; exit 2
    ;;
esac
