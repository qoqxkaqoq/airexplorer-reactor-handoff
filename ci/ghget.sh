#!/bin/bash
# ghget.sh <artifact_id> <outdir>   — 经代理下载 GitHub artifact 并解压
set -e
TOKEN=${GH_TOKEN:-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}
ID=$1
OUT=${2:-/tmp/ghart}
REPO=qoqxkaqoq/airexplorer-reactor-handoff
API="https://p.xixky.eu.org/https://api.github.com/repos/$REPO/actions/artifacts/$ID/zip"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' -H "Authorization: token $TOKEN" "$API")
if [ -z "$LOC" ]; then echo "no redirect"; exit 1; fi
mkdir -p "$OUT"
curl -sL "$LOC" -o "$OUT/a.zip"
rm -rf "$OUT/x"
unzip -o -q "$OUT/a.zip" -d "$OUT/x"
ls -la "$OUT/x"
