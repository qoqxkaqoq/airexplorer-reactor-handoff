#!/usr/bin/env python3
"""
gh_sync.py — 走 GitHub API 提交文件（用于 git 直连不可用/代理不支持认证推送的环境）。

用法:
    # 提交若干路径到仓库 main 分支
    python3 scripts/gh_sync.py push -m "message" board/README.md board/agents/xxx.md

    # 提交到指定分支（分支不存在会自动基于 main 创建）
    python3 scripts/gh_sync.py push -b my-branch -m "message" exes/AirExplorer_xxx.exe

    # 删除路径
    python3 scripts/gh_sync.py rm -m "message" exes/old.exe

Token 来源（按优先级）:
    1) 环境变量 GITHUB_TOKEN
    2) 仓库根目录下 .gh_token 文件（该文件本身必须已被 gitignore）

说明:
    - 每次都基于远端最新 commit 建 tree（base_tree），只覆盖你显式传入的路径，
      因此多个 agent 并发提交时不会互相抹掉对方的改动（后提交者赢在其路径上）。
    - 大文件（exe）通过 Git Data API 的 blob 接口上传，支持到 100MB。
"""
import argparse
import base64
import json
import time
import os
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"
REPO = "qoqxkaqoq/airexplorer-reactor-handoff"
UA = "gh_sync.py (multi-agent handoff)"


def get_token():
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        return tok.strip()
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".gh_token")
    if os.path.exists(p):
        return open(p).read().strip()
    sys.exit("缺少 GITHUB_TOKEN 环境变量或仓库根的 .gh_token 文件")


def req(method, path, token, data=None, raw=False):
    url = API + path
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, method=method)
    r.add_header("Authorization", "Bearer " + token)
    r.add_header("Accept", "application/vnd.github+json")
    r.add_header("User-Agent", UA)
    if body:
        r.add_header("Content-Type", "application/json")
    raw_bytes = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(r, timeout=300) as resp:
                raw_bytes = resp.read()
            break
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:800]
            sys.exit("HTTP %s %s -> %s\n%s" % (e.code, method, path, detail))
        except (TimeoutError, OSError) as e:
            print("[gh_sync] retry %d/%d after %s: %s" % (attempt + 1, 4, type(e).__name__, e), flush=True)
            if attempt == 3:
                raise
            time.sleep(5)
    if raw:
        return raw_bytes
    return json.loads(raw_bytes.decode())


def ref_path(branch):
    return "/repos/%s/git/refs/heads/%s" % (REPO, branch)


def get_head(token, branch):
    """返回 (commit_sha, tree_sha)"""
    try:
        d = req("GET", ref_path(branch), token)
    except SystemExit:
        # 分支不存在 -> 基于 main 创建
        base = req("GET", ref_path("main"), token)["object"]["sha"]
        req("POST", "/repos/%s/git/refs" % REPO, token,
            {"ref": "refs/heads/" + branch, "sha": base})
        d = req("GET", ref_path(branch), token)
    commit = req("GET", "/repos/%s/git/commits/%s" % (REPO, d["object"]["sha"]), token)
    return d["object"]["sha"], commit["tree"]["sha"]


def upload_blobs(token, paths, deleted):
    entries = []
    for p in paths:
        with open(p, "rb") as f:
            content = f.read()
        b64 = base64.b64encode(content).decode()
        blob = req("POST", "/repos/%s/git/blobs" % REPO, token,
                   {"content": b64, "encoding": "base64"})
        entries.append({"path": p, "mode": "100644", "type": "blob", "sha": blob["sha"]})
        print("  blob %-60s %8d bytes" % (p, len(content)))
    for p in deleted:
        entries.append({"path": p, "mode": "100644", "type": "blob", "sha": None})
    return entries


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_push = sub.add_parser("push")
    p_push.add_argument("-m", "--message", required=True)
    p_push.add_argument("-b", "--branch", default="main")
    p_push.add_argument("paths", nargs="+")

    p_rm = sub.add_parser("rm")
    p_rm.add_argument("-m", "--message", required=True)
    p_rm.add_argument("-b", "--branch", default="main")
    p_rm.add_argument("paths", nargs="+")

    a = ap.parse_args()
    token = get_token()
    branch = a.branch

    missing = [p for p in a.paths if not os.path.isfile(p)] if a.cmd == "push" else []
    if missing:
        sys.exit("文件不存在: %s" % ", ".join(missing))

    print("[gh_sync] branch=%s" % branch)
    head, base_tree = get_head(token, branch)
    print("[gh_sync] head=%s" % head[:8])

    entries = upload_blobs(token, a.paths if a.cmd == "push" else [],
                           a.paths if a.cmd == "rm" else [])
    tree = req("POST", "/repos/%s/git/trees" % REPO, token,
               {"base_tree": base_tree, "tree": entries})
    commit = req("POST", "/repos/%s/git/commits" % REPO, token,
                 {"message": a.message, "tree": tree["sha"], "parents": [head]})
    req("PATCH", ref_path(branch), token, {"sha": commit["sha"], "force": False})
    print("[gh_sync] pushed %s -> %s" % (commit["sha"][:8], branch))
    print("[gh_sync] https://github.com/%s/commit/%s" % (REPO, commit["sha"]))


if __name__ == "__main__":
    main()
