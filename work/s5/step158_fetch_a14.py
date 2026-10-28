#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step158: download s5probe artifact for a14 (two-step: redirect then unauthenticated) and print verdict."""
import os, sys, zipfile, io, urllib.request

TOKEN = None
for line in os.popen('cd /workspace/repo_git && git remote get-url origin'):
    import re
    m = re.search(r'ghp_[A-Za-z0-9]+', line)
    if m: TOKEN = m.group(0)
RUN = sys.argv[1] if len(sys.argv) > 1 else '40776075931'
PFX = 'https://p.xixky.eu.org/https://api.github.com/repos/qoqxkaqoq/airexplorer-reactor-handoff'
H = {'Authorization': 'token %s' % TOKEN, 'Accept': 'application/vnd.github+json'}

def api(path):
    req = urllib.request.Request(PFX + path, headers=H)
    return urllib.request.urlopen(req, timeout=60).read()

# run status
import json
st = json.loads(api('/actions/runs/%s' % RUN))
print('[run %s] status=%s conclusion=%s' % (RUN, st['status'], st['conclusion']))
if st['status'] != 'completed':
    sys.exit(0)

arts = json.loads(api('/actions/runs/%s/artifacts' % RUN))
for a in arts.get('artifacts', []):
    print('  artifact:', a['name'], a['id'], a['size_in_bytes'])
name = [a for a in arts.get('artifacts', []) if 'a14' in a['name']]
if not name:
    print('NO a14 artifact'); sys.exit(1)
aid = name[0]['id']

# two-step download: redirect url then unauthenticated
req = urllib.request.Request(PFX + '/actions/artifacts/%s/zip' % aid, headers=H)
r = urllib.request.urlopen(req, timeout=60)
url = r.geturl()  # follows redirect; urllib follows 302 automatically with auth header dropped? keep manual
z = urllib.request.urlopen(r.geturl(), timeout=180).read()
zf = zipfile.ZipFile(io.BytesIO(z))
for n in zf.namelist():
    if n.endswith('.log'):
        txt = zf.read(n).decode('utf-8', 'replace')
        print('===== %s =====' % n)
        print(txt[-3000:])
