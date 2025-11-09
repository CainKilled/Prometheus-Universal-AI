#!/usr/bin/env python3
"""Upload the current directory into a branch on GitHub using the Contents API.
Environment variables:
  GITHUB_TOKEN (required)
  REPO (owner/repo) (optional, will prompt)
  BRANCH (target branch name, default: feature/webssh-verifier)
  BASE_BRANCH (branch to base off, default: main)
  SOURCE_DIR (directory to upload, default: .)

This script uses the GitHub Contents API to create/update files. It's intended to be runnable from iSH on iPhone, macOS, Linux, or CI runners.
"""
import os, sys, json, base64, urllib.request, urllib.error
from urllib.parse import quote

GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
if not GITHUB_TOKEN:
    print('Error: GITHUB_TOKEN environment variable is required.')
    sys.exit(2)

REPO = os.environ.get('REPO') or input('Repo (owner/repo): ').strip()
BRANCH = os.environ.get('BRANCH') or 'feature/webssh-verifier'
BASE_BRANCH = os.environ.get('BASE_BRANCH') or 'main'
SOURCE_DIR = os.environ.get('SOURCE_DIR') or '.'
COMMIT_PREFIX = os.environ.get('COMMIT_PREFIX') or 'chore(verifier):'

API_BASE = 'https://api.github.com'

headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'User-Agent': 'webssh-verifier-uploader',
    'Accept': 'application/vnd.github+json'
}

def api_get(path):
    req = urllib.request.Request(API_BASE + path, headers=headers, method='GET')
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        return e

def api_post(path, data):
    data_b = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(API_BASE + path, data=data_b, headers={**headers, 'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)

def api_put(path, data):
    data_b = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(API_BASE + path, data=data_b, headers={**headers, 'Content-Type': 'application/json'}, method='PUT')
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)

def ensure_branch():
    # get base branch sha
    print(f'Ensuring branch {BRANCH} exists (base: {BASE_BRANCH})...')
    r = api_get(f'/repos/{REPO}/git/ref/heads/{BASE_BRANCH}')
    if isinstance(r, Exception):
        print('Failed to fetch base branch info:', r)
        sys.exit(3)
    base_sha = r['object']['sha']
    # try to create branch
    existing = api_get(f'/repos/{REPO}/git/ref/heads/{BRANCH}')
    if not isinstance(existing, Exception):
        print('Branch already exists.')
        return
    payload = {'ref': f'refs/heads/{BRANCH}', 'sha': base_sha}
    try:
        api_post(f'/repos/{REPO}/git/refs', payload)
        print('Branch created.')
    except Exception as e:
        print('Failed to create branch:', e)
        sys.exit(4)

def upload_file(path_on_disk, relpath):
    with open(path_on_disk, 'rb') as f:
        content = f.read()
    content_b64 = base64.b64encode(content).decode('utf-8')
    # check if file exists on branch
    try:
        existing = api_get(f'/repos/{REPO}/contents/{quote(relpath)}?ref={BRANCH}')
        if isinstance(existing, Exception):
            raise Exception('not found')
        sha = existing.get('sha')
    except Exception:
        sha = None
    message = f"{COMMIT_PREFIX} add {relpath}"
    payload = {'message': message, 'content': content_b64, 'branch': BRANCH}
    if sha:
        payload['sha'] = sha
    try:
        res = api_put(f'/repos/{REPO}/contents/{quote(relpath)}', payload)
        print('Uploaded', relpath)
    except urllib.error.HTTPError as e:
        print('Failed to upload', relpath, 'status', e.code)
        print(e.read().decode())
        sys.exit(5)

def main():
    ensure_branch()
    files = []
    for root, dirs, filenames in os.walk(SOURCE_DIR):
        # skip .git and node_modules and __pycache__
        if '.git' in root.split(os.sep):
            continue
        if root.startswith('./.git') or '/.git' in root:
            continue
        for fn in filenames:
            # skip zip output if present
            if fn.endswith('.zip'):
                continue
            # compute relpath
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, SOURCE_DIR)
            files.append((full, rel.replace('\\','/')))
    # Upload each file
    for full, rel in files:
        upload_file(full, rel)

if __name__ == '__main__':
    main()
