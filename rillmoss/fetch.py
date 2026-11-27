"""HTTPS-only transport. Optional GITHUB_TOKEN applies only to api.github.com."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
import re
import subprocess
import time
from urllib.parse import urlsplit, quote

from .parse import Invalid, decode

RETRY_DELAYS = (2, 5)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _github_api_config(hostname):
    if hostname != "api.github.com":
        return None
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token or not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
        return None
    # Pass via stdin (--config -) so the token never appears in argv or process listings.
    return (f'header = "Authorization: Bearer {token}"\n'
            'header = "Accept: application/vnd.github+json"\n').encode()


def download(url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or not parsed.hostname:
        raise Invalid("Only credential-free HTTPS source URLs are allowed")
    config = _github_api_config(parsed.hostname)
    args = ["curl", "--disable", "--fail", "--silent", "--show-error", "--location",
            "--proto", "=https", "--proto-redir", "=https", "--max-redirs", "5",
            "--connect-timeout", "10", "--max-time", "30", "--max-filesize", "20000000",
            "--user-agent", "rillmoss-source-check/1"]
    if config is not None:
        args.extend(["--config", "-"])
    args.append(url)
    for attempt in range(3):
        try:
            result = subprocess.run(
                args, input=config, capture_output=True, timeout=32, check=False)
            if result.returncode == 0:
                decode(result.stdout)
                return result.stdout
        except (subprocess.TimeoutExpired, Invalid):
            pass
        if attempt < len(RETRY_DELAYS):
            time.sleep(RETRY_DELAYS[attempt])
    # Neither response bodies nor environment/proxy details belong in public logs.
    raise Invalid(f"HTTPS download failed after 3 attempts: {parsed.hostname}{parsed.path}")


def resolve_commit_git(repo, ref):
    url = f"https://github.com/{repo}.git"
    targets = (f"refs/heads/{ref}", f"refs/tags/{ref}")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["git", "ls-remote", "--quiet", url, *targets],
                capture_output=True, text=True, timeout=30, check=False, env=env)
            if result.returncode == 0:
                matches = {}
                for line in result.stdout.splitlines():
                    parts = line.split("\t", 1)
                    if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{40}", parts[0]):
                        matches[parts[1].strip()] = parts[0]
                for target in targets:
                    if target in matches:
                        return matches[target]
        except subprocess.TimeoutExpired:
            pass
        if attempt < len(RETRY_DELAYS):
            time.sleep(RETRY_DELAYS[attempt])
    raise Invalid(f"Git commit lookup failed after 3 attempts: {repo}@{ref}")


def validate_manifest(manifest, *, require_base=True):
    ids = set()
    refs = {}
    for source in manifest["sources"]:
        sid = source["id"]
        if not re.fullmatch(r"[a-z0-9-]+", sid) or sid in ids:
            raise Invalid("Unsafe or duplicate source id")
        ids.add(sid)
        if "repo" in source:
            repo, ref, path = source["repo"], source["ref"], source["path"]
            if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
                raise Invalid("Invalid GitHub repository")
            if path.startswith("/") or ".." in path.split("/"):
                raise Invalid("Unsafe repository path")
            if repo.lower() in refs and refs[repo.lower()] != ref:
                raise Invalid("One upstream repository must use one ref")
            refs[repo.lower()] = ref
    if require_base and "base" not in ids:
        raise Invalid("Base source is required")


def collect(manifest, dest, transport=None, *, require_base=True):
    use_default = transport is None or transport is download
    if transport is None:
        transport = download
    validate_manifest(manifest, require_base=require_base)
    dest.mkdir(parents=True, exist_ok=False)
    pins = {}
    for source in manifest["sources"]:
        if "repo" in source and source["repo"].lower() not in pins:
            repo = source["repo"]
            try:
                data = json.loads(transport(f"https://api.github.com/repos/{repo}/commits/{quote(source['ref'], safe='')}"))
                sha = data.get("sha", "")
            except Invalid:
                if not use_default:
                    raise
                sha = resolve_commit_git(repo, source["ref"])
            if not re.fullmatch(r"[0-9a-f]{40}", sha):
                raise Invalid("GitHub did not return a commit SHA")
            pins[repo.lower()] = sha

    def one(source):
        commit = pins.get(source.get("repo", "").lower())
        url = (f"https://raw.githubusercontent.com/{source['repo']}/{commit}/{source['path']}"
               if commit else source["url"])
        data = transport(url)
        decode(data)
        (dest / (source["id"] + ".txt")).write_bytes(data)
        return source["id"], dict(url=url, sha256=digest(data), bytes=len(data), commit=commit)

    records = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(one, s) for s in manifest["sources"]]
        for task in as_completed(futures):
            sid, record = task.result()
            records[sid] = record
    return dict(pins=pins, sources=records)
