"""HTTPS-only transport. No credentials are needed for public upstreams."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import re
import subprocess
from urllib.parse import urlsplit, quote

from .parse import Invalid, decode


def digest(data):
    return hashlib.sha256(data).hexdigest()


def download(url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or not parsed.hostname:
        raise Invalid("Only credential-free HTTPS source URLs are allowed")
    for attempt in range(3):
        try:
            result = subprocess.run(
                ["curl", "--disable", "--fail", "--silent", "--show-error", "--location",
                 "--proto", "=https", "--proto-redir", "=https", "--max-redirs", "5",
                 "--connect-timeout", "10", "--max-time", "30", "--max-filesize", "20000000",
                 "--user-agent", "rillmoss-source-check/1", url],
                capture_output=True, timeout=32, check=False)
            if result.returncode == 0:
                decode(result.stdout)
                return result.stdout
        except (subprocess.TimeoutExpired, Invalid):
            pass
    # Neither response bodies nor environment/proxy details belong in public logs.
    raise Invalid(f"HTTPS download failed after 3 attempts: {parsed.hostname}{parsed.path}")


def validate_manifest(manifest):
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
    if "base" not in ids:
        raise Invalid("Base source is required")


def collect(manifest, dest, transport=download):
    validate_manifest(manifest)
    dest.mkdir(parents=True, exist_ok=False)
    pins = {}
    for source in manifest["sources"]:
        if "repo" in source and source["repo"].lower() not in pins:
            repo = source["repo"]
            data = json.loads(transport(f"https://api.github.com/repos/{repo}/commits/{quote(source['ref'], safe='')}"))
            sha = data.get("sha", "")
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
