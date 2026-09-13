"""Pin the complete published tree once a month, without fetching rule sources."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import subprocess
from zoneinfo import ZoneInfo

from .parse import Invalid
from .runner import read, verify


def git(root, *args, input=None):
    result = subprocess.run(["git", *args], cwd=root, input=input, text=True,
                            capture_output=True, timeout=120)
    if result.returncode:
        raise Invalid(f"Backup Git operation failed: {args[0]}")
    return result.stdout.strip()


def monthly(root, now=None):
    now = now or datetime.now(ZoneInfo("Asia/Taipei"))
    if now.tzinfo is None:
        raise Invalid("Backup time must include a timezone")
    local = now.astimezone(ZoneInfo("Asia/Taipei"))
    if local.day < 15:
        return dict(status="not_due", month=local.strftime("%Y-%m"))
    tag = local.strftime("backup-%Y-%m-15")
    ref = f"refs/tags/{tag}"
    if git(root, "ls-remote", "--tags", "origin", ref):
        return dict(status="already_archived", tag=tag)
    if git(root, "status", "--porcelain", "--untracked-files=all"):
        raise Invalid("Backup requires a clean checkout of published main")
    commit = git(root, "rev-parse", "HEAD")
    remote = git(root, "ls-remote", "origin", "refs/heads/main").split()
    if not remote or remote[0] != commit:
        raise Invalid("Remote main changed; retry from a fresh checkout")
    if git(root, "tag", "--list", tag):
        raise Invalid("Local backup tag already exists; inspect before retrying")
    _, report = verify(root)
    version = read(root / "version.json")
    check = read(root / "checks/latest.json")
    metadata = dict(
        schema=1, tag=tag, scheduled_date=local.strftime("%Y-%m-15"),
        archived_at=local.isoformat(timespec="seconds"), commit=commit,
        rules_built_at=version["rules_built_at"], rules_version=version["rules_version"],
        snapshot_id=version["snapshot_id"], rule_count=report["rule_count"],
        source_snapshot_checked_at=read(root / "snapshot/manifest.json")["checked_at"],
        last_check_status=check["status"], last_check_at=check["checked_at"],
        scope="complete published repository tree; no new source fetch",
    )
    git(root, "-c", "user.name=rillmoss backup",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "tag", "-a", tag, commit, "-F", "-", input=json.dumps(metadata, ensure_ascii=False, indent=2))
    # Never force or move a tag. A competing push fails instead of replacing a backup.
    git(root, "push", "origin", f"{ref}:{ref}")
    published = git(root, "ls-remote", "--tags", "origin", ref).split()
    if not published or published[0] != git(root, "rev-parse", ref):
        raise Invalid("Cannot confirm the published backup tag")
    return dict(status="archived", **metadata)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    try:
        print(json.dumps(monthly(args.root.resolve()), ensure_ascii=False, indent=2))
        return 0
    except (Invalid, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(str(error) if isinstance(error, Invalid) else f"Backup failed ({type(error).__name__})")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
