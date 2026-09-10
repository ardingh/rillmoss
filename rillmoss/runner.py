"""Stage whole bundles before touching the current candidate or Git publication."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .build import build, canonical, parse_sources
from .fetch import collect, digest, validate_manifest
from .parse import Invalid


def read(path):
    return json.loads(path.read_bytes())


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(data))


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def lock(root):
    (root / ".work").mkdir(exist_ok=True)
    with (root / ".work/update.lock").open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise Invalid("Another update is already running") from e
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def stage(root, output, bootstrap=False, collector=collect):
    if output.exists():
        raise Invalid("Output must be a new directory")
    manifest, personal = read(root / "policy/sources.json"), read(root / "policy/personal.json")
    validate_manifest(manifest)
    baseline_path = root / "policy/counts.json"
    if bootstrap and ((root / "version.json").exists() or baseline_path.exists()):
        raise Invalid("Bootstrap is only allowed for the first local candidate")
    if not bootstrap and not baseline_path.exists():
        raise Invalid("Missing reviewed count baseline")
    output.mkdir(parents=True)
    snapshot = output / "snapshot"
    raw = snapshot / "raw"
    fetched = collector(manifest, raw)
    baseline = parse_sources(raw, manifest, personal)[1] if bootstrap else read(baseline_path)
    conf, report = build(raw, manifest, personal, baseline)
    for name, data in (("personal", personal), ("sources", manifest), ("counts", baseline)):
        write(snapshot / "inputs" / (name + ".json"), data)
    write(output / "policy/counts.json", report["source_counts"])
    for name in ("personal.json", "sources.json"):
        (output / "policy" / name).write_bytes((root / "policy" / name).read_bytes())
    (output / "rillmoss.conf").write_text(conf)
    write(output / "reports/build.json", report)
    checksums = {str(p.relative_to(output)): digest(p.read_bytes()) for p in output.rglob("*") if p.is_file()}
    metadata = dict(schema=1, checked_at=utc(), upstream=fetched, files=checksums,
                    rules_version=report["rules_version"], source_counts=report["source_counts"])
    metadata["snapshot_id"] = digest(canonical(dict(files=checksums, upstream=fetched)))
    write(snapshot / "manifest.json", metadata)
    current_path = root / "version.json"
    current = read(current_path) if current_path.exists() else {}
    version = dict(schema=1, rules_version=report["rules_version"], snapshot_id=metadata["snapshot_id"],
                   rules_built_at=current.get("rules_built_at") if current.get("rules_version") == report["rules_version"] else utc())
    write(output / "version.json", version)
    verify(output)
    return report


def verify(bundle):
    meta = read(bundle / "snapshot/manifest.json")
    expected = set(meta["files"])
    if digest(canonical(dict(files=meta["files"], upstream=meta["upstream"]))) != meta["snapshot_id"]:
        raise Invalid("Snapshot manifest digest mismatch")
    required = {"rillmoss.conf", "reports/build.json", "policy/personal.json", "policy/sources.json", "policy/counts.json"}
    required |= {f"snapshot/inputs/{n}.json" for n in ("personal", "sources", "counts")}
    if not required <= expected:
        raise Invalid("Incomplete snapshot manifest")
    for relative, checksum in meta["files"].items():
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or (bundle / path).is_symlink():
            raise Invalid("Unsafe snapshot path")
        if digest((bundle / path).read_bytes()) != checksum:
            raise Invalid(f"Snapshot file checksum mismatch: {relative}")
    manifest = read(bundle / "snapshot/inputs/sources.json")
    validate_manifest(manifest)
    source_ids = {s["id"] for s in manifest["sources"]}
    raw_files = {p.stem for p in (bundle / "snapshot/raw").iterdir()}
    if raw_files != source_ids or set(meta["upstream"]["sources"]) != source_ids:
        raise Invalid("Snapshot is incomplete or contains unexpected sources")
    for source in manifest["sources"]:
        sid = source["id"]
        path = f"snapshot/raw/{sid}.txt"
        if path not in expected or digest((bundle / path).read_bytes()) != meta["upstream"]["sources"][sid]["sha256"]:
            raise Invalid("Raw-source checksum mismatch")
        if "repo" in source:
            pin = meta["upstream"]["pins"][source["repo"].lower()]
            record = meta["upstream"]["sources"][sid]
            url = f"https://raw.githubusercontent.com/{source['repo']}/{pin}/{source['path']}"
            if record["commit"] != pin or record["url"] != url:
                raise Invalid("GitHub snapshot mixes commits")
    personal = read(bundle / "snapshot/inputs/personal.json")
    counts = read(bundle / "snapshot/inputs/counts.json")
    conf, report = build(bundle / "snapshot/raw", manifest, personal, counts)
    if (bundle / "rillmoss.conf").read_text() != conf or report != read(bundle / "reports/build.json"):
        raise Invalid("Offline rebuild differs from stored bundle")
    version = read(bundle / "version.json")
    if version["rules_version"] != report["rules_version"] or meta["rules_version"] != report["rules_version"] or version["snapshot_id"] != meta["snapshot_id"]:
        raise Invalid("Version record mismatch")
    if read(bundle / "policy/personal.json") != personal or read(bundle / "policy/sources.json") != manifest:
        raise Invalid("Personal settings do not correspond to the stored configuration")
    if read(bundle / "policy/counts.json") != report["source_counts"] or meta["source_counts"] != report["source_counts"]:
        raise Invalid("Successful count baseline mismatch")
    return conf, report


BUNDLE_PATHS = ("rillmoss.conf", "snapshot", "reports/build.json", "version.json",
                "policy/personal.json", "policy/sources.json", "policy/counts.json")


def install(root, bundle, replace=os.replace):
    verify(bundle)
    # Each replacement is reversible. Nothing here pushes; remote publication is one Git commit.
    with tempfile.TemporaryDirectory(prefix="install-", dir=root / ".work") as temp:
        backup = Path(temp) / "backup"
        prepared = Path(temp) / "prepared"
        for name in BUNDLE_PATHS:
            src, dst = bundle / name, prepared / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
        touched = []
        try:
            for name in BUNDLE_PATHS:
                target, old, new = root / name, backup / name, prepared / name
                target.parent.mkdir(parents=True, exist_ok=True)
                old.parent.mkdir(parents=True, exist_ok=True)
                existed = target.exists()
                if existed:
                    replace(target, old)
                touched.append((name, existed))
                replace(new, target)
        except BaseException:
            for name, existed in reversed(touched):
                target, old = root / name, backup / name
                if target.exists():
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                if existed:
                    os.replace(old, target)
            raise


def can_publish(root):
    control = read(root / "policy/release.json")
    if not control["publish_enabled"]:
        return False
    acceptance = control.get("acceptance") or {}
    required = ("mac", "iphone", "ai_faults", "ipv4", "ipv6", "udp", "device_update")
    if any(acceptance.get(k) != "passed" for k in required) or not acceptance.get("evidence") or not acceptance.get("rules_version"):
        raise Invalid("Publication requires documented device acceptance")
    return True


def rollback(root, bundle):
    _, report = verify(bundle)
    if not can_publish(bundle):
        raise Invalid("Rollback target has no completed device acceptance")
    acceptance = read(bundle / "policy/release.json")["acceptance"]
    if acceptance["rules_version"] != report["rules_version"]:
        raise Invalid("Rollback target version has not been explicitly confirmed usable")
    control = read(root / "policy/release.json")
    control["publish_enabled"] = False
    control["reason"] = "Rollback: daily checks continue; publication awaits repair and retesting"
    # Pause first, so even an interrupted restore cannot resume an unsafe updater.
    write(root / "policy/release.json", control)
    install(root, bundle)
    record_check(root, dict(status="rolled_back_publication_paused", restored_rules_version=report["rules_version"]))


def record_check(root, result):
    result["checked_at"] = utc()
    current = root / "version.json"
    result["current_rules_version"] = read(current)["rules_version"] if current.exists() else None
    run_id, attempt = os.environ.get("GITHUB_RUN_ID"), os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    if run_id and run_id.isdecimal() and attempt.isdecimal():
        result["run_url"] = f"https://github.com/ardingh/rillmoss/actions/runs/{run_id}"
        key = run_id + "-" + attempt
    else:
        key = datetime.now(timezone.utc).strftime("local-%Y%m%dT%H%M%S%fZ")
    write(root / "checks" / (key + ".json"), result)
    write(root / "checks/latest.json", result)


def update(root):
    with lock(root):
        enabled = False
        try:
            enabled = can_publish(root)
            temp = tempfile.mkdtemp(prefix="check-", dir=root / ".work")
            candidate = Path(temp) / "bundle"
            report = stage(root, candidate)
            old = read(root / "version.json")["rules_version"]
            if enabled:
                install(root, candidate)
            result = dict(status="passed" if enabled else "passed_publication_paused",
                          candidate_rules_version=report["rules_version"],
                          rules_changed=old != report["rules_version"], publication_enabled=enabled,
                          base_changes_not_imported=report["base_changes_not_imported"])
            record_check(root, result)
            return 0
        except Exception as e:
            # Public logs contain controlled builder errors, not arbitrary upstream content.
            message = str(e) if isinstance(e, Invalid) else f"Internal failure ({type(e).__name__})"
            record_check(root, dict(status="failed", error=message, publication_enabled=enabled, bundle_applied=False))
            print(message)
            return 1


def ci_check(root):
    tested = subprocess.run(["python3", "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=root)
    if tested.returncode:
        with lock(root):
            record_check(root, dict(status="failed", error="Automated tests failed", publication_enabled=False))
        return 1
    return update(root)


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


def commit_update(root, expected_head):
    verify(root)
    if git(root, "rev-parse", "HEAD") != expected_head:
        raise Invalid("Local HEAD changed during update")
    remote = git(root, "ls-remote", "origin", "refs/heads/main").split()
    if not remote or remote[0] != expected_head:
        raise Invalid("Remote main changed; stop without overwriting or rebasing")
    # This allowlist excludes .work, private logs, device backup files, and credentials.
    git(root, "add", "--", *BUNDLE_PATHS, "checks")
    changed = git(root, "diff", "--cached", "--name-only")
    if not changed:
        return
    allowed = lambda p: p in BUNDLE_PATHS or any(p.startswith(x + "/") for x in ("snapshot", "checks"))
    if any(not allowed(p) for p in changed.splitlines()):
        raise Invalid("Unexpected staged file; refuse automated commit")
    git(root, "-c", "user.name=rillmoss updater", "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit", "-m", "chore: record source check and validated bundle")
    # A racing remote change makes this non-fast-forward; there is deliberately no retry/force.
    git(root, "push", "origin", "HEAD:refs/heads/main")


def main(argv=None):
    parser = argparse.ArgumentParser(description="rillmoss: local staging and atomic Git publication")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("prepare")
    fetch.add_argument("--output", type=Path, required=True)
    fetch.add_argument("--bootstrap", action="store_true")
    for command in ("verify", "rebuild", "install-candidate", "adopt-candidate", "rollback"):
        p = sub.add_parser(command)
        p.add_argument("--bundle", type=Path, required=True)
        if command == "rebuild":
            p.add_argument("--output", type=Path, required=True)
    sub.add_parser("update")
    sub.add_parser("ci-check")
    p = sub.add_parser("commit-update")
    p.add_argument("--expected-head", required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        if args.command == "prepare":
            with lock(root):
                report = stage(root, args.output.resolve(), bootstrap=args.bootstrap)
            print(json.dumps({k: report[k] for k in ("rules_version", "rule_count", "source_counts")}, ensure_ascii=False))
        elif args.command in {"verify", "rebuild"}:
            conf, report = verify(args.bundle.resolve())
            if args.command == "rebuild":
                # Explicit exclusive creation protects an existing user artifact.
                with args.output.open("x") as out:
                    out.write(conf)
            print(f"Verified {report['rule_count']} rules; {report['rules_version']}")
        elif args.command == "install-candidate":
            with lock(root):
                if (root / "version.json").exists():
                    raise Invalid("Initial candidate already exists; use a reviewed maintenance change")
                install(root, args.bundle.resolve())
            print("Local candidate installed. Device acceptance and publication remain pending.")
        elif args.command == "update":
            return update(root)
        elif args.command == "ci-check":
            return ci_check(root)
        elif args.command == "rollback":
            with lock(root):
                rollback(root, args.bundle.resolve())
            print("Known-good bundle restored locally; automatic publication paused. Review and commit together.")
        elif args.command == "adopt-candidate":
            with lock(root):
                verify(args.bundle.resolve())
                control = read(root / "policy/release.json")
                control.update(publish_enabled=False, acceptance=None, reason="New local candidate; device review pending")
                write(root / "policy/release.json", control)
                install(root, args.bundle.resolve())
            print("Reviewed candidate adopted locally; publication paused and previous acceptance cleared.")
        elif args.command == "commit-update":
            with lock(root):
                commit_update(root, args.expected_head)
        return 0
    except (Invalid, OSError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as e:
        print(str(e) if isinstance(e, Invalid) else f"Operation failed ({type(e).__name__})")
        return 1
