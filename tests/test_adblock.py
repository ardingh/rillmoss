import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rillmoss import adblock, build, fetch, guard, parse, runner
from rillmoss.parse import Invalid, Rule


ROOT = Path(__file__).resolve().parents[1]
DATA = ("DOMAIN-SUFFIX,ads.rillmoss-ad-test.net\n"
        "DOMAIN-SUFFIX,sentry.io\n"
        "DOMAIN-SUFFIX,statsigapi.net\n"
        "DOMAIN-SUFFIX,future-telemetry.meta.ai\n"
        "DOMAIN-SUFFIX,future-telemetry.fbcdn.net\n"
        "DOMAIN-SUFFIX,ad.new-child.bilibili.com\n"
        "DOMAIN-SUFFIX,baidu.greenxf.cn\n"
        "DOMAIN-SUFFIX,ads.rillmoss-ad-test.cn\n").encode()


def policy():
    return dict(schema=1, sources=copy.deepcopy(adblock.SOURCES), update_url=adblock.UPDATE_URL,
                reviewed_count=len(DATA.splitlines()), routing_priority="existing_routes_first")


def collector(manifest, raw):
    raw.mkdir(parents=True)
    pin = "a" * 40
    records = {}
    for source in manifest["sources"]:
        data = DATA if source["id"] == "anti-ad" else b"MIT License\nCopyright (c) Synthetic test fixture\n"
        (raw / (source["id"] + ".txt")).write_bytes(data)
        records[source["id"]] = dict(commit=pin, bytes=len(data), sha256=fetch.digest(data),
                                      url=f"https://raw.githubusercontent.com/{source['repo']}/{pin}/{source['path']}")
    return dict(pins={adblock.SOURCES[0]["repo"].lower(): pin}, sources=records)


def copy_base(source, dest):
    dest.mkdir(parents=True)
    for name in runner.BUNDLE_PATHS:
        src, dst = source / name, dest / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    runner.write(dest / "policy/adblock.json", policy())
    runner.write(dest / "policy/release.json", dict(
        publish_enabled=True, acceptance=None,
        user_authorization=dict(scope="current_policy_and_daily_source_updates",
                                confirmed_at="2026-10-15T00:00:00+00:00", evidence="synthetic fixture")))


class AdvertisingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.fixture = Path(cls.temp.name) / "fixture"
        copy_base(ROOT, cls.fixture)
        cls.candidate = Path(cls.temp.name) / "ad-candidate"
        adblock.stage(cls.fixture, cls.fixture, cls.candidate, collector=collector)
        adblock.install(cls.fixture, cls.candidate)

    def setUp(self):
        self.temp_case = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_case.cleanup)
        self.root = Path(self.temp_case.name) / "project"
        shutil.copytree(self.fixture, self.root)

    def base_collector(self, manifest, raw):
        shutil.copytree(self.root / "snapshot/raw", raw)
        return runner.read(self.root / "snapshot/manifest.json")["upstream"]

    def fingerprint(self, paths):
        result = {}
        for name in paths:
            path = self.root / name
            for p in path.rglob("*") if path.is_dir() else [path]:
                if p.is_file():
                    result[str(p.relative_to(self.root))] = fetch.digest(p.read_bytes())
        return result

    def test_both_outputs_have_identical_base_rules_groups_settings_and_distinct_update_urls(self):
        base, base_report = runner.verify(self.root)
        conf, report = adblock.verify(self.root)
        a, b = parse.sections(base), parse.sections(conf)
        boundary, count = report["insertion_after_base_rules"], report["added_rule_count"]
        self.assertEqual(b["Rule"][:boundary] + b["Rule"][boundary + count:], a["Rule"])
        for section in ("Proxy Group", "Host", "MITM", "URL Rewrite"):
            self.assertEqual(a[section], b[section])
        self.assertEqual(b["General"], [line.replace(build.UPDATE_URL, adblock.UPDATE_URL) for line in a["General"]])
        self.assertEqual(base_report["direct_routing"], report["direct_routing"])
        self.assertEqual(report["base_rules_version"], base_report["rules_version"])
        self.assertEqual((ROOT / "rillmoss.conf").read_bytes(), (self.root / "rillmoss.conf").read_bytes())
        self.assertEqual(count, 2)
        self.assertEqual(report["source_rule_count"], 8)
        self.assertIn("# MIT License\n# Copyright (c) Synthetic test fixture", conf)

    def test_residential_and_direct_scopes_survive_future_ad_domains(self):
        conf, _ = adblock.verify(self.root)
        entries = []
        for line in parse.sections(conf)["Rule"]:
            fields = line.split(",")
            if fields[0] not in {"GEOIP", "FINAL"}:
                entries.append((parse.rule(",".join(fields[:2] + fields[3:])), fields[2], "fixture"))
        routes = guard.DomainRoutes(entries)
        targets = {"sentry.io": "Claude", "events.statsigapi.net": "Claude",
                   "api.statsig.com": "OpenAI", "api64.ipify.org": "V3 Static Residential",
                   "future-telemetry.meta.ai": "Muse", "future-telemetry.fbcdn.net": "Muse",
                   "deep.future-telemetry.meta.ai": "Muse", "api.anthropic.com": "Claude",
                   "ad.new-child.bilibili.com": "DIRECT", "baidu.greenxf.cn": "DIRECT",
                   "ads.rillmoss-ad-test.net": "REJECT", "child.ads.rillmoss-ad-test.net": "REJECT",
                   "ads.rillmoss-ad-test.cn": "REJECT", "api.snssdk.com": "DIRECT"}
        for host, expected in targets.items():
            with self.subTest(host=host):
                self.assertEqual(routes.match(host)[1], expected)
        self.assertEqual(build.route(entries, address="160.79.104.8")[0], "Claude")
        self.assertEqual(build.route(entries, address="2607:6bc0::8")[0], "Claude")

    def test_unsafe_formats_count_anomalies_and_policy_changes_are_rejected(self):
        for text in (b"DOMAIN-KEYWORD,openx", b"DOMAIN-SUFFIX,com", b"DOMAIN-SUFFIX,*.example.net",
                     b"IP-CIDR,1.2.3.0/24", b"DOMAIN-SUFFIX,example.net,REJECT", b"<html>503</html>"):
            with self.subTest(text=text), self.assertRaises(Invalid):
                adblock.parse_ads(text, 1)
        with self.assertRaisesRegex(Invalid, "abnormal rule count"):
            adblock.parse_ads(DATA, 100)
        for key, value in (("update_url", build.UPDATE_URL), ("routing_priority", "ads_first"),
                           ("sources", []), ("reviewed_count", True)):
            changed = policy()
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(Invalid):
                adblock.validate_policy(changed)

    def test_invalid_base_stops_before_anti_ad_access(self):
        (self.root / "rillmoss.conf").write_text("broken base")
        with patch("rillmoss.fetch.collect") as collect, self.assertRaises(Invalid):
            adblock.stage(self.root, self.root, self.root / ".work/new-ad")
        collect.assert_not_called()

    def test_missing_tampered_or_mixed_commit_ad_snapshot_fails(self):
        path = self.root / "adblock/raw/anti-ad.txt"
        path.write_bytes(DATA + b"DOMAIN-SUFFIX,extra.example.net\n")
        with self.assertRaises(Invalid):
            adblock.verify(self.root)
        path.write_bytes(DATA)
        manifest = runner.read(self.root / "adblock/manifest.json")
        manifest["upstream"]["sources"]["anti-ad-license"]["commit"] = "b" * 40
        manifest["snapshot_id"] = fetch.digest(build.canonical(dict(files=manifest["files"], upstream=manifest["upstream"])))
        runner.write(self.root / "adblock/manifest.json", manifest)
        with self.assertRaisesRegex(Invalid, "mixes commits"):
            adblock.verify(self.root)

    def test_ad_install_failure_restores_all_ad_files_and_never_touches_base(self):
        before = self.fingerprint(runner.BUNDLE_PATHS + adblock.BUNDLE_PATHS)
        calls = 0
        def fail(a, b):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError("simulated write failure")
            return runner.os.replace(a, b)
        with self.assertRaises(OSError):
            adblock.install(self.root, self.candidate, replace=fail)
        self.assertEqual(before, self.fingerprint(runner.BUNDLE_PATHS + adblock.BUNDLE_PATHS))

    def test_daily_base_is_validated_and_installed_before_ad_access(self):
        real_stage, real_ad_stage = runner.stage, adblock.stage
        old_ad = (self.root / "rillmoss-ad.conf").read_bytes()
        def base_stage(root, output):
            return real_stage(root, output, collector=self.base_collector)
        def ad_stage(root, base, output):
            self.assertEqual((root / "rillmoss.conf").read_bytes(), (base / "rillmoss.conf").read_bytes())
            runner.verify(base)
            self.assertEqual((root / "rillmoss-ad.conf").read_bytes(), old_ad)
            return real_ad_stage(root, base, output, collector=collector)
        with patch("rillmoss.runner.stage", side_effect=base_stage), patch("rillmoss.adblock.stage", side_effect=ad_stage):
            self.assertEqual(runner.update(self.root), 0)
        runner.verify_all(self.root)
        check = runner.read(self.root / "checks/latest.json")
        self.assertEqual(check["status"], "passed")
        self.assertTrue(check["adblock"]["bundle_applied"])
        self.assertIsNone(runner.read(self.root / "policy/release.json")["acceptance"])

    def test_ad_failure_keeps_previous_complete_ad_but_updates_base(self):
        previous_ad = self.fingerprint(adblock.BUNDLE_PATHS)
        previous_base = runner.read(self.root / "version.json")["rules_version"]
        real_stage = runner.stage
        def changed_collector(manifest, raw):
            metadata = self.base_collector(manifest, raw)
            path = raw / "global.txt"
            path.write_text(path.read_text() + "\nHOST,new-base.rillmoss-test.net,Global\n")
            metadata["sources"]["global"].update(sha256=fetch.digest(path.read_bytes()), bytes=path.stat().st_size)
            return metadata
        with patch("rillmoss.runner.stage", side_effect=lambda root, out:
                   real_stage(root, out, collector=changed_collector)), patch(
                   "rillmoss.adblock.stage", side_effect=Invalid("anti-AD unavailable")):
            self.assertEqual(runner.update(self.root), 1)
        self.assertNotEqual(runner.read(self.root / "version.json")["rules_version"], previous_base)
        self.assertEqual(previous_ad, self.fingerprint(adblock.BUNDLE_PATHS))
        runner.verify_all(self.root)  # The retained variant carries its own complete, older base.
        check = runner.read(self.root / "checks/latest.json")
        self.assertEqual(check["status"], "base_passed_adblock_failed")
        self.assertFalse(check["adblock"]["bundle_applied"])

    def test_base_failure_does_not_contact_ads_or_replace_either_variant(self):
        before = self.fingerprint(runner.BUNDLE_PATHS + adblock.BUNDLE_PATHS)
        with patch("rillmoss.runner.stage", side_effect=Invalid("base download failed")), patch(
                "rillmoss.adblock.stage") as ads:
            self.assertEqual(runner.update(self.root), 1)
        ads.assert_not_called()
        self.assertEqual(before, self.fingerprint(runner.BUNDLE_PATHS + adblock.BUNDLE_PATHS))

    def test_pause_prevents_both_installs_and_keeps_both_candidates(self):
        control = runner.read(self.root / "policy/release.json")
        control["publish_enabled"] = False
        runner.write(self.root / "policy/release.json", control)
        before = self.fingerprint(runner.BUNDLE_PATHS + adblock.BUNDLE_PATHS)
        real_stage, real_ad_stage = runner.stage, adblock.stage
        with patch("rillmoss.runner.stage", side_effect=lambda root, out:
                   real_stage(root, out, collector=self.base_collector)), patch(
                   "rillmoss.adblock.stage", side_effect=lambda root, base, out:
                   real_ad_stage(root, base, out, collector=collector)):
            self.assertEqual(runner.update(self.root), 0)
        self.assertEqual(before, self.fingerprint(runner.BUNDLE_PATHS + adblock.BUNDLE_PATHS))
        check = runner.read(self.root / "checks/latest.json")
        self.assertEqual(check["adblock"]["status"], "passed_publication_paused")
        self.assertFalse(check["adblock"]["bundle_applied"])

    def test_unchanged_offline_ad_rebuild_keeps_version_and_timestamp(self):
        output = self.root / ".work/repeated-ad"
        with patch("rillmoss.fetch.download", side_effect=AssertionError("network access")):
            adblock.stage(self.root, self.root, output, collector=collector)
        self.assertEqual((self.root / "rillmoss-ad.conf").read_bytes(), (output / "rillmoss-ad.conf").read_bytes())
        self.assertEqual(runner.read(self.root / "adblock/version.json"), runner.read(output / "adblock/version.json"))

    def test_ad_cli_rebuild_is_offline_and_never_overwrites_an_existing_file(self):
        output = Path(self.temp_case.name) / "rebuilt-ad.conf"
        args = ["rebuild-adblock", "--bundle", str(self.root), "--output", str(output)]
        with patch("rillmoss.fetch.download", side_effect=AssertionError("network access")):
            self.assertEqual(runner.main(args), 0)
        self.assertEqual(output.read_bytes(), (self.root / "rillmoss-ad.conf").read_bytes())
        output.write_text("existing user artifact")
        self.assertEqual(runner.main(args), 1)
        self.assertEqual(output.read_text(), "existing user artifact")

    def test_daily_commit_publishes_and_rechecks_both_variants_in_one_commit(self):
        remote = Path(self.temp_case.name) / "remote.git"
        def git(cwd, *args):
            return subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
                                  cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()
        git(self.root, "init", "--initial-branch=main")
        git(self.root, "add", ".")
        git(self.root, "commit", "-m", "fixture")
        git(self.root, "init", "--bare", str(remote))
        git(self.root, "remote", "add", "origin", str(remote))
        git(self.root, "push", "origin", "HEAD:main")
        head = git(self.root, "rev-parse", "HEAD")
        runner.record_check(self.root, dict(status="passed", rules_changed=False))
        runner.commit_update(self.root, head)
        self.assertEqual(git(self.root, "rev-list", "--count", head + "..HEAD"), "1")
        restored = Path(self.temp_case.name) / "restored"
        git(self.root, "clone", str(remote), str(restored))
        runner.verify_all(restored)
        self.assertEqual((restored / "rillmoss-ad.conf").read_bytes(), (self.root / "rillmoss-ad.conf").read_bytes())


if __name__ == "__main__":
    unittest.main()
