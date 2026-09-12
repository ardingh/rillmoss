import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rillmoss import parse, fetch, build, runner
from rillmoss.parse import Invalid, Rule

ROOT = Path(__file__).resolve().parents[1]


class ParserTests(unittest.TestCase):
    def test_qx_policy_and_ipv6_flags(self):
        self.assertEqual(parse.rule("HOST-SUFFIX,Example.com,old-policy", True), Rule("DOMAIN-SUFFIX", "example.com"))
        self.assertEqual(parse.rule("IP6-CIDR,2607:6bc0::/48,old,no-resolve", True),
                         Rule("IP-CIDR6", "2607:6bc0::/48", ("no-resolve",)))
        self.assertEqual(parse.rule("IP-CIDR,::/127,no-resolve").kind, "IP-CIDR6")

    def test_unknown_formats_and_flags_are_errors(self):
        for text in ("HOSTNAME,example.com", "DOMAIN,", "DOMAIN,example.com,no-resolve",
                     "DOMAIN,example.com,unknown=1", "IP-CIDR,1.2.3.0/24,no-reslove",
                     "DOMAIN,x.com,DIRECT", "IP-CIDR6,1.2.3.0/24", "DOMAIN,x,ok,no-resolve,bad"):
            with self.subTest(text=text), self.assertRaises(Invalid):
                parse.rules(text)

    def test_empty_error_pages_and_binary_rejected(self):
        for text in ("", "# no rules", "<html><h1>503 unavailable</h1></html>", "404: Not Found"):
            with self.subTest(text=text), self.assertRaises(Invalid):
                parse.rules(text)
        for data in (b"", b"\x00", b"\xff"):
            with self.assertRaises(Invalid):
                parse.decode(data)

    def test_chatgpt_section_only_not_comments_count(self):
        text = "# 999 rules\n# > Siri\nDOMAIN,x.apple.com\n# > ChatGPT\nDOMAIN-SUFFIX,openai.com\n# > Other\nDOMAIN,other.ai\n"
        self.assertEqual(parse.chatgpt(text), [Rule("DOMAIN-SUFFIX", "openai.com")])
        with self.assertRaises(Invalid):
            parse.chatgpt(text + "# > ChatGPT\nDOMAIN,y.com\n")

    def test_claude_typed_block_only(self):
        text = """<p>DOMAIN-SUFFIX,ntp.org</p><pre>- DOMAIN-SUFFIX,anthropic.com</pre>
        <pre>DOMAIN-SUFFIX,anthropic.com
DOMAIN-KEYWORD,datadog
DOMAIN-KEYWORD,sift
IP-CIDR,160.79.104.0/21,no-resolve
IP-ASN,399358,no-resolve</pre>"""
        self.assertEqual([r.value for r in parse.claude(text)], ["anthropic.com", "datadog", "sift"])
        with self.assertRaises(Invalid):
            parse.claude(text.replace("IP-ASN", "UNKNOWN"))

    def test_official_inbound_is_scoped_and_pinned(self):
        text = '<h2 id="inbound-ip-addresses">Inbound</h2><code>160.79.104.0/23</code><code>2607:6bc0::/48</code><h2 id="outbound-ip-addresses">Outbound</h2><code>160.79.104.0/21</code>'
        expected = ["160.79.104.0/23", "2607:6bc0::/48"]
        self.assertEqual([r.value for r in parse.inbound(text, expected)], expected)
        for bad in (text.replace("/23", "/21"), text.replace('id="inbound-ip-addresses"', 'id="changed"')):
            with self.assertRaises(Invalid):
                parse.inbound(bad, expected)

    def test_unknown_base_rules_cannot_be_silently_skipped(self):
        text = "[General]\nipv6 = true\n[Proxy Group]\nx = select,node\n[Rule]\nUNSUPPORTED,example.com,DIRECT\n"
        with self.assertRaises(Invalid):
            parse.sections(text)


class DownloadTests(unittest.TestCase):
    def test_transport_retries_and_verifies_tls(self):
        bad = subprocess.CompletedProcess([], 28, b"partial", b"private error detail")
        with patch("rillmoss.fetch.subprocess.run", return_value=bad) as run:
            with self.assertRaises(Invalid) as error:
                fetch.download("https://example.com/rules")
            self.assertEqual(run.call_count, 3)
            self.assertNotIn("private error", str(error.exception))
            args = run.call_args.args[0]
            self.assertIn("--max-time", args)
            self.assertEqual(args[args.index("--max-time") + 1], "30")
            self.assertNotIn("-k", args)
            self.assertNotIn("--insecure", args)
            self.assertEqual(args[1], "--disable")

    def test_https_only(self):
        for url in ("http://example.com/file", "https://user:secret@example.com/file"):
            with self.assertRaises(Invalid):
                fetch.download(url)

    def test_one_commit_for_every_file_from_a_repo(self):
        sources = dict(sources=[dict(id="base", repo="a/b", ref="main", path="one", format="base"),
                                dict(id="two", repo="a/b", ref="main", path="two", format="rules")])
        calls = []
        def transport(url):
            calls.append(url)
            if "api.github.com" in url:
                return json.dumps(dict(sha="a" * 40)).encode()
            return b"DOMAIN,example.com"
        with tempfile.TemporaryDirectory() as temp:
            metadata = fetch.collect(sources, Path(temp) / "raw", transport)
        self.assertEqual(len([u for u in calls if "api.github.com" in u]), 1)
        self.assertTrue(all("a" * 40 in r["url"] for r in metadata["sources"].values()))


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.personal = runner.read(ROOT / "policy/personal.json")
        cls.manifest = runner.read(ROOT / "policy/sources.json")
        cls.raw = ROOT / "snapshot/raw"
        cls.parsed, cls.counts = build.parse_sources(cls.raw, cls.manifest, cls.personal)
        cls.entries, cls.duplicates, cls.removed = build.compose(cls.parsed, cls.manifest, cls.personal)

    def test_actual_snapshot_routes(self):
        checks = build.constraints(self.entries, self.personal, self.parsed)
        self.assertGreater(len(checks), 45)

    def test_claude_check_probe_is_exact_and_precedes_general_ipify(self):
        self.assertEqual(build.route(self.entries, host="api64.ipify.org")[0], "V3 Static Residential")
        for host in ("ipify.org", "api.ipify.org", "other.api64.ipify.org"):
            with self.subTest(host=host):
                self.assertEqual(build.route(self.entries, host=host)[0], "常规境外")
        bad = [(r, p, origin) for r, p, origin in self.entries
               if r != Rule("DOMAIN", "api64.ipify.org")]
        with self.assertRaisesRegex(Invalid, "Routing constraint failed: api64.ipify.org"):
            build.constraints(bad, self.personal, self.parsed)

    def test_claude_check_probe_rejects_unapproved_target_or_exit(self):
        for key, value in (("domain", "ipify.org"), ("policy", "常规境外"), ("policy", "DIRECT")):
            with self.subTest(key=key, value=value):
                personal = copy.deepcopy(self.personal)
                personal["claude_check_probe"][key] = value
                with self.assertRaisesRegex(Invalid, "Claude Check probe"):
                    build.compose(self.parsed, self.manifest, personal)

    def test_exact_ths_and_ai_shared_ownership(self):
        ths = [r.value for r, p, origin in self.entries if origin == "R03" and p == "DIRECT"]
        self.assertEqual(ths, build.THS)
        for domain in ("sentry.io", "intercom.io", "intercomcdn.com"):
            matches = [(r, p) for r, p, _ in self.entries if r == Rule("DOMAIN-SUFFIX", domain)]
            self.assertEqual(matches, [(Rule("DOMAIN-SUFFIX", domain), "OpenAI")])

    def test_humb_is_direct_even_if_future_ai_source_adds_it(self):
        parsed = copy.deepcopy(self.parsed)
        parsed["openai-base"].append(Rule("DOMAIN", "humb.apple.com"))
        entries, _, _ = build.compose(parsed, self.manifest, self.personal)
        build.constraints(entries, self.personal, parsed)
        self.assertEqual(build.route(entries, host="humb.apple.com")[0], "DIRECT")

    def test_exit_constraints_cannot_be_bypassed_by_new_baseline(self):
        personal = copy.deepcopy(self.personal)
        personal["groups"]["OpenAI"] = build.GROUPS["常规境外"]
        with self.assertRaises(Invalid):
            build.build(self.raw, self.manifest, personal, self.counts)
        bad = [(r, "DIRECT" if origin.startswith("openai") else p, origin)
               for r, p, origin in self.entries]
        with self.assertRaises(Invalid):
            build.constraints(bad, self.personal, self.parsed)

    def test_single_known_ai_endpoint_loss_blocks_update(self):
        parsed = copy.deepcopy(self.parsed)
        parsed["openai-base"] = [r for r in parsed["openai-base"] if r.value != "chat.com"]
        # One removal is within the 20% count threshold; the route guard still blocks it.
        build.check_counts({"openai-base": 12}, {"openai-base": 13})
        entries, _, _ = build.compose(parsed, self.manifest, self.personal)
        with self.assertRaisesRegex(Invalid, "Known AI endpoint"):
            build.constraints(entries, self.personal, parsed)

    def test_entire_bilibili_domain_set_is_direct(self):
        for r in self.parsed["bilibili"]:
            if r.kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
                with self.subTest(domain=r.value):
                    self.assertEqual(build.route(self.entries, host=r.value)[0], "DIRECT")

    def test_removes_foreign_snssdk_preserves_bytedapm(self):
        self.assertEqual(build.route(self.entries, host="a.bytedapm.com")[0], "常规境外")
        self.assertEqual(build.route(self.entries, host="a.snssdk.com")[0], "DIRECT")
        self.assertFalse(any(p != "DIRECT" and (r.value == "snssdk.com" or r.value.endswith(".snssdk.com"))
                             for r, p, _ in self.entries))

    def test_threshold_boundaries(self):
        for count in (80, 100, 150):
            build.check_counts({"x": count}, {"x": 100})
        for count in (0, 79, 151):
            with self.assertRaises(Invalid):
                build.check_counts({"x": count}, {"x": 100})
        with self.assertRaises(Invalid):
            build.check_counts({"new": 1}, {"old": 1})

    def test_render_has_only_local_bindings_and_no_remote_rules(self):
        conf, _ = build.render(self.entries, self.personal)
        self.assertNotIn("RULE-SET,", conf)
        self.assertEqual(len(parse.sections(conf)["Proxy Group"]), 3)
        for group, node in build.GROUPS.items():
            self.assertIn(f"{group} = select,{node},policy-select-name={node}", conf)
        self.assertIn("^https?://(www.)?google.cn https://www.google.com 302", conf)
        self.assertIn("hostname = *.google.cn", conf)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        (self.root / ".work").mkdir()
        for name in runner.BUNDLE_PATHS + ("policy/release.json",):
            source, target = ROOT / name, self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copy2(source, target)
        # Each fixture starts paused regardless of the deployed repository's release setting.
        runner.write(self.root / "policy/release.json", dict(publish_enabled=False, acceptance=None))

    def fingerprint(self):
        return {str(p.relative_to(self.root)): fetch.digest(p.read_bytes()) for p in self.root.rglob("*")
                if p.is_file() and not str(p.relative_to(self.root)).startswith((".work/", "checks/"))}

    def test_complete_offline_rebuild(self):
        conf, report = runner.verify(self.root)
        self.assertEqual(conf, (self.root / "rillmoss.conf").read_text())
        self.assertEqual(report["rules_version"], runner.read(self.root / "version.json")["rules_version"])

    def test_tampered_and_missing_raw_snapshot_fails(self):
        raw = self.root / "snapshot/raw/openai-acl.txt"
        raw.write_text("# truncated\n")
        with self.assertRaises(Invalid):
            runner.verify(self.root)
        raw.unlink()
        with self.assertRaises((Invalid, FileNotFoundError)):
            runner.verify(self.root)

    def test_any_fetch_failure_leaves_entire_bundle_unchanged(self):
        before = self.fingerprint()
        def failed(manifest, raw):
            raw.mkdir(parents=True)
            (raw / "base.txt").write_text("partial")
            raise Invalid("simulated interrupted download")
        with self.assertRaises(Invalid):
            runner.stage(self.root, self.root / ".work/candidate", collector=failed)
        self.assertEqual(self.fingerprint(), before)

    def test_install_exception_rolls_back_all_files(self):
        before = self.fingerprint()
        calls = 0
        def failing_replace(a, b):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError("simulated filesystem error")
            return runner.os.replace(a, b)
        with self.assertRaises(OSError):
            runner.install(self.root, ROOT, replace=failing_replace)
        self.assertEqual(self.fingerprint(), before)

    def test_duplicate_task_lock_rejects_second_runner(self):
        with runner.lock(self.root):
            with self.assertRaises(Invalid):
                with runner.lock(self.root):
                    self.fail("Second task acquired the lock")

    def test_failed_update_records_failure_without_touching_version(self):
        before = self.fingerprint()
        with patch("rillmoss.runner.stage", side_effect=Invalid("simulated upstream failure")):
            self.assertEqual(runner.update(self.root), 1)
        self.assertEqual(before, self.fingerprint())
        self.assertEqual(runner.read(self.root / "checks/latest.json")["status"], "failed")

    def test_publication_requires_device_evidence(self):
        self.assertFalse(runner.can_publish(self.root))
        runner.write(self.root / "policy/release.json", dict(publish_enabled=True, acceptance=None))
        with self.assertRaises(Invalid):
            runner.can_publish(self.root)

    def test_rollback_rejects_unaccepted_candidate(self):
        before = self.fingerprint()
        with self.assertRaises(Invalid):
            runner.rollback(self.root, ROOT)
        self.assertEqual(before, self.fingerprint())

    def authorize_publication(self):
        runner.write(self.root / "policy/release.json", dict(
            publish_enabled=True, acceptance=None,
            user_authorization=dict(scope="current_policy_and_daily_source_updates",
                                    confirmed_at="2026-09-12T00:00:00+00:00",
                                    evidence="synthetic test fixture")))

    def test_user_authorization_preserves_unverified_acceptance_and_pause(self):
        self.authorize_publication()
        self.assertTrue(runner.can_publish(self.root))
        control = runner.read(self.root / "policy/release.json")
        self.assertIsNone(control["acceptance"])
        control["publish_enabled"] = False
        runner.write(self.root / "policy/release.json", control)
        self.assertFalse(runner.can_publish(self.root))

    def test_incomplete_user_authorization_cannot_publish(self):
        for field in ("scope", "confirmed_at", "evidence"):
            with self.subTest(field=field):
                self.authorize_publication()
                control = runner.read(self.root / "policy/release.json")
                control["user_authorization"][field] = ""
                runner.write(self.root / "policy/release.json", control)
                with self.assertRaisesRegex(Invalid, "user authorization"):
                    runner.can_publish(self.root)

    def test_authorized_update_installs_complete_bundle_with_probe_rule(self):
        self.authorize_publication()
        real_stage = runner.stage
        def collector(manifest, raw):
            shutil.copytree(self.root / "snapshot/raw", raw)
            return runner.read(self.root / "snapshot/manifest.json")["upstream"]
        def stage(root, candidate):
            return real_stage(root, candidate, collector=collector)
        with patch("rillmoss.runner.stage", side_effect=stage), patch(
                "rillmoss.runner.install", wraps=runner.install) as installed:
            self.assertEqual(runner.update(self.root), 0)
            installed.assert_called_once()
        conf, _ = runner.verify(self.root)
        self.assertIn("DOMAIN,api64.ipify.org,V3 Static Residential", conf)
        self.assertTrue(runner.read(self.root / "checks/latest.json")["publication_enabled"])
        self.assertIsNone(runner.read(self.root / "policy/release.json")["acceptance"])

    def test_authorized_failed_update_preserves_current_bundle(self):
        self.authorize_publication()
        before = self.fingerprint()
        with patch("rillmoss.runner.stage", side_effect=Invalid("simulated upstream failure")):
            self.assertEqual(runner.update(self.root), 1)
        self.assertEqual(before, self.fingerprint())
        self.assertFalse(runner.read(self.root / "checks/latest.json")["bundle_applied"])

    def test_rollback_pauses_publication_and_restores_whole_bundle(self):
        source = Path(self.temp.name) / "accepted"
        shutil.copytree(self.root, source)
        version = runner.read(source / "version.json")["rules_version"]
        acceptance = {k: "passed" for k in ("mac", "iphone", "ai_faults", "ipv4", "ipv6", "udp", "device_update")}
        acceptance.update(rules_version=version, evidence="synthetic test fixture")
        runner.write(source / "policy/release.json", dict(publish_enabled=True, acceptance=acceptance))
        runner.rollback(self.root, source)
        self.assertFalse(runner.can_publish(self.root))
        runner.verify(self.root)
        self.assertEqual(runner.read(self.root / "checks/latest.json")["status"], "rolled_back_publication_paused")

    def test_success_while_paused_does_not_install_candidate(self):
        before = self.fingerprint()
        def checked(root, candidate):
            return dict(rules_version="different-version", base_changes_not_imported={})
        with patch("rillmoss.runner.stage", side_effect=checked), patch("rillmoss.runner.install") as installed:
            self.assertEqual(runner.update(self.root), 0)
            installed.assert_not_called()
        self.assertEqual(before, self.fingerprint())
        status = runner.read(self.root / "checks/latest.json")
        self.assertEqual(status["status"], "passed_publication_paused")
        self.assertNotEqual(status["current_rules_version"], status["candidate_rules_version"])

    def test_oversized_source_fails_before_install(self):
        before = self.fingerprint()
        def collector(manifest, raw):
            shutil.copytree(self.root / "snapshot/raw", raw)
            target = raw / "openai-acl.txt"
            target.write_text(target.read_text() + "DOMAIN-SUFFIX,more.example\n" * 20)
            return runner.read(self.root / "snapshot/manifest.json")["upstream"]
        with self.assertRaisesRegex(Invalid, "abnormal rule count"):
            runner.stage(self.root, self.root / ".work/huge", collector=collector)
        self.assertEqual(before, self.fingerprint())

    def test_unchanged_recheck_keeps_rules_timestamp(self):
        def collector(manifest, raw):
            shutil.copytree(self.root / "snapshot/raw", raw)
            return runner.read(self.root / "snapshot/manifest.json")["upstream"]
        output = self.root / ".work/rechecked"
        runner.stage(self.root, output, collector=collector)
        self.assertEqual(runner.read(output / "version.json"), runner.read(self.root / "version.json"))
        self.assertEqual((output / "rillmoss.conf").read_bytes(), (self.root / "rillmoss.conf").read_bytes())

    def test_upstream_commit_change_is_not_a_fake_rule_version(self):
        def collector(manifest, raw):
            shutil.copytree(self.root / "snapshot/raw", raw)
            metadata = runner.read(self.root / "snapshot/manifest.json")["upstream"]
            repo = "acl4ssr/acl4ssr"
            old = metadata["pins"][repo]
            metadata["pins"][repo] = "b" * 40
            record = metadata["sources"]["openai-acl"]
            record["commit"] = "b" * 40
            record["url"] = record["url"].replace(old, "b" * 40)
            return metadata
        output = self.root / ".work/new-provenance"
        runner.stage(self.root, output, collector=collector)
        old, new = runner.read(self.root / "version.json"), runner.read(output / "version.json")
        self.assertNotEqual(old["snapshot_id"], new["snapshot_id"])
        self.assertEqual(old["rules_version"], new["rules_version"])
        self.assertEqual(old["rules_built_at"], new["rules_built_at"])


class GitPublicationTests(unittest.TestCase):
    def test_remote_divergence_stops_before_commit(self):
        with patch("rillmoss.runner.verify"), patch("rillmoss.runner.git", side_effect=["a" * 40, "b" * 40 + "\trefs/heads/main"]) as git:
            with self.assertRaises(Invalid):
                runner.commit_update(Path("."), "a" * 40)
            self.assertEqual(git.call_count, 2)

    @patch.dict("os.environ", {"GITHUB_RUN_ID": "123456", "GITHUB_RUN_ATTEMPT": "1"})
    @patch("rillmoss.runner.utc", return_value="2026-01-01T00:00:00+00:00")
    def test_one_real_commit_and_nonfastforward_race(self, _clock):
        with tempfile.TemporaryDirectory() as temp:
            remote, work, other = [Path(temp) / name for name in ("remote.git", "work", "other")]
            def command(cwd, *args):
                return subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args],
                                      cwd=cwd, capture_output=True, check=True, text=True).stdout.strip()
            command(Path(temp), "init", "--bare", "--initial-branch=main", str(remote))
            work.mkdir()
            command(work, "init", "--initial-branch=main")
            for name in runner.BUNDLE_PATHS:
                source, target = ROOT / name, work / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if source.is_dir():
                    shutil.copytree(source, target)
                else:
                    shutil.copy2(source, target)
            command(work, "add", ".")
            command(work, "commit", "-m", "Initial fixture")
            command(work, "remote", "add", "origin", str(remote))
            command(work, "push", "origin", "HEAD:main")
            head = command(work, "rev-parse", "HEAD")
            runner.record_check(work, dict(status="passed", rules_changed=False))
            runner.commit_update(work, head)
            published = command(work, "rev-parse", "HEAD")
            self.assertEqual(command(remote, "rev-parse", "main"), published)
            self.assertEqual(command(work, "rev-list", "--count", f"{head}..{published}"), "1")
            command(Path(temp), "clone", str(remote), str(other))
            # A reused CI run ID and the same second must still stage a real change.
            runner.record_check(work, dict(status="passed", rules_changed=True))
            self.assertIn("checks/latest.json", command(work, "diff", "--name-only").splitlines())
            real_git = runner.git
            def racing_git(root, *args):
                result = real_git(root, *args)
                if args[0] == "ls-remote":
                    (other / "maintainer.txt").write_text("Concurrent maintainer change")
                    command(other, "add", "maintainer.txt")
                    command(other, "commit", "-m", "Concurrent change")
                    command(other, "push", "origin", "main")
                return result
            with patch("rillmoss.runner.git", side_effect=racing_git):
                with self.assertRaises(subprocess.CalledProcessError):
                    runner.commit_update(work, published)
            self.assertEqual(command(remote, "rev-parse", "main"), command(other, "rev-parse", "HEAD"))
            self.assertNotEqual(command(remote, "rev-parse", "main"), command(work, "rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()
