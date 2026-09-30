import copy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from rillmoss import build, fetch, guard, runner
from rillmoss.parse import Invalid, Rule

ROOT = Path(__file__).resolve().parents[1]


class DirectRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.personal = runner.read(ROOT / "policy/personal.json")
        cls.manifest = runner.read(ROOT / "policy/sources.json")
        cls.parsed, cls.counts = build.parse_sources(ROOT / "snapshot/raw", cls.manifest, cls.personal)
        cls.entries, _, _ = build.compose(cls.parsed, cls.manifest, cls.personal)

    def validate(self, entries, parsed=None, personal=None):
        return guard.validate(entries, parsed or self.parsed, self.manifest, personal or self.personal)

    def changed_global(self, rule):
        parsed = copy.deepcopy(self.parsed)
        parsed["global"].append(rule)
        counts = dict(self.counts)
        counts["global"] += 1
        build.check_counts(counts, self.counts)
        entries, _, _ = build.compose(parsed, self.manifest, self.personal)
        return entries, parsed

    def test_confirmed_direct_exceptions_and_domestic_targets(self):
        report, checks = self.validate(self.entries)
        self.assertEqual(report["claude_conflicts"], [])
        self.assertTrue(all(row["actual"] == "DIRECT" for row in checks))
        for host in ("h-adashx.ut.hzshudian.com", "qingmail.cn", "a.qingmail.com",
                     "router.asus.com", "local.adguard.org", "device.ts.net", "hiwifi.com",
                     "gspe19-cn.ls-apple.com.akadns.net", "appldnld.apple.com.edgesuite.net",
                     "new-cdn.apple.com.akadns.net",
                     "e16991.b.akamaiedge.net", "init01.push-apple.com.akadns.net"):
            with self.subTest(host=host):
                self.assertEqual(build.route(self.entries, host=host)[0], "DIRECT")

    def test_shared_cdns_and_the_observed_endpoint_remain_narrow(self):
        for host in ("unrelated.akadns.net", "other.edgesuite.net", "other.b.akamaiedge.net",
                     "other.hzshudian.com", "child.h-adashx.ut.hzshudian.com", "config.edge.skype.com",
                     "bytedapm.com"):
            with self.subTest(host=host):
                self.assertEqual(build.route(self.entries, host=host)[0], "Overseas")

    def test_bank_and_hema_upstream_proxy_reclassification_is_blocked(self):
        for host in ("cmbchina.com", "hemaos.com"):
            with self.subTest(host=host):
                entries, parsed = self.changed_global(Rule("DOMAIN-SUFFIX", host))
                self.assertEqual(len(entries), len(self.entries))
                self.assertEqual(build.route(entries, host=host)[0], "Overseas")
                build.constraints(entries, self.personal, parsed)
                with self.assertRaisesRegex(Invalid, "Unreviewed DIRECT routing conflict"):
                    self.validate(entries, parsed)

    def test_exact_proxy_child_cannot_hide_behind_a_direct_parent(self):
        entries, parsed = self.changed_global(Rule("DOMAIN", "login.cmbchina.com"))
        self.assertEqual(build.route(entries, host="cmbchina.com")[0], "DIRECT")
        self.assertEqual(build.route(entries, host="login.cmbchina.com")[0], "Overseas")
        with self.assertRaisesRegex(Invalid, "Unreviewed DIRECT routing conflict.*protected-subdomain"):
            self.validate(entries, parsed)

    def test_proxy_keyword_and_wildcard_covering_domestic_targets_are_blocked(self):
        for r in (Rule("DOMAIN-KEYWORD", "hema"), Rule("DOMAIN-WILDCARD", "*.cmbchina.com")):
            with self.subTest(rule=r):
                entries, parsed = self.changed_global(r)
                with self.assertRaisesRegex(Invalid, "Unreviewed DIRECT routing conflict"):
                    self.validate(entries, parsed)

    def test_new_direct_source_target_is_checked_without_a_manual_app_entry(self):
        parsed = copy.deepcopy(self.parsed)
        r = Rule("DOMAIN-SUFFIX", "new-critical.cn")
        parsed["china"].append(r)
        parsed["global"].append(r)
        entries, _, _ = build.compose(parsed, self.manifest, self.personal)
        with self.assertRaisesRegex(Invalid, "Unreviewed DIRECT routing conflict.*china"):
            self.validate(entries, parsed)

    def test_new_proxy_child_of_an_unlisted_direct_source_domain_is_blocked(self):
        entries, parsed = self.changed_global(Rule("DOMAIN", "new-critical.qq.com"))
        self.assertEqual(build.route(entries, host="qq.com")[0], "DIRECT")
        with self.assertRaisesRegex(Invalid, "Unreviewed DIRECT routing conflict.*protected-subdomain"):
            self.validate(entries, parsed)

    def test_generic_cn_fallback_does_not_disallow_new_overseas_services(self):
        entries, parsed = self.changed_global(Rule("DOMAIN-SUFFIX", "new-overseas-service.cn"))
        self.assertEqual(build.route(entries, host="new-overseas-service.cn")[0], "Overseas")
        self.validate(entries, parsed)

    def test_an_interior_ip_overlap_is_checked_not_only_the_network_start(self):
        parsed = copy.deepcopy(self.parsed)
        parsed["china"].append(Rule("IP-CIDR", "203.0.113.0/24"))
        parsed["global"].append(Rule("IP-CIDR", "203.0.113.64/26"))
        entries, _, _ = build.compose(parsed, self.manifest, self.personal)
        self.assertEqual(build.route(entries, address="203.0.113.1")[0], "DIRECT")
        self.assertEqual(build.route(entries, address="203.0.113.65")[0], "Overseas")
        with self.assertRaisesRegex(Invalid, "Unreviewed DIRECT routing conflict.*203.0.113"):
            self.validate(entries, parsed)

    def test_a_proxy_ip_range_after_the_apple_direct_range_does_not_raise(self):
        entries, parsed = self.changed_global(Rule("IP-CIDR", "17.253.0.0/24"))
        self.assertEqual(build.route(entries, address="17.253.0.1")[0], "DIRECT")
        self.validate(entries, parsed)

    def test_reviewed_conflict_is_exact_not_an_allowance_for_any_proxy_policy(self):
        entries = [(r, "OpenAI" if r == Rule("DOMAIN-SUFFIX", "akadns.net") else p, origin)
                   for r, p, origin in self.entries]
        with self.assertRaisesRegex(Invalid, "Unreviewed DIRECT routing conflict"):
            self.validate(entries)

    def test_loss_of_a_domestic_target_is_blocked_even_with_unchanged_app_names(self):
        entries = [(r, p, sid) for r, p, sid in self.entries if r.value != "cmbchina.com"]
        with self.assertRaisesRegex(Invalid, "Required DIRECT target has no domain route: cmbchina.com"):
            self.validate(entries)

    def test_each_domestic_app_needs_a_real_target_inventory(self):
        personal = copy.deepcopy(self.personal)
        personal["direct_routing"]["domestic_targets"].pop("盒马")
        with self.assertRaisesRegex(Invalid, "Every domestic app"):
            self.validate(self.entries, personal=personal)

    def test_direct_exceptions_cannot_override_claude_content_or_priority(self):
        original = [(r, p, sid) for r, p, sid in self.entries if p == "Claude"]
        for text in ("DOMAIN-SUFFIX,sentry.io", "DOMAIN,consumer.datadog.cn"):
            with self.subTest(rule=text):
                personal = copy.deepcopy(self.personal)
                personal["direct_routing"]["priority_rules"].append(text)
                with self.assertRaisesRegex(Invalid, "conflicts with Claude; AI unchanged"):
                    build.compose(self.parsed, self.manifest, personal)
                self.assertEqual([(r, p, sid) for r, p, sid in self.entries if p == "Claude"], original)


class FailedDailyUpdateTests(unittest.TestCase):
    def test_new_direct_conflict_keeps_the_published_bundle_intact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in runner.BUNDLE_PATHS + ("policy/release.json",):
                source, target = ROOT / name, root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if source.is_dir():
                    shutil.copytree(source, target)
                else:
                    shutil.copy2(source, target)
            before = {name: fetch.digest((root / name).read_bytes()) for name in
                      ("rillmoss.conf", "policy/personal.json", "version.json", "snapshot/manifest.json")}

            def collector(manifest, raw):
                shutil.copytree(root / "snapshot/raw", raw)
                path = raw / "global.txt"
                with path.open("a") as out:
                    out.write("\nHOST-SUFFIX,cmbchina.com,Global\n")
                metadata = runner.read(root / "snapshot/manifest.json")["upstream"]
                metadata["sources"]["global"].update(sha256=fetch.digest(path.read_bytes()), bytes=path.stat().st_size)
                return metadata

            stage = runner.stage
            with patch("rillmoss.runner.stage", side_effect=lambda r, out: stage(r, out, collector=collector)):
                self.assertEqual(runner.update(root), 1)
            latest = runner.read(root / "checks/latest.json")
            self.assertEqual(latest["status"], "failed")
            self.assertFalse(latest["bundle_applied"])
            self.assertIn("Unreviewed DIRECT routing conflict", latest["error"])
            self.assertEqual(before, {name: fetch.digest((root / name).read_bytes()) for name in before})


if __name__ == "__main__":
    unittest.main()
