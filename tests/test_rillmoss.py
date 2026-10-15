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

    def test_muse_routes_cover_approved_meta_domains_without_capturing_neighbors(self):
        self.assertEqual(self.personal["groups"]["Muse"], "V3 Static Residential")
        for host in ("muse.ai", "auth.muse.ai", "api.muse.ai", "security.muse.ai",
                     "introducing.muse.ai", "metaaivm.com", "hatch.metaaivm.com", "vm.metaaivm.com",
                     "meta.ai", "api.meta.ai", "agent.meta.ai", "gateway.meta.ai", "edge-chat.meta.ai",
                     "edge-chat-latest.meta.ai", "shortwave.meta.ai", "deep.worker.meta.ai",
                     "metaaiusercontent.com", "media.metaaiusercontent.com", "ecto1usercontent.com",
                     "files.ecto1usercontent.com", "meta-agents-apps.workers.dev",
                     "app.meta-agents-apps.workers.dev", "meta.com", "auth.meta.com",
                     "facebook.com", "www.facebook.com", "instagram.com", "i.instagram.com",
                     "fbcdn.net", "static.xx.fbcdn.net", "scontent.xx.fbcdn.net",
                     "facebook.net", "connect.facebook.net", "fbsbx.com", "lookaside.fbsbx.com"):
            with self.subTest(host=host):
                self.assertEqual(build.route(self.entries, host=host)[0], "Muse")
        for host in ("cdninstagram.com", "static.cdninstagram.com", "whatsapp.com",
                     "workers.dev", "other-app.workers.dev", "notmuse.ai", "muse.ai.example.com",
                     "notmetaaivm.com", "metaaivm.com.example.com", "notmeta.ai", "meta.ai.example.com",
                     "notmetaaiusercontent.com", "metaaiusercontent.com.example.com",
                     "notecto1usercontent.com", "ecto1usercontent.com.example.com",
                     "notmeta-agents-apps.workers.dev", "meta-agents-apps.workers.dev.example.com",
                     "notmeta.com", "meta.com.example.com", "notfacebook.com", "facebook.com.example.com",
                     "notinstagram.com", "instagram.com.example.com",
                     "notfbcdn.net", "fbcdn.net.example.com", "notfacebook.net",
                     "facebook.net.example.com", "notfbsbx.com", "fbsbx.com.example.com"):
            with self.subTest(host=host):
                self.assertEqual(build.route(self.entries, host=host)[0], "Overseas")

    def test_muse_personal_routes_survive_upstream_removal_and_specific_proxy_rules(self):
        parsed = copy.deepcopy(self.parsed)
        parsed["global"] = [r for r in parsed["global"] if r not in build.MUSE_RULES]
        parsed["global"].insert(0, Rule("DOMAIN", "api.muse.ai"))
        parsed["global"].insert(0, Rule("DOMAIN-SUFFIX", "hatch.metaaivm.com"))
        parsed["global"].insert(0, Rule("DOMAIN", "api.meta.ai"))
        parsed["global"].insert(0, Rule("DOMAIN-WILDCARD", "future-*.meta.ai"))
        for domain in ("metaaiusercontent.com", "ecto1usercontent.com", "meta-agents-apps.workers.dev",
                       "meta.com", "facebook.com", "instagram.com", "fbcdn.net", "facebook.net", "fbsbx.com"):
            parsed["global"].insert(0, Rule("DOMAIN", "future." + domain))
        entries, _, _ = build.compose(parsed, self.manifest, self.personal)
        build.constraints(entries, self.personal, parsed)
        for host in ("muse.ai", "api.muse.ai", "metaaivm.com", "hatch.metaaivm.com",
                     "meta.ai", "api.meta.ai", "future-api.meta.ai", "future.metaaiusercontent.com",
                     "future.ecto1usercontent.com", "future.meta-agents-apps.workers.dev",
                     "future.meta.com", "future.facebook.com", "future.instagram.com",
                     "future.fbcdn.net", "future.facebook.net", "future.fbsbx.com"):
            self.assertEqual(build.route(entries, host=host)[0], "Muse")

    def test_muse_binding_and_personal_domain_scope_cannot_be_bypassed(self):
        for node in ("DIRECT", build.GROUPS["Overseas"]):
            with self.subTest(node=node):
                personal = copy.deepcopy(self.personal)
                personal["groups"]["Muse"] = node
                with self.assertRaisesRegex(Invalid, "Exact group binding"):
                    build.build(self.raw, self.manifest, personal, self.counts)
        for rules in ([], self.personal["muse_rules"][:1], self.personal["muse_rules"][:-1],
                      ["DOMAIN-SUFFIX,workers.dev", *self.personal["muse_rules"]]):
            with self.subTest(rules=rules):
                personal = copy.deepcopy(self.personal)
                personal["muse_rules"] = rules
                with self.assertRaisesRegex(Invalid, "Muse rules must retain"):
                    build.compose(self.parsed, self.manifest, personal)

    def test_muse_residential_route_cannot_be_shadowed(self):
        for policy in ("DIRECT", "Overseas", "OpenAI"):
            with self.subTest(policy=policy):
                entries = [(Rule("DOMAIN", "api.muse.ai"), policy, "test"), *self.entries]
                with self.assertRaisesRegex(Invalid, "Routing constraint failed: api.muse.ai"):
                    build.constraints(entries, self.personal, self.parsed)

    def test_new_ai_endpoint_inside_meta_ai_blocks_muse_priority_conflict(self):
        for policy, sid in (("Claude", "claude-page"), ("OpenAI", "openai-base")):
            for kind, value in (("DOMAIN", "future-service.meta.ai"),
                                ("DOMAIN-SUFFIX", "future-service.meta.ai"),
                                ("DOMAIN-WILDCARD", "future-*.meta.ai")):
                with self.subTest(policy=policy, kind=kind):
                    parsed = copy.deepcopy(self.parsed)
                    parsed[sid].append(Rule(kind, value))
                    entries, _, _ = build.compose(parsed, self.manifest, self.personal)
                    with self.assertRaisesRegex(Invalid, "Muse routing conflict"):
                        build.constraints(entries, self.personal, parsed)

    def test_direct_exception_cannot_override_any_approved_muse_domain(self):
        for domain in ("muse.ai", "metaaivm.com", "meta.ai", "metaaiusercontent.com",
                       "ecto1usercontent.com", "meta-agents-apps.workers.dev", "meta.com",
                       "facebook.com", "instagram.com", "fbcdn.net", "facebook.net", "fbsbx.com"):
            with self.subTest(domain=domain):
                personal = copy.deepcopy(self.personal)
                personal["direct_routing"]["priority_rules"].append("DOMAIN,api." + domain)
                with self.assertRaisesRegex(Invalid, "Direct exception conflicts with Muse"):
                    build.compose(self.parsed, self.manifest, personal)

    def test_claude_check_probe_is_exact_and_precedes_general_ipify(self):
        self.assertEqual(build.route(self.entries, host="api64.ipify.org")[0], "V3 Static Residential")
        for host in ("ipify.org", "api.ipify.org", "other.api64.ipify.org"):
            with self.subTest(host=host):
                self.assertEqual(build.route(self.entries, host=host)[0], "Overseas")
        bad = [(r, p, origin) for r, p, origin in self.entries
               if r != Rule("DOMAIN", "api64.ipify.org")]
        with self.assertRaisesRegex(Invalid, "Routing constraint failed: api64.ipify.org"):
            build.constraints(bad, self.personal, self.parsed)

    def test_claude_check_probe_rejects_unapproved_target_or_exit(self):
        for key, value in (("domain", "ipify.org"), ("policy", "Overseas"), ("policy", "DIRECT")):
            with self.subTest(key=key, value=value):
                personal = copy.deepcopy(self.personal)
                personal["claude_check_probe"][key] = value
                with self.assertRaisesRegex(Invalid, "Claude Check probe"):
                    build.compose(self.parsed, self.manifest, personal)

    def test_exact_ths_and_independent_claude_shared_rules(self):
        ths = [r.value for r, p, origin in self.entries if origin == "R03" and p == "DIRECT"]
        self.assertEqual(ths, build.THS)
        for domain in ("sentry.io", "intercom.io", "intercomcdn.com"):
            matches = [(r, p) for r, p, _ in self.entries if r == Rule("DOMAIN-SUFFIX", domain)]
            self.assertEqual(matches, [(Rule("DOMAIN-SUFFIX", domain), p) for p in ("Claude", "OpenAI")])

    def test_either_ai_group_survives_removing_the_other_sources(self):
        for remaining, removed in (("Claude", "OpenAI"), ("OpenAI", "Claude")):
            parsed = copy.deepcopy(self.parsed)
            for sid in build.AI_SOURCES[removed]:
                parsed[sid] = []
            entries, _, _ = build.compose(parsed, self.manifest, self.personal)
            for text in self.personal[f"{remaining.lower()}_required_rules"]:
                r = parse.rule(text)
                hosts = [r.value]
                if r.kind == "DOMAIN-SUFFIX":
                    hosts.append("probe." + r.value)
                for host in hosts:
                    with self.subTest(remaining=remaining, host=host):
                        self.assertEqual(build.route(entries, host=host)[0], remaining)

    def test_openai_cannot_mask_loss_of_a_required_claude_rule(self):
        for domain in ("sentry.io", "intercom.io", "intercomcdn.com", "anthropic.auth0.com", "statsigapi.net"):
            with self.subTest(domain=domain):
                parsed = copy.deepcopy(self.parsed)
                parsed["claude-page"] = [r for r in parsed["claude-page"] if r.value != domain]
                entries, _, _ = build.compose(parsed, self.manifest, self.personal)
                with self.assertRaisesRegex(Invalid, "Required Claude rule missing|Routing constraint failed"):
                    build.constraints(entries, self.personal, parsed)

    def test_claude_cannot_mask_loss_of_a_required_openai_rule(self):
        for domain in ("sentry.io", "intercom.io", "intercomcdn.com", "events.statsigapi.net",
                       "api-iam.intercom.io", "o33249.ingest.sentry.io"):
            with self.subTest(domain=domain):
                parsed = copy.deepcopy(self.parsed)
                for sid in build.AI_SOURCES["OpenAI"]:
                    parsed[sid] = [r for r in parsed[sid] if r.value != domain]
                entries, _, _ = build.compose(parsed, self.manifest, self.personal)
                with self.assertRaisesRegex(Invalid, "Required OpenAI rule missing"):
                    build.constraints(entries, self.personal, parsed)

    def test_claude_first_resolves_shared_dependencies_and_keeps_openai_core(self):
        for host in ("sentry.io", "intercom.io", "intercomcdn.com", "anthropic.auth0.com", "events.statsigapi.net",
                     "api-iam.intercom.io", "o33249.ingest.sentry.io", "api.anthropic.com",
                     "api.statsigapi.net", "browser-intake-us5-datadoghq.com"):
            with self.subTest(host=host):
                self.assertEqual(build.route(self.entries, host=host)[0], "Claude")
        for host in ("api.openai.com", "chatgpt.com", "cdn.oaistatic.com", "files.oaiusercontent.com",
                     "auth0.com", "api.statsig.com", "challenges.cloudflare.com", "stripe.com"):
            with self.subTest(host=host):
                self.assertEqual(build.route(self.entries, host=host)[0], "OpenAI")

    def test_new_claude_source_domain_cannot_be_shadowed_by_openai(self):
        parsed = copy.deepcopy(self.parsed)
        parsed["claude-page"].append(Rule("DOMAIN", "new-claude.auth0.com"))
        entries, _, _ = build.compose(parsed, self.manifest, self.personal)
        build.constraints(entries, self.personal, parsed)
        # An accidental earlier OpenAI wildcard must fail even for a new endpoint.
        entries.insert(0, (Rule("DOMAIN-SUFFIX", "new-claude.auth0.com"), "OpenAI", "test"))
        with self.assertRaisesRegex(Invalid, "Claude domain lost its routing priority"):
            build.constraints(entries, self.personal, parsed)

    def test_invalid_ai_order_cannot_drop_duplicate_or_reverse_groups(self):
        for order in ([], ["Claude"], ["Claude", "Claude"], ["OpenAI", "Claude"], ["Claude", "Other"]):
            with self.subTest(order=order):
                personal = copy.deepcopy(self.personal)
                personal["ai_rule_order"] = order
                with self.assertRaisesRegex(Invalid, "AI rule order"):
                    build.compose(self.parsed, self.manifest, personal)

    def test_humb_is_direct_even_if_future_ai_source_adds_it(self):
        parsed = copy.deepcopy(self.parsed)
        parsed["openai-base"].append(Rule("DOMAIN", "humb.apple.com"))
        entries, _, _ = build.compose(parsed, self.manifest, self.personal)
        build.constraints(entries, self.personal, parsed)
        self.assertEqual(build.route(entries, host="humb.apple.com")[0], "DIRECT")

    def test_exit_constraints_cannot_be_bypassed_by_new_baseline(self):
        personal = copy.deepcopy(self.personal)
        personal["groups"]["OpenAI"] = build.GROUPS["Overseas"]
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
        with self.assertRaisesRegex(Invalid, "Required OpenAI rule missing"):
            build.constraints(entries, self.personal, parsed)

    def test_entire_bilibili_domain_set_is_direct(self):
        for r in self.parsed["bilibili"]:
            if r.kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
                with self.subTest(domain=r.value):
                    self.assertEqual(build.route(self.entries, host=r.value)[0], "DIRECT")

    def test_removes_foreign_snssdk_preserves_bytedapm(self):
        self.assertEqual(build.route(self.entries, host="a.bytedapm.com")[0], "Overseas")
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
        self.assertEqual(len(parse.sections(conf)["Proxy Group"]), 4)
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
        self.assertIn("Muse = select,V3 Static Residential,policy-select-name=V3 Static Residential", conf)
        for domain in ("muse.ai", "metaaivm.com", "meta.ai", "metaaiusercontent.com",
                       "ecto1usercontent.com", "meta-agents-apps.workers.dev", "meta.com",
                       "facebook.com", "instagram.com", "fbcdn.net", "facebook.net", "fbsbx.com"):
            self.assertIn(f"DOMAIN-SUFFIX,{domain},Muse", conf)
            self.assertNotIn(f"DOMAIN-SUFFIX,{domain},Overseas", conf)
        self.assertTrue(runner.read(self.root / "checks/latest.json")["publication_enabled"])
        self.assertIsNone(runner.read(self.root / "policy/release.json")["acceptance"])

    def test_authorized_failed_update_preserves_current_bundle(self):
        self.authorize_publication()
        before = self.fingerprint()
        with patch("rillmoss.runner.stage", side_effect=Invalid("simulated upstream failure")):
            self.assertEqual(runner.update(self.root), 1)
        self.assertEqual(before, self.fingerprint())
        self.assertFalse(runner.read(self.root / "checks/latest.json")["bundle_applied"])

    def test_daily_update_keeps_all_muse_domains_residential_with_new_global_subdomains(self):
        self.authorize_publication()
        real_stage = runner.stage
        def collector(manifest, raw):
            shutil.copytree(self.root / "snapshot/raw", raw)
            target = raw / "global.txt"
            domains = ("muse.ai", "metaaivm.com", "meta.ai", "metaaiusercontent.com",
                       "ecto1usercontent.com", "meta-agents-apps.workers.dev", "meta.com",
                       "facebook.com", "instagram.com", "fbcdn.net", "facebook.net", "fbsbx.com")
            target.write_text(target.read_text() + "".join(
                "\nHOST,future-service." + domain + ",Global\n" for domain in domains))
            metadata = runner.read(self.root / "snapshot/manifest.json")["upstream"]
            metadata["sources"]["global"].update(sha256=fetch.digest(target.read_bytes()),
                                                   bytes=target.stat().st_size)
            return metadata
        with patch("rillmoss.runner.stage", side_effect=lambda root, candidate:
                   real_stage(root, candidate, collector=collector)):
            self.assertEqual(runner.update(self.root), 0)
        conf, _ = runner.verify(self.root)
        lines = parse.sections(conf)["Rule"]
        for domain in ("muse.ai", "metaaivm.com", "meta.ai", "metaaiusercontent.com",
                       "ecto1usercontent.com", "meta-agents-apps.workers.dev", "meta.com",
                       "facebook.com", "instagram.com", "fbcdn.net", "facebook.net", "fbsbx.com"):
            with self.subTest(domain=domain):
                self.assertLess(lines.index(f"DOMAIN-SUFFIX,{domain},Muse"),
                                lines.index(f"DOMAIN,future-service.{domain},Overseas"))
                self.assertNotIn(f"DOMAIN-SUFFIX,{domain},Overseas", conf)
        self.assertEqual(runner.read(self.root / "checks/latest.json")["status"], "passed")

    def test_daily_update_muse_priority_conflict_keeps_previous_complete_bundle(self):
        self.authorize_publication()
        before = self.fingerprint()
        real_stage = runner.stage
        def collector(manifest, raw):
            shutil.copytree(self.root / "snapshot/raw", raw)
            target = raw / "claude-page.txt"
            text = target.read_text()
            marker = "DOMAIN-SUFFIX,anthropic.com"
            self.assertIn(marker, text)
            target.write_text(text.replace(marker, "DOMAIN,future-service.meta-agents-apps.workers.dev\n" + marker, 1))
            metadata = runner.read(self.root / "snapshot/manifest.json")["upstream"]
            metadata["sources"]["claude-page"].update(sha256=fetch.digest(target.read_bytes()),
                                                       bytes=target.stat().st_size)
            return metadata
        with patch("rillmoss.runner.stage", side_effect=lambda root, candidate:
                   real_stage(root, candidate, collector=collector)):
            self.assertEqual(runner.update(self.root), 1)
        self.assertEqual(before, self.fingerprint())
        check = runner.read(self.root / "checks/latest.json")
        self.assertFalse(check["bundle_applied"])
        self.assertIn("Muse routing conflict", check["error"])
        runner.verify(self.root)

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
        old, new = runner.read(self.root / "version.json"), runner.read(output / "version.json")
        # A successful count change refreshes the next snapshot's baseline input,
        # even when its rule content and upstream provenance are unchanged.
        self.assertEqual(old["rules_version"], new["rules_version"])
        self.assertEqual(old["rules_built_at"], new["rules_built_at"])
        self.assertEqual((output / "rillmoss.conf").read_bytes(), (self.root / "rillmoss.conf").read_bytes())
        runner.install(self.root, output)
        repeated = self.root / ".work/rechecked-again"
        runner.stage(self.root, repeated, collector=collector)
        self.assertEqual(runner.read(repeated / "version.json"), new)
        self.assertEqual((repeated / "rillmoss.conf").read_bytes(), (output / "rillmoss.conf").read_bytes())

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
