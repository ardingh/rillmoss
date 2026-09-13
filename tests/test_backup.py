from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rillmoss import backup
from rillmoss.parse import Invalid

ROOT = Path(__file__).resolve().parents[1]
DUE = datetime(2026, 9, 15, 1, 0, tzinfo=timezone.utc)


class MonthlyBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root, self.remote = self.base / "checkout", self.base / "origin.git"
        self.root.mkdir()
        for name in ("rillmoss.conf", "snapshot", "policy", "reports", "version.json", "checks", "rillmoss"):
            source = ROOT / name
            if source.is_dir():
                shutil.copytree(source, self.root / name, ignore=shutil.ignore_patterns("__pycache__"))
            else:
                shutil.copy2(source, self.root / name)
        backup.git(self.root, "init", "-b", "main")
        backup.git(self.root, "config", "user.name", "Backup Test")
        backup.git(self.root, "config", "user.email", "backup@example.invalid")
        backup.git(self.root, "add", ".")
        backup.git(self.root, "commit", "-m", "complete published baseline")
        backup.git(self.base, "init", "--bare", str(self.remote))
        backup.git(self.root, "remote", "add", "origin", str(self.remote))
        backup.git(self.root, "push", "origin", "main")

    def commit(self, message):
        backup.git(self.root, "add", ".")
        backup.git(self.root, "commit", "-m", message)
        backup.git(self.root, "push", "origin", "main")

    def test_timezone_boundary_and_no_early_git_access(self):
        with patch.object(backup, "git", side_effect=AssertionError("early Git access")):
            result = backup.monthly(self.root, datetime(2026, 9, 14, 15, 59, tzinfo=timezone.utc))
        self.assertEqual(result["status"], "not_due")
        result = backup.monthly(self.root, datetime(2026, 9, 14, 16, 0, tzinfo=timezone.utc))
        self.assertEqual(result["tag"], "backup-2026-09-15")

    def test_full_archive_restores_offline_without_touching_main(self):
        before = backup.git(self.root, "rev-parse", "HEAD")
        with patch("rillmoss.fetch.download", side_effect=AssertionError("upstream access")):
            result = backup.monthly(self.root, DUE)
        self.assertEqual(result["status"], "archived")
        self.assertEqual(backup.git(self.remote, "rev-parse", "main"), before)
        restored = self.base / "restored"
        backup.git(self.base, "clone", "--branch", result["tag"], str(self.remote), str(restored))
        with patch("rillmoss.fetch.download", side_effect=AssertionError("upstream access")):
            conf, report = backup.verify(restored)
        self.assertEqual(conf, (self.root / "rillmoss.conf").read_text())
        self.assertEqual(report["rule_count"], result["rule_count"])
        self.assertTrue((restored / "rillmoss/build.py").is_file())
        note = backup.git(self.root, "for-each-ref", "--format=%(contents)", "refs/tags/" + result["tag"])
        self.assertEqual(json.loads(note)["commit"], before)

    def test_repeat_never_moves_existing_tag_even_when_main_changes(self):
        first = backup.monthly(self.root, DUE)
        original = backup.git(self.remote, "rev-parse", first["tag"])
        (self.root / "later.txt").write_text("later published content")
        self.commit("later published version")
        result = backup.monthly(self.root, DUE)
        self.assertEqual(result["status"], "already_archived")
        self.assertEqual(backup.git(self.remote, "rev-parse", first["tag"]), original)

    def test_late_run_keeps_real_dates_and_can_archive_after_upstream_failure(self):
        path = self.root / "checks/latest.json"
        check = json.loads(path.read_text())
        check.update(status="failed", checked_at="2026-09-16T00:08:00+00:00")
        path.write_text(json.dumps(check))
        self.commit("record failed upstream check")
        version = json.loads((self.root / "version.json").read_text())
        result = backup.monthly(self.root, datetime(2026, 9, 16, 1, 0, tzinfo=timezone.utc))
        self.assertEqual(result["tag"], "backup-2026-09-15")
        self.assertTrue(result["archived_at"].startswith("2026-09-16"))
        self.assertEqual(result["rules_built_at"], version["rules_built_at"])
        self.assertEqual(result["last_check_status"], "failed")

    def test_corrupt_published_snapshot_cannot_be_archived(self):
        (self.root / "snapshot/raw/base.txt").write_text("corrupt")
        self.commit("broken snapshot")
        with self.assertRaises(Invalid):
            backup.monthly(self.root, DUE)
        self.assertEqual(backup.git(self.remote, "tag", "--list"), "")

    def test_dirty_checkout_and_stale_head_stop(self):
        (self.root / "unpublished.txt").write_text("local only")
        with self.assertRaisesRegex(Invalid, "clean checkout"):
            backup.monthly(self.root, DUE)
        backup.git(self.root, "add", ".")
        backup.git(self.root, "commit", "-m", "not published")
        with self.assertRaisesRegex(Invalid, "Remote main changed"):
            backup.monthly(self.root, DUE)
        self.assertEqual(backup.git(self.remote, "tag", "--list"), "")

    def test_concurrent_tag_creation_is_not_overwritten(self):
        real_git = backup.git
        competing = {}
        def race(root, *args, **kwargs):
            if args[0] == "push":
                real_git(self.remote, "-c", "user.name=Other", "-c", "user.email=other@example.invalid",
                         "tag", "-a", "backup-2026-09-15", "main", "-m", "competing archive")
                competing["tag"] = real_git(self.remote, "rev-parse", "backup-2026-09-15")
            return real_git(root, *args, **kwargs)
        with patch.object(backup, "git", side_effect=race), self.assertRaisesRegex(Invalid, "push"):
            backup.monthly(self.root, DUE)
        self.assertEqual(real_git(self.remote, "rev-parse", "backup-2026-09-15"), competing["tag"])

    def test_next_month_gets_separate_archive(self):
        first = backup.monthly(self.root, DUE)
        second = backup.monthly(self.root, datetime(2026, 10, 15, 1, 0, tzinfo=timezone.utc))
        self.assertEqual(first["tag"], "backup-2026-09-15")
        self.assertEqual(second["tag"], "backup-2026-10-15")


if __name__ == "__main__":
    unittest.main()
