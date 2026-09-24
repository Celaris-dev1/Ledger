"""Regression tests: the spool must be private (0600, per-user 0700 dir) and must never follow
a planted symlink or replay a file someone else can write."""
import os
import stat
import tempfile
import unittest

from ledger_sdk import _spool
from ledger_sdk._spool import Spool, SpoolSecurityError, private_dir


@unittest.skipUnless(os.name == "posix", "POSIX permissions")
class SpoolSecurity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_files_are_private(self):
        d = private_dir(self.tmp)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        p = os.path.join(d, "s.jsonl")
        sp = Spool(p)
        sp.push({"a": 1})
        sp.push({"a": 2})
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        sp.pop_front()
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_symlink_not_followed(self):
        victim = os.path.join(self.tmp, "victim")
        with open(victim, "w") as f:
            f.write("precious\n")
        p = os.path.join(self.tmp, "s.jsonl")
        os.symlink(victim, p)
        with self.assertRaises(OSError):
            Spool(p)
        # planted .tmp symlink is removed, not written through
        os.unlink(p)
        sp = Spool(p)
        sp.push({"a": 1})
        os.symlink(victim, p + ".tmp")
        sp.pop_front()
        with open(victim) as f:
            self.assertEqual(f.read(), "precious\n")

    def test_world_writable_spool_refused(self):
        p = os.path.join(self.tmp, "s.jsonl")
        with open(p, "w") as f:
            f.write('{"chain":"x","type":"injected"}\n')
        os.chmod(p, 0o666)
        with self.assertRaises(SpoolSecurityError):
            Spool(p)

    def test_private_dir_rejects_symlink(self):
        target = tempfile.mkdtemp()
        uid = os.getuid()
        os.symlink(target, os.path.join(self.tmp, f"ledger-sdk-{uid}"))
        with self.assertRaises(SpoolSecurityError):
            private_dir(self.tmp)

    def test_foreign_owner_refused(self):
        st = os.stat(self.tmp)
        fake = os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid + 1, st.st_gid, st.st_size,
                               st.st_atime, st.st_mtime, st.st_ctime))
        with self.assertRaises(SpoolSecurityError):
            _spool._check_owned(fake, "x")


if __name__ == "__main__":
    unittest.main()
