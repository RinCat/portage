# Copyright 2026 Gentoo Authors
# Portage Unit Testing Functionality

import io
import os
import stat
import tarfile
import tempfile

from portage.gpkg import tar_safe_extract
from portage.tests import TestCase


def _make_tar(members):
    """
    Build an uncompressed tar in memory. members is a list of
    (TarInfo, bytes or None) tuples.
    """
    data = io.BytesIO()
    with tarfile.open(mode="w", fileobj=data) as tar:
        for tarinfo, content in members:
            if content is None:
                tar.addfile(tarinfo)
            else:
                tarinfo.size = len(content)
                tar.addfile(tarinfo, io.BytesIO(content))
    data.seek(0)
    return data


def _regular(name, content=b"data"):
    tarinfo = tarfile.TarInfo(name)
    tarinfo.type = tarfile.REGTYPE
    tarinfo.mode = 0o644
    return (tarinfo, content)


def _symlink(name, target):
    tarinfo = tarfile.TarInfo(name)
    tarinfo.type = tarfile.SYMTYPE
    tarinfo.linkname = target
    tarinfo.mode = 0o777
    return (tarinfo, None)


def _directory(name):
    tarinfo = tarfile.TarInfo(name)
    tarinfo.type = tarfile.DIRTYPE
    tarinfo.mode = 0o755
    return (tarinfo, None)


class test_gpkg_hostile_case(TestCase):
    def _extract(self, members, dest_dir):
        data = _make_tar(members)
        with tarfile.open(mode="r", fileobj=data) as tar:
            tar_safe_extract(tar, "image").extractall(dest_dir)

    def _assertRejected(self, members):
        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = os.path.join(tmpdir, "dest")
            os.mkdir(dest_dir)
            self.assertRaises(ValueError, self._extract, members, dest_dir)
            self.assertEqual(os.listdir(dest_dir), [])

    def test_symlink_escape(self):
        """
        A symlink to an outside directory followed by a member written
        through it must not escape the extraction directory.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = os.path.join(tmpdir, "dest")
            outside = os.path.join(tmpdir, "outside")
            os.mkdir(dest_dir)
            os.mkdir(outside)

            members = [
                _directory("image"),
                _symlink("image/x", outside),
                _regular("image/x/evil", b"pwned"),
            ]
            self.assertRaises(ValueError, self._extract, members, dest_dir)
            self.assertEqual(os.listdir(outside), [])

    def test_symlink_escape_to_root(self):
        self._assertRejected(
            [
                _directory("image"),
                _symlink("image/x", "/"),
                _regular("image/x/etc/cron.d/evil"),
            ]
        )

    def test_symlink_escape_relative(self):
        self._assertRejected(
            [
                _directory("image"),
                _symlink("image/x", "../../.."),
                _regular("image/x/evil"),
            ]
        )

    def test_absolute_path(self):
        self._assertRejected([_directory("image"), _regular("/etc/evil")])

    def test_path_traversal(self):
        self._assertRejected([_directory("image"), _regular("image/../../evil")])

    def test_path_traversal_dot_prefix(self):
        self._assertRejected([_directory("image"), _regular("./../evil")])

    def test_duplicate_files(self):
        self._assertRejected(
            [_directory("image"), _regular("image/a"), _regular("image/a")]
        )

    def test_device_file(self):
        tarinfo = tarfile.TarInfo("image/hda")
        tarinfo.type = tarfile.BLKTYPE
        tarinfo.devmajor = 8
        tarinfo.devminor = 0
        self._assertRejected([_directory("image"), (tarinfo, None)])

    def test_hardlink_escape(self):
        tarinfo = tarfile.TarInfo("image/shadow")
        tarinfo.type = tarfile.LNKTYPE
        tarinfo.linkname = "/etc/shadow"
        self._assertRejected([_directory("image"), (tarinfo, None)])

    def test_ordinary_archive(self):
        """
        Absolute symlinks and setuid bits are legitimate in binary
        packages, so they must survive extraction untouched.
        """
        setuid = tarfile.TarInfo("image/usr/bin/su")
        setuid.type = tarfile.REGTYPE
        setuid.mode = 0o4755

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = os.path.join(tmpdir, "dest")
            os.mkdir(dest_dir)
            self._extract(
                [
                    _directory("image"),
                    _directory("image/usr"),
                    _directory("image/usr/bin"),
                    (setuid, b"binary"),
                    _directory("image/usr/lib"),
                    _symlink("image/usr/lib/libfoo.so", "/usr/lib64/libfoo.so.1"),
                ],
                dest_dir,
            )

            su = os.path.join(dest_dir, "usr/bin/su")
            self.assertEqual(stat.S_IMODE(os.stat(su).st_mode), 0o4755)
            self.assertEqual(
                os.readlink(os.path.join(dest_dir, "usr/lib/libfoo.so")),
                "/usr/lib64/libfoo.so.1",
            )
