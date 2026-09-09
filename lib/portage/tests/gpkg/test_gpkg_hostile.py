# Copyright 2026 Gentoo Authors
# Portage Unit Testing Functionality

import io
import os
import stat
import tarfile
import tempfile
from itertools import product
from pathlib import Path
from unittest.mock import patch

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


def _regular(name, content=b"data", *, kind=tarfile.REGTYPE):
    """Build a file member and its contents."""
    tarinfo = tarfile.TarInfo(name)
    tarinfo.type = kind
    tarinfo.mode = 0o644
    return (tarinfo, content)


def _symlink(name, target):
    """Build a symlink with the given target text."""
    tarinfo = tarfile.TarInfo(name)
    tarinfo.type = tarfile.SYMTYPE
    tarinfo.linkname = target
    tarinfo.mode = 0o777
    return (tarinfo, None)


def _hardlink(name, target, *, mode=0o644):
    """Build a hardlink to another archive member."""
    tarinfo = tarfile.TarInfo(name)
    tarinfo.type = tarfile.LNKTYPE
    tarinfo.linkname = target
    tarinfo.mode = mode
    return (tarinfo, None)


def _directory(name):
    """Build a directory member."""
    tarinfo = tarfile.TarInfo(name)
    tarinfo.type = tarfile.DIRTYPE
    tarinfo.mode = 0o755
    return (tarinfo, None)


class test_gpkg_hostile_case(TestCase):
    def _extract(self, members, dest_dir, prefix="image", mode="r"):
        """Extract an in-memory archive using the production extractor."""
        with _make_tar(members) as data:
            with tarfile.open(mode=mode, fileobj=data) as tar:
                tar_safe_extract(tar, prefix).extractall(dest_dir)

    def _assertRejected(self, members):
        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = os.path.join(tmpdir, "dest")
            os.mkdir(dest_dir)
            self.assertRaises(ValueError, self._extract, members, dest_dir)
            self.assertEqual(os.listdir(dest_dir), [])

    def test_symlink_escape(self):
        """
        Reject writing image/link/marker after image/link points outside.
        Cover absolute and relative targets; leave the outside marker unchanged.
        """
        for relative, name in product(
            (False, True), ("image/link/marker", "./image/link/marker")
        ):
            with self.subTest(relative=relative, name=name):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    dest = root / "dest"
                    dest.mkdir()
                    outside = root / "outside"
                    outside.mkdir()
                    marker = outside / "marker"
                    marker.write_bytes(b"original")
                    target = "../../../outside" if relative else str(outside)
                    with self.assertRaisesRegex(ValueError, "Symlink"):
                        self._extract(
                            [
                                _symlink("image/link", target),
                                _regular(name, b"overwritten"),
                            ],
                            dest,
                        )
                    self.assertEqual(marker.read_bytes(), b"original")
                    self.assertEqual(list(dest.iterdir()), [])

    def test_symlink_escape_to_root(self):
        """Reject image/x/etc/cron.d/evil after creating image/x -> /."""
        self._assertRejected(
            [
                _directory("image"),
                _symlink("image/x", "/"),
                _regular("image/x/etc/cron.d/evil"),
            ]
        )

    def test_absolute_path(self):
        """Reject an absolute archive member name, such as /etc/evil."""
        self._assertRejected([_directory("image"), _regular("/etc/evil")])

    def test_path_traversal(self):
        """Reject member names containing '..', including image/.. and ./../evil."""
        for name in (
            "..",
            "image/..",
            "../outside",
            "image/../outside",
            "image/../../evil",
            "./../evil",
        ):
            with self.subTest(name=name):
                self._assertRejected([_directory("image"), _directory(name)])

    def test_duplicate_files(self):
        """Reject two regular file entries with the same name, image/a."""
        self._assertRejected(
            [_directory("image"), _regular("image/a"), _regular("image/a")]
        )

    def test_device_file(self):
        """Reject a block device member named image/hda."""
        tarinfo = tarfile.TarInfo("image/hda")
        tarinfo.type = tarfile.BLKTYPE
        tarinfo.devmajor = 8
        tarinfo.devminor = 0
        self._assertRejected([_directory("image"), (tarinfo, None)])

    def test_hardlink_escape(self):
        """Reject image/shadow hardlinked to /etc/shadow, which is not in the archive."""
        self._assertRejected(
            [_directory("image"), _hardlink("image/shadow", "/etc/shadow")]
        )

    def test_ordinary_archive(self):
        """
        Preserve ordinary files, hardlinks, symlink targets and permission bits.
        Examples: su with mode 06755, su-copy hardlinked to su, and
        libfoo.so -> /usr/lib64/libfoo.so.1, plus relative and dangling links.
        """
        setuid = tarfile.TarInfo("image/usr/bin/su")
        setuid.type = tarfile.REGTYPE
        setuid.mode = 0o6755

        with tempfile.TemporaryDirectory() as tmpdir:
            dest_dir = os.path.join(tmpdir, "dest")
            os.mkdir(dest_dir)
            self._extract(
                [
                    _directory("image"),
                    _directory("image/usr"),
                    _directory("image/usr/bin"),
                    (setuid, b"binary"),
                    _hardlink("image/usr/bin/su-copy", "image/usr/bin/su", mode=0o6755),
                    _directory("image/usr/lib"),
                    _symlink("image/usr/lib/libfoo.so", "/usr/lib64/libfoo.so.1"),
                    _symlink("image/usr/lib/relative", "libfoo.so"),
                    _symlink("image/usr/lib/dangling", "../missing"),
                ],
                dest_dir,
            )

            su = os.path.join(dest_dir, "usr/bin/su")
            self.assertEqual(stat.S_IMODE(os.stat(su).st_mode), 0o6755)
            self.assertTrue(
                os.path.samefile(su, os.path.join(dest_dir, "usr/bin/su-copy"))
            )
            self.assertEqual(
                os.readlink(os.path.join(dest_dir, "usr/lib/libfoo.so")),
                "/usr/lib64/libfoo.so.1",
            )
            for name, target in (("relative", "libfoo.so"), ("dangling", "../missing")):
                self.assertEqual(
                    os.readlink(os.path.join(dest_dir, "usr/lib", name)), target
                )

    def test_outside_parent_with_inside_leaf(self):
        """
        Reject replacing image/link/back when image/link points outside,
        even if outside/back points back to staging/image/inside.
        The test prearranges that outside symlink; it must stay unchanged.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "dest"
            dest.mkdir()
            outside = root / "outside"
            outside.mkdir()
            staging = tempfile.TemporaryDirectory(dir=dest)
            with staging:
                target = os.path.join(staging.name, "image/inside")
                (outside / "back").symlink_to(target)
                with patch(
                    "portage.gpkg.tempfile.TemporaryDirectory", return_value=staging
                ):
                    with self.assertRaisesRegex(ValueError, "Symlink"):
                        self._extract(
                            [
                                _regular("image/inside", b"contents"),
                                _symlink("image/link", str(outside)),
                                _symlink("image/link/back", "replacement"),
                            ],
                            dest,
                        )
                self.assertEqual(os.readlink(outside / "back"), target)
                self.assertEqual(list(dest.iterdir()), [])

    def test_symlink_alias_overwrite(self):
        """
        Reject writing image/./link when image/link points to an outside file.
        Cover './' and '//' aliases, relative targets, and unknown file type Z.
        """
        for name, kind, relative in product(
            ("image/./link", "image//link", "./image/link"),
            (tarfile.REGTYPE, b"Z"),
            (False, True),
        ):
            with self.subTest(name=name, kind=kind, relative=relative):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    dest = root / "dest"
                    dest.mkdir()
                    marker = root / "marker"
                    marker.write_bytes(b"original")
                    target = "../../../marker" if relative else str(marker)
                    with self.assertRaisesRegex(ValueError, "Symlink"):
                        self._extract(
                            [
                                _symlink("image/link", target),
                                _regular(name, b"overwritten", kind=kind),
                            ],
                            dest,
                        )
                    self.assertEqual(marker.read_bytes(), b"original")

    def test_symlink_chain(self):
        """
        Reject writes through a chain of two symlinks.
        image/link points to image/end, which points outside the staging directory.
        Cover writes to image/link/marker and image/./link.
        """
        for parent in (False, True):
            with self.subTest(parent=parent):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    dest = root / "dest"
                    dest.mkdir()
                    outside = root / "outside"
                    outside.mkdir()
                    marker = outside / "marker"
                    marker.write_bytes(b"original")
                    target = str(outside if parent else marker)
                    name = "image/link/marker" if parent else "image/./link"
                    with self.assertRaisesRegex(ValueError, "Symlink"):
                        self._extract(
                            [
                                _symlink("image/end", target),
                                _symlink("image/link", "end"),
                                _regular(name, b"overwritten"),
                            ],
                            dest,
                        )
                    self.assertEqual(marker.read_bytes(), b"original")

    def test_internal_symlink_parent(self):
        """
        Reject image/alias/link when alias -> . but link points outside.
        An internal parent must not hide an outside file target.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "dest"
            dest.mkdir()
            marker = root / "marker"
            marker.write_bytes(b"original")
            with self.assertRaisesRegex(ValueError, "Symlink"):
                self._extract(
                    [
                        _symlink("image/link", str(marker)),
                        _symlink("image/alias", "."),
                        _regular("image/alias/link", b"overwritten"),
                    ],
                    dest,
                )
            self.assertEqual(marker.read_bytes(), b"original")

    def test_contained_symlink_parent(self):
        """
        Allow image/bin -> usr/bin followed by a file at image/bin/tool.
        Also allow bin -> ../usr/bin when its target stays inside staging.
        Cover both streaming and seekable archives.
        """
        for mode, prefix in product(("r|", "r:"), ("image", "")):
            with self.subTest(mode=mode, prefix=prefix):
                with tempfile.TemporaryDirectory() as tmp:
                    dest = Path(tmp)
                    directory = "image/usr/bin" if prefix else "usr/bin"
                    target = "usr/bin" if prefix else "../usr/bin"
                    self._extract(
                        [
                            _directory(directory),
                            _symlink("image/bin", target),
                            _regular("image/bin/tool", b"contents"),
                        ],
                        dest,
                        prefix=prefix,
                        mode=mode,
                    )
                    link = dest / ("bin" if prefix else "image/bin")
                    self.assertEqual(os.readlink(link), target)
                    self.assertEqual((link / "tool").read_bytes(), b"contents")
                    self.assertEqual((dest / "usr/bin/tool").read_bytes(), b"contents")

    def test_contained_symlink_leaf(self):
        """
        Allow writing image/./link when image/link -> file stays inside staging.
        Also allow a hardlink to that symlink and directory metadata via dirlink.
        """
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            self._extract(
                [
                    _regular("image/file", b"original"),
                    _symlink("image/link", "file"),
                    _regular("image/./link", b"updated"),
                    _hardlink("image/hard", "image/link"),
                    _directory("image/dir"),
                    _symlink("image/dirlink", "dir"),
                    _directory("image/./dirlink"),
                ],
                dest,
            )
            self.assertEqual((dest / "file").read_bytes(), b"updated")
            self.assertEqual(os.readlink(dest / "link"), "file")
            self.assertEqual((dest / "hard").read_bytes(), b"updated")
            self.assertEqual(os.readlink(dest / "dirlink"), "dir")
            self.assertEqual(stat.S_IMODE((dest / "dir").stat().st_mode), 0o755)

    def test_relocated_hardlink_symlink_escape(self):
        """
        Reject hardlinking image/deep/link -> ../../marker as image/hard.
        The same target text points inside staging at the source, but outside
        at the new location. Leave the outside file and its metadata unchanged.
        """
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp)
            marker = dest / "marker"
            marker.write_bytes(b"original")
            marker.chmod(0o600)
            os.utime(marker, (1234567890, 1234567890))
            with self.assertRaisesRegex(ValueError, "Symlink"):
                self._extract(
                    [
                        _regular("marker", b"inside staging"),
                        _symlink("image/deep/link", "../../marker"),
                        _hardlink("image/hard", "image/deep/link"),
                    ],
                    dest,
                )
            self.assertEqual(marker.read_bytes(), b"original")
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
            self.assertEqual(marker.stat().st_mtime, 1234567890)

    def test_hardlink_to_symlink(self):
        """
        Reject image/hardlink hardlinked to image/link -> an outside file.
        Finding the source in the archive must not allow changing outside metadata.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "dest"
            dest.mkdir()
            marker = root / "marker"
            marker.write_bytes(b"original")
            marker.chmod(0o600)
            os.utime(marker, (1234567890, 1234567890))
            with self.assertRaisesRegex(ValueError, "Symlink"):
                self._extract(
                    [
                        _symlink("image/link", str(marker)),
                        _hardlink("image/hardlink", "image/link"),
                    ],
                    dest,
                )
            self.assertEqual(marker.read_bytes(), b"original")
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
            self.assertEqual(marker.stat().st_mtime, 1234567890)

    def test_directory_metadata_through_symlink(self):
        """
        Reject a directory entry at image/./link after image/link points outside.
        Leave the outside directory's permissions and timestamp unchanged.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "dest"
            dest.mkdir()
            outside = root / "outside"
            outside.mkdir()
            outside.chmod(0o755)
            os.utime(outside, (1234567890, 1234567890))
            with self.assertRaisesRegex(ValueError, "Symlink"):
                self._extract(
                    [_symlink("image/link", str(outside)), _directory("image/./link")],
                    dest,
                )
            self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)
            self.assertEqual(outside.stat().st_mtime, 1234567890)

    def test_symlink_prefix(self):
        """
        Reject image -> an outside directory before moving extracted entries.
        Cover the metadata prefix too; outside files must remain in place.
        """
        for prefix, mode in product(("image", "metadata"), ("r|", "r:")):
            with self.subTest(prefix=prefix, mode=mode):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    dest = root / "dest"
                    dest.mkdir()
                    outside = root / "outside"
                    outside.mkdir()
                    marker = outside / "marker"
                    marker.write_bytes(b"original")
                    with self.assertRaisesRegex(ValueError, "Symlink"):
                        self._extract(
                            [_symlink(prefix, str(outside))],
                            dest,
                            prefix=prefix,
                            mode=mode,
                        )
                    self.assertEqual(marker.read_bytes(), b"original")
                    self.assertEqual(list(dest.iterdir()), [])

    def test_destination_symlink(self):
        """
        Given dest/entry -> an outside directory, move image/entry into dest.
        A file or symlink replaces the old link; a directory raises OSError.
        Nothing may be moved into the outside directory.
        """
        for kind in (tarfile.REGTYPE, tarfile.SYMTYPE, tarfile.DIRTYPE):
            with self.subTest(kind=kind):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    dest = root / "dest"
                    dest.mkdir()
                    outside = root / "outside"
                    outside.mkdir()
                    (dest / "entry").symlink_to(outside)
                    if kind == tarfile.DIRTYPE:
                        with self.assertRaises(OSError):
                            self._extract([_directory("image/entry")], dest)
                        self.assertEqual(os.readlink(dest / "entry"), str(outside))
                    elif kind == tarfile.SYMTYPE:
                        self._extract([_symlink("image/entry", "new-target")], dest)
                        self.assertEqual(os.readlink(dest / "entry"), "new-target")
                    else:
                        self._extract(
                            [_regular("image/entry", b"contents", kind=kind)], dest
                        )
                        self.assertFalse((dest / "entry").is_symlink())
                        self.assertEqual((dest / "entry").read_bytes(), b"contents")
                    self.assertEqual(list(outside.iterdir()), [])
