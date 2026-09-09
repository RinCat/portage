# Copyright Gentoo Foundation 2006-2020
# Portage Unit Testing Functionality

import gzip
import io
import os
import shutil
import tarfile
import tempfile
from itertools import product
from os import urandom
from unittest.mock import patch

from portage.exception import InvalidBinaryPackageFormat
from portage.gpkg import checksum_helper, gpkg
from portage.tests import TestCase
from portage.tests.resolver.ResolverPlayground import ResolverPlayground
from portage.util._compare_files import compare_files


class test_gpkg_metadata_case(TestCase):
    @staticmethod
    def _metadata_package(settings, path, kind):
        """Build an unsigned package with valid checksums and a chosen metadata type."""
        metadata = io.BytesIO()
        with tarfile.open(fileobj=metadata, mode="w") as archive:
            member = tarfile.TarInfo("metadata/EAPI")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"8"))
            member = tarfile.TarInfo("metadata/test")
            member.type = kind
            member.linkname = "EAPI" if member.issym() else "metadata/EAPI"
            data = b"value" if member.isreg() else b""
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))

        files = {"gpkg-1": b"", "metadata.tar.gz": gzip.compress(metadata.getvalue())}
        manifest = []
        for name, data in files.items():
            checksum = checksum_helper(settings)
            checksum.update(data)
            hashes = " ".join(
                f"{name} {digest.hexdigest()}" for name, digest in checksum.libs.items()
            )
            manifest.append(f"DATA {name} {len(data)} {hashes}\n")
        files["Manifest"] = "".join(manifest).encode()
        with tarfile.open(path, "w") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo("test/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def test_metadata_member_types(self):
        """
        Accept regular metadata files; reject links, directories, devices and FIFO.
        For example, reject metadata/test -> EAPI even though EAPI is in the tar.
        Check local reads, URL reads (including unrequested entries), and extraction.
        """
        playground = ResolverPlayground(
            user_config={
                "make.conf": ('FEATURES="-binpkg-signing -binpkg-request-signature"',),
            }
        )
        try:
            kinds = (
                tarfile.REGTYPE,
                tarfile.AREGTYPE,
                tarfile.SYMTYPE,
                tarfile.LNKTYPE,
                tarfile.DIRTYPE,
                tarfile.CHRTYPE,
                tarfile.BLKTYPE,
                tarfile.FIFOTYPE,
                b"Z",
            )
            for kind, mode in product(kinds, ("local", "url", "filtered", "disk")):
                with (
                    self.subTest(kind=kind, mode=mode),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    path = os.path.join(tmp, "test.gpkg.tar")
                    self._metadata_package(playground.settings, path, kind)
                    package = gpkg(playground.settings, "test", path)
                    dest = os.path.join(tmp, "dest")
                    os.mkdir(dest)

                    def read_metadata():
                        if mode == "local":
                            return package.get_metadata()
                        if mode == "disk":
                            return package.unpack_metadata(dest)
                        with open(path, "rb") as archive:
                            data = archive.read()
                        with patch(
                            "portage.gpkg.urlopen",
                            side_effect=lambda *args, **kwargs: io.BytesIO(data),
                        ):
                            return package.get_metadata_url(
                                "https://example.invalid/test.gpkg.tar",
                                want=[] if mode == "filtered" else None,
                            )

                    if kind in (tarfile.REGTYPE, tarfile.AREGTYPE):
                        result = read_metadata()
                        if mode == "disk":
                            with open(os.path.join(dest, "test"), "rb") as extracted:
                                self.assertEqual(extracted.read(), b"value")
                        else:
                            self.assertEqual(
                                result,
                                (
                                    {}
                                    if mode == "filtered"
                                    else {"EAPI": b"8", "test": b"value"}
                                ),
                            )
                    else:
                        with self.assertRaisesRegex(
                            InvalidBinaryPackageFormat,
                            "not a regular file: metadata/test",
                        ):
                            read_metadata()
                        self.assertEqual(os.listdir(dest), [])
        finally:
            playground.cleanup()

    def test_gpkg_update_metadata(self):
        playground = ResolverPlayground(
            user_config={
                "make.conf": ('BINPKG_COMPRESS="gzip"', 'FEATURES="-binpkg-signing"'),
            }
        )
        tmpdir = tempfile.mkdtemp()

        try:
            settings = playground.settings
            orig_full_path = os.path.join(tmpdir, "orig/")
            os.makedirs(orig_full_path)
            with open(os.path.join(orig_full_path, "test"), "wb") as test_file:
                test_file.write(urandom(1048576))

            gpkg_file_loc = os.path.join(tmpdir, "test.gpkg.tar")
            test_gpkg = gpkg(settings, "test", gpkg_file_loc)

            meta = {"test1": b"1234567890", "test2": b"abcdef"}

            test_gpkg.compress(os.path.join(tmpdir, "orig"), meta)

            meta_result = test_gpkg.get_metadata()
            self.assertEqual(meta, meta_result)

            meta_new = {"test3": b"0987654321", "test4": b"XXXXXXXX"}
            test_gpkg.update_metadata(meta_new)

            meta_result = test_gpkg.get_metadata()
            self.assertEqual(meta_new, meta_result)

            test_gpkg.decompress(os.path.join(tmpdir, "test"))
            r = compare_files(
                os.path.join(tmpdir, "orig/" + "test"),
                os.path.join(tmpdir, "test/" + "test"),
                skipped_types=("atime", "mtime", "ctime"),
            )
            self.assertEqual(r, ())
        finally:
            shutil.rmtree(tmpdir)
            playground.cleanup()
