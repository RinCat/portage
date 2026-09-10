# Copyright 2022-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

import io
from itertools import product
import os
import sys
import tempfile
from unittest.mock import MagicMock, call, patch

from portage.const import BINREPOS_CONF_FILE
from portage.dbapi.bintree import binarytree
from portage.tests import TestCase
from portage.versions import _pkg_str

from _emerge.BinpkgFetcher import BinpkgFetcher


class BinarytreeTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Create a temporary TMPDIR which prevents test
        methods of this class from leaving behind an empty
        /tmp/Packages file if TMPDIR is initially unset.
        """
        cls._orig_tmpdir = os.environ.get("TMPDIR")
        cls._tmpdir = tempfile.TemporaryDirectory()
        os.environ["TMPDIR"] = cls._tmpdir.name

    @classmethod
    def tearDownClass(cls):
        cls._tmpdir.cleanup()
        if cls._orig_tmpdir is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = cls._orig_tmpdir
        del cls._orig_tmpdir, cls._tmpdir

    def test_required_init_params(self):
        with self.assertRaises(TypeError) as cm:
            binarytree()
        self.assertEqual(str(cm.exception), "pkgdir parameter is required")
        with self.assertRaises(TypeError) as cm:
            binarytree(pkgdir=os.getenv("TMPDIR", "/tmp"))
        self.assertEqual(str(cm.exception), "settings parameter is required")

    def test_instance_has_required_attrs(self):
        # Quite smoky test. What would it be a better testing strategy?
        # Not sure yet...
        required_attrs_no_multi_instance = {
            "pkgdir",
            "_multi_instance",
            "dbapi",
            "update_ents",
            "move_slot_ent",
            "populated",
            "tree",
            "_binrepos_conf",
            "_remote_has_index",
            "_remotepkgs",
            "_additional_pkgs",
            "invalids",
            "invalid_paths",
            "settings",
            "_pkg_paths",
            "_populating",
            "_all_directory",
            "_pkgindex_version",
            "_pkgindex_hashes",
            "_pkgindex_file",
            "_pkgindex_keys",
            "_pkgindex_aux_keys",
            "_pkgindex_use_evaluated_keys",
            "_pkgindex_header",
            "_pkgindex_header_keys",
            "_pkgindex_default_pkg_data",
            "_pkgindex_inherited_keys",
            "_pkgindex_default_header_data",
            "_pkgindex_translated_keys",
            "_pkgindex_allowed_pkg_keys",
        }
        no_multi_instance_settings = MagicMock()
        no_multi_instance_settings.features = ""
        no_multi_instance_bt = binarytree(
            pkgdir=os.getenv("TMPDIR", "/tmp"), settings=no_multi_instance_settings
        )
        multi_instance_settings = MagicMock()
        multi_instance_settings.features = "binpkg-multi-instance"
        multi_instance_bt = binarytree(
            pkgdir=os.getenv("TMPDIR", "/tmp"), settings=multi_instance_settings
        )
        for attr in required_attrs_no_multi_instance:
            getattr(no_multi_instance_bt, attr)
            getattr(multi_instance_bt, attr)
        # The next attribute is the difference between multi instance
        # and no multi instance:
        multi_instance_bt._allocate_filename

    @patch("portage.dbapi.bintree.binarytree._populate_local")
    def test_populate_without_updates_repos_nor_getbinspkgs(self, ppopulate_local):
        bt = binarytree(pkgdir=os.getenv("TMPDIR", "/tmp"), settings=MagicMock())
        ppopulate_local.return_value = {}
        bt.populate()
        ppopulate_local.assert_called_once_with(reindex=True, invalid_errors=True)
        self.assertFalse(bt._populating)
        self.assertTrue(bt.populated)

    @patch("portage.dbapi.bintree.binarytree._populate_local")
    def test_populate_calls_twice_populate_local_if_updates(self, ppopulate_local):
        bt = binarytree(pkgdir=os.getenv("TMPDIR", "/tmp"), settings=MagicMock())
        bt.populate()
        self.assertIn(
            call(reindex=True, invalid_errors=True), ppopulate_local.mock_calls
        )
        self.assertIn(call(), ppopulate_local.mock_calls)
        self.assertEqual(ppopulate_local.call_count, 2)

    @patch("portage.dbapi.bintree.binarytree._populate_additional")
    @patch("portage.dbapi.bintree.binarytree._populate_local")
    def test_populate_with_repos(self, ppopulate_local, ppopulate_additional):
        repos = ("one", "two")
        bt = binarytree(pkgdir=os.getenv("TMPDIR", "/tmp"), settings=MagicMock())
        bt.populate(add_repos=repos)
        ppopulate_additional.assert_called_once_with(repos)

    @patch("portage.dbapi.bintree.BinRepoConfigLoader")
    @patch("portage.dbapi.bintree.binarytree._populate_remote")
    @patch("portage.dbapi.bintree.binarytree._populate_local")
    def test_populate_with_getbinpkgs(
        self, ppopulate_local, ppopulate_remote, pBinRepoConfigLoader
    ):
        refresh = "something"
        settings = MagicMock()
        settings.__getitem__.return_value = "/some/path"
        bt = binarytree(pkgdir=os.getenv("TMPDIR", "/tmp"), settings=settings)
        bt.populate(getbinpkgs=True, getbinpkg_refresh=refresh)
        ppopulate_remote.assert_called_once_with(
            getbinpkg_refresh=refresh,
            pretend=False,
            verbose=False,
            getbinpkg_exclude=None,
            getbinpkg_include=None,
        )

    @patch("portage.dbapi.bintree.BinRepoConfigLoader")
    @patch("portage.dbapi.bintree.binarytree._populate_remote")
    @patch("portage.dbapi.bintree.binarytree._populate_local")
    def test_populate_with_getbinpkgs_and_not_BinRepoConfigLoader(
        self, ppopulate_local, ppopulate_remote, pBinRepoConfigLoader
    ):
        refresh = "something"
        settings = MagicMock()
        portage_root = "/some/path"
        settings.__getitem__.return_value = portage_root
        pBinRepoConfigLoader.return_value = None
        conf_file = os.path.join(portage_root, BINREPOS_CONF_FILE)
        bt = binarytree(pkgdir=os.getenv("TMPDIR", "/tmp"), settings=settings)
        out = io.StringIO()
        stderr_orig = sys.stderr
        try:
            sys.stderr = out
            bt.populate(getbinpkgs=True, getbinpkg_refresh=refresh)
        finally:
            sys.stderr = stderr_orig

        ppopulate_remote.assert_not_called()
        self.assertEqual(
            out.getvalue(),
            "!!! binrepos.conf is missing (or PORTAGE_BINHOST is unset), but use is requested.\n",
        )

    @patch("portage.dbapi.bintree.BinRepoConfigLoader")
    @patch("portage.dbapi.bintree.binarytree._populate_remote")
    @patch("portage.dbapi.bintree.binarytree._populate_local")
    def test_default_getbinpkg_refresh_in_populate(
        self, ppopulate_local, ppopulate_remote, pBinRepoConfigLoader
    ):
        """Bug #864259
        This test fixes the bug. It requires that
        ``_emerge.actions.run_action`` calls ``binarytree.populate``
        explicitly with ``getbinpkg_refresh=True``
        """
        settings = MagicMock()
        settings.__getitem__.return_value = "/some/path"
        bt = binarytree(pkgdir=os.getenv("TMPDIR", "/tmp"), settings=settings)
        bt.populate(getbinpkgs=True)
        ppopulate_remote.assert_called_once_with(
            getbinpkg_refresh=False,
            pretend=False,
            verbose=False,
            getbinpkg_exclude=None,
            getbinpkg_include=None,
        )

    @patch("portage.data.secpass", 2)
    @patch("portage.dbapi.bintree.BinRepoConfigLoader")
    @patch("portage.dbapi.bintree.binarytree._run_trust_helper")
    def test_default_getbinpkg_refresh_in_populate_trusthelper(
        self, run_trust_helper, pBinRepoConfigLoader
    ):
        """
        Test for bug #915842.

        Verify that we call the trust helper in non-pretend mode.
        """
        settings = MagicMock()
        settings.features = ["binpkg-request-signature"]
        settings.__getitem__.return_value = "/some/path"

        d = tempfile.TemporaryDirectory()
        try:
            bt = binarytree(pkgdir=d.name, settings=settings)
            bt.populate(getbinpkgs=True, pretend=False)
            run_trust_helper.assert_called_once()
        finally:
            d.cleanup()

    @patch("portage.dbapi.bintree.BinRepoConfigLoader")
    @patch("portage.dbapi.bintree.binarytree._run_trust_helper")
    def test_default_getbinpkg_refresh_in_populate_trusthelper_pretend(
        self, run_trust_helper, pBinRepoConfigLoader
    ):
        """
        Test for bug #915842.

        Verify we do not call the trust helper in pretend mode.
        """
        settings = MagicMock()
        settings.features = ["binpkg-request-signature"]
        settings.__getitem__.return_value = "/some/path"

        d = tempfile.TemporaryDirectory()
        try:
            bt = binarytree(pkgdir=d.name, settings=settings)
            bt.populate(getbinpkgs=True, pretend=True)
            run_trust_helper.assert_not_called()
        finally:
            d.cleanup()

    def test_remote_location_without_build_id(self):
        """
        Test for bug #970606.

        Verify that remote packages use location and PATH even without BUILD_ID,
        independently of the format and layout used for local packages.
        """
        cases = product(("xpak", "gpkg"), (False, True), (None, "4"))
        d = tempfile.TemporaryDirectory()
        try:
            for remote_format, multi_instance, build_id in cases:
                msg = (remote_format, multi_instance, build_id)
                local_format = "gpkg" if remote_format == "xpak" else "xpak"
                settings = MagicMock()
                settings.features = "binpkg-multi-instance" if multi_instance else ""
                settings.get.side_effect = {"BINPKG_FORMAT": local_format}.get
                bt = binarytree(
                    pkgdir=os.path.join(d.name, "packages"), settings=settings
                )
                bt.populated = True
                location = os.path.join(d.name, "remote")
                repoconfig = MagicMock()
                repoconfig.location = location
                suffix = "xpak" if remote_format == "xpak" else "gpkg.tar"
                metadata = {
                    "BUILD_TIME": "1648851237",
                    "PATH": f"dev-libs/A/A-1-4.{suffix}",
                }
                if build_id is not None:
                    metadata["BUILD_ID"] = build_id
                cpv = _pkg_str("dev-libs/A-1", metadata=metadata, repoconfig=repoconfig)
                metadata["CPV"] = cpv
                key = bt.dbapi._instance_key(cpv)
                bt._remotepkgs = {key: metadata}
                bt.dbapi.cpv_inject(cpv)
                expected = os.path.join(location, metadata["PATH"])
                self.assertEqual(
                    bt.getname_build_id(cpv),
                    (expected, None if build_id is None else int(build_id)),
                    msg,
                )
                pkg = MagicMock()
                pkg.cpv = cpv
                pkg.root_config.trees = {"bintree": bt}
                fetcher = BinpkgFetcher(pkg=pkg)
                self.assertEqual(fetcher.pkg_path, expected + ".partial", msg)
                # Extraction calls getname again without any format override.
                self.assertEqual(bt.getname(cpv), fetcher.pkg_allocated_path, msg)

                # An existing local copy must still take precedence.
                bt._pkg_paths[key] = f"dev-libs/A-1.{suffix}"
                self.assertEqual(
                    bt.getname(cpv),
                    os.path.join(bt.pkgdir, bt._pkg_paths[key]),
                    msg,
                )
        finally:
            d.cleanup()
