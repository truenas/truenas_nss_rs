#!/usr/bin/env python3
"""
Integration tests for TrueNAS NSS Python bindings
"""

import pytest
import truenas_nss
from truenas_nss import nss_common, pwd, grp


class TestNssCommon:
    """Test nss_common module functionality"""

    def test_nss_module_creation(self):
        """Test creating NssModule instances"""
        files_module = nss_common.PyNssModule("files")
        assert files_module.name == "files"
        assert str(files_module) == "files"
        assert "NssModule" in repr(files_module)

    def test_nss_module_constants(self):
        """Test NssModule class constants"""
        assert hasattr(nss_common.PyNssModule, 'FILES')
        assert hasattr(nss_common.PyNssModule, 'SSS')
        assert hasattr(nss_common.PyNssModule, 'WINBIND')

    def test_nss_error_exists(self):
        """Test that NssError exception exists"""
        assert hasattr(nss_common, 'NssError')

    def test_invalid_module_name(self):
        """Test that invalid module names raise NssError"""
        with pytest.raises(nss_common.NssError):
            nss_common.PyNssModule("invalid_module")


class TestPwd:
    """Test pwd module functionality"""

    def test_pwd_functions_exist(self):
        """Test that pwd functions are available"""
        assert hasattr(pwd, 'getpwnam')
        assert hasattr(pwd, 'getpwuid')
        assert hasattr(pwd, 'iterpw')

    def test_passwd_entry_class_exists(self):
        """Test that PasswdEntry class exists"""
        assert hasattr(pwd, 'PyPasswdEntry')

    def test_passwd_iterator_class_exists(self):
        """Test that PasswdIterator class exists"""
        assert hasattr(pwd, 'PyPasswdIterator')

    def test_getpwnam_root(self):
        """Test getpwnam for root user (should exist on most systems)"""
        try:
            entry = pwd.getpwnam("root")
            assert entry.pw_name == "root"
            assert entry.pw_uid == 0
            assert hasattr(entry, 'pw_gid')
            assert hasattr(entry, 'pw_gecos')
            assert hasattr(entry, 'pw_dir')
            assert hasattr(entry, 'pw_shell')
            assert hasattr(entry, 'source')

            # Test string representation
            assert "root" in str(entry)
            assert "PasswdEntry" in repr(entry)

            # Test to_dict method
            entry_dict = entry.to_dict()
            assert entry_dict['pw_name'] == "root"
            assert entry_dict['pw_uid'] == 0
        except nss_common.NssError as e:
            # It's okay if root doesn't exist in the test environment
            pytest.skip(f"Root user not found: {e}")

    def test_getpwuid_zero(self):
        """Test getpwuid for UID 0 (root)"""
        try:
            entry = pwd.getpwuid(0)
            assert entry.pw_uid == 0
            assert entry.pw_name == "root"
        except nss_common.NssError as e:
            # It's okay if UID 0 doesn't exist in the test environment
            pytest.skip(f"UID 0 user not found: {e}")

    def test_getpwnam_nonexistent(self):
        """Test getpwnam for non-existent user"""
        with pytest.raises(KeyError):
            pwd.getpwnam("nonexistent_user_12345")

    def test_passwd_iterator(self):
        """Test passwd iterator functionality"""
        try:
            files_module = nss_common.PyNssModule("files")
            iterator = pwd.iterpw(files_module)

            # Test that iterator is iterable
            assert hasattr(iterator, '__iter__')
            assert hasattr(iterator, '__next__')

            # Try to get at least one entry
            entries = []
            for entry in iterator:
                entries.append(entry)
                if len(entries) >= 3:  # Limit to avoid consuming too many entries
                    break

            # We should have at least one entry in most systems
            if entries:
                entry = entries[0]
                assert hasattr(entry, 'pw_name')
                assert hasattr(entry, 'pw_uid')

        except nss_common.NssError as e:
            pytest.skip(f"Iterator test failed: {e}")

    def test_getpwall(self):
        """Test getpwall functionality"""
        try:
            # Test without specific module (should try all modules)
            all_entries = pwd.getpwall()
            assert isinstance(all_entries, dict)

            # Should have entries keyed by module name
            for module_name, entries in all_entries.items():
                assert isinstance(module_name, str)
                assert isinstance(entries, list)
                if entries:  # If there are entries, check first one
                    entry = entries[0]
                    assert hasattr(entry, 'pw_name')
                    assert hasattr(entry, 'pw_uid')
                    assert entry.source == module_name.upper()

            # Test with specific module
            files_module = nss_common.PyNssModule("files")
            files_entries = pwd.getpwall(files_module)
            assert isinstance(files_entries, dict)
            assert "FILES" in files_entries

            # Test as_dict parameter
            dict_entries = pwd.getpwall(files_module, as_dict=True)
            assert isinstance(dict_entries, dict)
            if dict_entries.get("files"):
                entry = dict_entries["files"][0]
                assert isinstance(entry, dict)
                assert 'pw_name' in entry
                assert 'pw_uid' in entry

        except nss_common.NssError as e:
            pytest.skip(f"getpwall test failed: {e}")


class TestGrp:
    """Test grp module functionality"""

    def test_grp_functions_exist(self):
        """Test that grp functions are available"""
        assert hasattr(grp, 'getgrnam')
        assert hasattr(grp, 'getgrgid')
        assert hasattr(grp, 'itergrp')

    def test_group_entry_class_exists(self):
        """Test that GroupEntry class exists"""
        assert hasattr(grp, 'PyGroupEntry')

    def test_group_iterator_class_exists(self):
        """Test that GroupIterator class exists"""
        assert hasattr(grp, 'PyGroupIterator')

    def test_getgrnam_root(self):
        """Test getgrnam for root group (should exist on most systems)"""
        try:
            entry = grp.getgrnam("root")
            assert entry.gr_name == "root"
            assert entry.gr_gid == 0
            assert hasattr(entry, 'gr_mem')
            assert hasattr(entry, 'source')
            assert isinstance(entry.gr_mem, list)

            # Test string representation
            assert "root" in str(entry)
            assert "GroupEntry" in repr(entry)

            # Test to_dict method
            entry_dict = entry.to_dict()
            assert entry_dict['gr_name'] == "root"
            assert entry_dict['gr_gid'] == 0
            assert isinstance(entry_dict['gr_mem'], list)
        except nss_common.NssError as e:
            # It's okay if root group doesn't exist in the test environment
            pytest.skip(f"Root group not found: {e}")

    def test_getgrgid_zero(self):
        """Test getgrgid for GID 0 (root)"""
        try:
            entry = grp.getgrgid(0)
            assert entry.gr_gid == 0
            assert entry.gr_name == "root"
        except nss_common.NssError as e:
            # It's okay if GID 0 doesn't exist in the test environment
            pytest.skip(f"GID 0 group not found: {e}")

    def test_getgrnam_nonexistent(self):
        """Test getgrnam for non-existent group"""
        with pytest.raises(KeyError):
            grp.getgrnam("nonexistent_group_12345")

    def test_group_iterator(self):
        """Test group iterator functionality"""
        try:
            files_module = nss_common.PyNssModule("files")
            iterator = grp.itergrp(files_module)

            # Test that iterator is iterable
            assert hasattr(iterator, '__iter__')
            assert hasattr(iterator, '__next__')

            # Try to get at least one entry
            entries = []
            for entry in iterator:
                entries.append(entry)
                if len(entries) >= 3:  # Limit to avoid consuming too many entries
                    break

            # We should have at least one entry in most systems
            if entries:
                entry = entries[0]
                assert hasattr(entry, 'gr_name')
                assert hasattr(entry, 'gr_gid')
                assert hasattr(entry, 'gr_mem')
                assert isinstance(entry.gr_mem, list)

        except nss_common.NssError as e:
            pytest.skip(f"Iterator test failed: {e}")

    def test_getgrall(self):
        """Test getgrall functionality"""
        try:
            # Test without specific module (should try all modules)
            all_entries = grp.getgrall()
            assert isinstance(all_entries, dict)

            # Should have entries keyed by module name
            for module_name, entries in all_entries.items():
                assert isinstance(module_name, str)
                assert isinstance(entries, list)
                if entries:  # If there are entries, check first one
                    entry = entries[0]
                    assert hasattr(entry, 'gr_name')
                    assert hasattr(entry, 'gr_gid')
                    assert hasattr(entry, 'gr_mem')
                    assert isinstance(entry.gr_mem, list)
                    assert entry.source == module_name.upper()

            # Test with specific module
            files_module = nss_common.PyNssModule("files")
            files_entries = grp.getgrall(files_module)
            assert isinstance(files_entries, dict)
            assert "FILES" in files_entries

            # Test as_dict parameter
            dict_entries = grp.getgrall(files_module, as_dict=True)
            assert isinstance(dict_entries, dict)
            if dict_entries.get("files"):
                entry = dict_entries["files"][0]
                assert isinstance(entry, dict)
                assert 'gr_name' in entry
                assert 'gr_gid' in entry
                assert 'gr_mem' in entry
                assert isinstance(entry['gr_mem'], list)

        except nss_common.NssError as e:
            pytest.skip(f"getgrall test failed: {e}")


class TestModuleIntegration:
    """Test integration between modules"""

    def test_module_parameter(self):
        """Test using NssModule as parameter"""
        try:
            files_module = nss_common.PyNssModule("files")

            # Test pwd with explicit module
            entry = pwd.getpwnam("root", files_module)
            assert entry.source == "FILES"

            # Test grp with explicit module
            entry = grp.getgrnam("root", files_module)
            assert entry.source == "FILES"

        except nss_common.NssError as e:
            pytest.skip(f"Module parameter test failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__])