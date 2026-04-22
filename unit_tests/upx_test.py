#!/usr/bin/env python3
"""
UPX unpacker tests — PE32, PE32+, ELF32, ELF64
"""

import unittest
import testcase
import sys


class TC(testcase.TestCase):

    @classmethod
    def setUpClass(cls):
        import os
        from pathlib import Path
        import shutil

        if os.getenv("UPX_TEST_STANDALONE") == "1":
            print("[standalone mode] injecting test environment")

            repo_root = Path(__file__).resolve().parent.parent

            os.environ["VERSION"] = "dev"
            os.environ["SOURCE"] = str(repo_root)
            os.environ["BUILD"] = str(repo_root / "build")
            os.environ["TMP"] = "/tmp"

            clamscan_path = shutil.which("clamscan")
            if not clamscan_path:
                raise Exception("clamscan not found in PATH")

            os.environ["CLAMSCAN"] = clamscan_path

        # IMPORTANT: must come before using cls.clamscan
        super(TC, cls).setUpClass()

        cls.upx_dir = cls.path_source / "unit_tests" / "input" / "other_scanfiles" / "upx"

        cls.scan_base = (
            f"{cls.valgrind} {cls.valgrind_args} {cls.clamscan} "
            f"-d \"{cls.upx_dir}\" --no-summary"
        )
        
    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_upx_00_pe32(self):
        self.step_name('UPX PE32 (x86) unpack and detect')
        cmd = f"{TC.scan_base} \"{TC.upx_dir}/clam.exe.upx\""
        output = self.execute_command(cmd)
        assert output.ec == 1
        self.verify_output(output.out, expected=['ClamAV.TestFile'])

    def test_upx_01_pe32plus(self):
        self.step_name('UPX PE32+ (x64) unpack and detect')
        cmd = f"{TC.scan_base} \"{TC.upx_dir}/clam64.exe.upx\""
        output = self.execute_command(cmd)
        assert output.ec == 1
        self.verify_output(output.out, expected=['ClamAV.TestFile'])

    def test_upx_02_elf32(self):
        self.step_name('UPX ELF32 (i386) unpack and detect')
        cmd = f"{TC.scan_base} \"{TC.upx_dir}/clam.elf.upx\""
        output = self.execute_command(cmd)
        assert output.ec == 1
        self.verify_output(output.out, expected=['ClamAV.TestFile'])

    def test_upx_03_elf64(self):
        self.step_name('UPX ELF64 (x86-64) unpack and detect')
        cmd = f"{TC.scan_base} \"{TC.upx_dir}/clam64.elf.upx\""
        output = self.execute_command(cmd)
        assert output.ec == 1
        self.verify_output(output.out, expected=['ClamAV.TestFile'])


if __name__ == '__main__':
    import sys

    standalone = False
    if "--standalone" in sys.argv:
        standalone = True
        sys.argv.remove("--standalone")

    # stash it somewhere global the class can read
    import os
    if standalone:
        os.environ["UPX_TEST_STANDALONE"] = "1"

    unittest.main(verbosity=2)
