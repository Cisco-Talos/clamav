# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run {valgrind} {valgrind_args} {clamscan} --fips-limits tests.
"""

import unittest
import hashlib
from zipfile import ZIP_DEFLATED, ZipFile
import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        TC.test_file = TC.path_tmp / "test_file"
        with TC.test_file.open('wb') as testfile:
            testfile.write(
                b"""<?php
IGNORE_user_abort(asdf) scandir(asdfasdfasf]);
foreach(asdfasfs) strpos(asdfasfsfasf) sdfasdfasdf .php.suspected
aasdfasdfsf explode asdasdfasfsf
rename()
<script>sfasfasf</script>
?>
""")

        TC.normalized_match_sig = TC.path_tmp / "normalized.ndb"
        TC.normalized_match_sig.write_text(r"Malicious.PHP.normalized:0:*:69676e6f72655f757365725f61626f7274286173646629")

        TC.original_hash_fp = TC.path_tmp / "original_hash.fp"
        TC.original_hash_fp.write_text(r"845c4893a8a4c666251300718eec7bdbd1b10011b12a08a90a4ab54879f3b9f9:190:original_hash")

        TC.original_hash_wild_fp = TC.path_tmp / "original_hash.wild.fp"
        TC.original_hash_wild_fp.write_text(r"845c4893a8a4c666251300718eec7bdbd1b10011b12a08a90a4ab54879f3b9f9:*:original_hash.wild:73")

        # The normalized hash is this for now. Changes to clamav normalization logic may require
        # changes to this hash.
        TC.normalized_hash_fp = TC.path_tmp / "normalized_hash.fp"
        TC.normalized_hash_fp.write_text(r"93506a60db8ba890558033e77d2e90274013c6c387e1ae11c542bcd65a8b260e:188:normalized_hash")

        TC.normalized_hash_wild_fp = TC.path_tmp / "normalized_hash.wild.fp"
        TC.normalized_hash_wild_fp.write_text(r"93506a60db8ba890558033e77d2e90274013c6c387e1ae11c542bcd65a8b260e:*:normalized_hash.wild:73")

        TC.normalized_md5_fp = TC.path_tmp / "normalized_md5.fp"
        TC.normalized_md5_fp.write_text(r"0e32a3ab501afb50daedc04764f8dc16:188:normalized_hash")

        TC.normalized_sha1_fp = TC.path_tmp / "normalized_sha1.fp"
        TC.normalized_sha1_fp.write_text(r"df6341adaf8c7cec6daaca281b724fad9f9c412e:188:normalized_hash")

        TC.test_file_zipped = TC.path_tmp / 'test_file.zip'
        with ZipFile(str(TC.test_file_zipped), 'w', ZIP_DEFLATED) as zf:
            # Add truncated PNG file that will alert with  --alert-broken-media
            with (TC.path_source / 'logo.png').open('br') as logo_png:
                zf.writestr('test_file', b"""<?php
IGNORE_user_abort(asdf) scandir(asdfasdfasf]);
foreach(asdfasfs) strpos(asdfasfsfasf) sdfasdfasdf .php.suspected
aasdfasdfsf explode asdasdfasfsf
rename()
<script>sfasfasf</script>
?>
""")

        # Generate hash of the zipped file.
        # Since we generated the zip in python, we don't know the hash in advance.
        hash_sha2_256 = hashlib.sha256()
        with TC.test_file_zipped.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha2_256.update(chunk)
        hash_sha2_256 = hash_sha2_256.hexdigest()

        TC.test_file_zipped_hash_fp = TC.path_tmp / 'test_file.zip.hash.fp'
        TC.test_file_zipped_hash_fp.write_text('{hash}:{size}:test_file.zip'.format(
            hash=hash_sha2_256,
            size=TC.test_file_zipped.stat().st_size))

        TC.test_file_zipped_hash_wild_fp = TC.path_tmp / 'test_file.zip.hash.wild.fp'
        TC.test_file_zipped_hash_wild_fp.write_text('{hash}:*:test_file.zip.wild:73'.format(
            hash=hash_sha2_256))

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_alerts_on_normalized(self):
        """
        This test expects that the normalized pattern match sig without the .fp sig will in fact alert.
        """
        self.step_name("Test file detection with pattern from normalized HTML")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1}".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file,
                db1=TC.normalized_match_sig,
            )
        )
        self.verify_output(output.out, expected=["Malicious.PHP.normalized.UNOFFICIAL FOUND"], unexpected=[])

    def test_alerts_on_zip(self):
        """
        This test expects that the OG sig without the .fp sig will in fact alert.
        """
        self.step_name("Test file detection with pattern from normalized HTML inside a ZIP file")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1}".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file_zipped,
                db1=TC.normalized_match_sig,
            )
        )
        self.verify_output(output.out, expected=["Malicious.PHP.normalized.UNOFFICIAL FOUND"], unexpected=[])

    def test_fp_for_normalized(self):
        """
        This test expects that FP sigs for normalized HTML hashes will work,
        because hashes are now created when an fmap is created and all embedded
        file content to be scanned now gets its own fmap.
        """
        self.step_name("Test file trusted with fixed-size hash of the normalized HTML")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1} -d {db2} ".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file,
                db1=TC.normalized_match_sig,
                db2=TC.normalized_hash_fp,
            )
        )
        self.verify_output(output.out, expected=["OK"], unexpected=[])

    def test_fp_for_normalized_fips_md5(self):
        """
        This test expects that FP sigs for normalized HTML hashes will fail if using md5 with --fips-limits
        This is because --fips-limits will prevent loading md5 and sha1 FP signatures.

        We can't test with --fips-limits disabled beacuse those tests will fail in a fips-enabled environment where
        these limits are forced.
        """
        self.step_name("Test file trusted with fixed-size hash of the normalized HTML")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1} -d {db2} ".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file,
                db1=TC.normalized_match_sig,
                db2=TC.normalized_md5_fp,
            )
        )
        self.verify_output(output.out, expected=["Malicious.PHP.normalized.UNOFFICIAL FOUND"], unexpected=[])

    def test_fp_for_normalized_fips_sha1(self):
        """
        This test expects that FP sigs for normalized HTML hashes will fail if using sha1 with --fips-limits
        This is because --fips-limits will prevent loading md5 and sha1 FP signatures.

        We can't test with --fips-limits disabled beacuse those tests will fail in a fips-enabled environment where
        these limits are forced.
        """
        self.step_name("Test file trusted with fixed-size hash of the normalized HTML")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1} -d {db2} ".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file,
                db1=TC.normalized_match_sig,
                db2=TC.normalized_sha1_fp,
            )
        )
        self.verify_output(output.out, expected=["Malicious.PHP.normalized.UNOFFICIAL FOUND"], unexpected=[])

    def test_fp_for_normalized_wild(self):
        """
        This test expects that wildcard FP sigs for normalized HTML hashes will work,
        because hashes are now created when an fmap is created and all embedded
        file content to be scanned now gets its own fmap.
        """
        self.step_name("Test file trusted with wild-card hash of the normalized HTML")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1} -d {db2} ".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file,
                db1=TC.normalized_match_sig,
                db2=TC.normalized_hash_wild_fp,
            )
        )
        self.verify_output(output.out, expected=["OK"], unexpected=[])

    def test_fp_for_nonnormalized(self):
        """
        This test expects that FP sigs for non-normalized HTML hashes will work,
        because we now check each hash in the fmap recursion list.
        """
        self.step_name("Test file trusted with the original non-normalized fixed-size hash")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1} -d {db2}".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file,
                db1=TC.normalized_match_sig,
                db2=TC.original_hash_fp,
            )
        )
        self.verify_output(output.out, expected=["OK"], unexpected=[])

    def test_fp_for_nonnormalized_wild(self):
        """
        This test expects that FP sigs for non-normalized HTML hashes will work,
        because we now check each hash in the fmap recursion list.
        """
        self.step_name("Test file trusted with the original non-normalized wild-card hash")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1} -d {db2}".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file,
                db1=TC.normalized_match_sig,
                db2=TC.original_hash_wild_fp,
            )
        )
        self.verify_output(output.out, expected=["OK"], unexpected=[])

    def test_fp_for_zipped_file(self):
        """
        This test expects that FP sigs for a zip containing the test file will work.
        """
        self.step_name("Test file trusted with fixed-size hash of zip containing test file")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1} -d {db2}".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file_zipped,
                db1=TC.normalized_match_sig,
                db2=TC.test_file_zipped_hash_fp,
            )
        )
        self.verify_output(output.out, expected=["OK"], unexpected=[])

    def test_fp_for_zipped_file_wild(self):
        """
        This test expects that FP sigs for a zip containing the test file will work.
        """
        self.step_name("Test file trusted with wildcard hash of zip containing test file")

        output = self.execute_command(
            "{valgrind} {valgrind_args} {clamscan} --fips-limits {testfiles} -d {db1} -d {db2}".format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                testfiles=TC.test_file_zipped,
                db1=TC.normalized_match_sig,
                db2=TC.test_file_zipped_hash_wild_fp,
            )
        )
        self.verify_output(output.out, expected=["OK"], unexpected=[])
