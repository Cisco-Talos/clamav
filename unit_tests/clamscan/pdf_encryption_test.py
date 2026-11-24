# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.
"""

import sys

sys.path.append('../unit_tests')
import testcase


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def scan_encrypted_pdf(self, filename):
        testfile = TC.path_source / 'unit_tests' / 'input' / 'other_scanfiles' / 'pdf' / filename
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} --heuristic-alerts --alert-encrypted-doc {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_source / 'unit_tests' / 'input' / 'other_sigs' / 'Clamav-Unit-Test-Signature.ndb',
            testfile=testfile,
        )
        return self.execute_command(command)

    #
    # The Encrypt dictionary in these files has /EncryptMetadata twice: once
    # inside /CF/StdCF and once at the top level. The Encrypt dictionary is
    # referenced from an xref stream, not a classic trailer.
    #

    def test_pdf_encrypt_metadata_twice_aes128(self):
        self.step_name('Test permission-only AES-128 (R4) PDF with two /EncryptMetadata keys is decryptable')

        output = self.scan_encrypted_pdf('encrypt-metadata-twice-aes128.pdf')

        assert output.ec == 0  # clean

        self.verify_output(output.out, expected=['OK'], unexpected=['Heuristics.Encrypted.PDF'])

    def test_pdf_encrypt_metadata_twice_aes256(self):
        self.step_name('Test permission-only AES-256 (R6) PDF with two /EncryptMetadata keys is decryptable')

        output = self.scan_encrypted_pdf('encrypt-metadata-twice-aes256.pdf')

        assert output.ec == 0  # clean

        self.verify_output(output.out, expected=['OK'], unexpected=['Heuristics.Encrypted.PDF'])

    def test_pdf_encrypt_metadata_twice_user_password(self):
        self.step_name('Test user-password PDF with two /EncryptMetadata keys is still flagged')

        output = self.scan_encrypted_pdf('encrypt-metadata-twice-user-password.pdf')

        assert output.ec == 1  # virus

        self.verify_output(output.out, expected=['Heuristics.Encrypted.PDF FOUND'])
