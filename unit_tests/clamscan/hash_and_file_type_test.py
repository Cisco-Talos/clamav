# Copyright (C) 2020-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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

        # Testing with our logo png file.
        TC.testfiles = TC.path_source / 'logo.png'

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    #
    # First check with the good database in all-match mode.
    #

    def test_log_hash(self):
        self.step_name('Test that the --log-hash option adds the FileHash output.')

        (TC.path_tmp / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
        )

        #
        # First try with --log-hash enabled to verify that the output is as expected.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            r'logo.png FileHash: f083e9c704165003f8c065964e4ccb47da48bbad8a80521d571cbf0f1d4762c6 \(sha2-256\)',
        ]
        unexpected_stdout = []
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Then try without --log-hash enabled to verify that the output is as expected.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = []
        unexpected_stdout = [
            'FileHash:',
            r'\(sha2-256\)',
            r'\(sha1\)',
            r'\(md5\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Now add the --hash-alg option to verify that the output is as expected.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-alg sha1'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            r'logo.png FileHash: da5b226552d19b5c1c3277d28a776162e568222c \(sha1\)',
        ]
        unexpected_stdout = []
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)


    def test_hash_hint(self):
        self.step_name('Test that the --hash-hint option can be used to supply the file hash.')

        (TC.path_tmp / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
        )

        #
        # Use --hash-hint to feed clamscan a different hash for the test file.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-hint 0000000000000000000000000000000000000000000000000000000000000123'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            r'logo.png FileHash: 0000000000000000000000000000000000000000000000000000000000000123 \(sha2-256\)',
        ]
        unexpected_stdout = [
            r'logo.png FileHash: f083e9c704165003f8c065964e4ccb47da48bbad8a80521d571cbf0f1d4762c6 \(sha2-256\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Combine this with --hash-alg to change a different hash algorithm.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-alg sha1 --hash-hint 0000000000000000000000000000000000000123'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            r'logo.png FileHash: 0000000000000000000000000000000000000123 \(sha1\)',
        ]
        unexpected_stdout = [
            r'logo.png FileHash: f083e9c704165003f8c065964e4ccb47da48bbad8a80521d571cbf0f1d4762c6 \(sha2-256\)',
            r'logo.png FileHash: da5b226552d19b5c1c3277d28a776162e568222c \(sha1\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Verify that feeding it a smaller hash than expected fails gracefully.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-hint 012345'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # error

        expected_stdout = [
            'Invalid argument passed to function ERROR',
        ]
        unexpected_stdout = [
            r'logo.png FileHash: 012345 \(sha2-256\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Verify that feeding it a bigger hash than expected fails gracefully.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-hash --hash-hint 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 2  # error

        expected_stdout = [
            'Invalid argument passed to function ERROR',
        ]
        unexpected_stdout = [
            r'logo.png FileHash: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345 \(sha2-256\)',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)


    def test_file_type_hint(self):
        self.step_name('Test that the --file-type-hint option can be used to supply the file type.')

        (TC.path_tmp / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
        )

        #
        # Don't provide a hint. Just use --log-file-type and verify that clamav gives the correct file type.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-file-type'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        unexpected_stdout = []
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Don't use the new options. Verify that it does not output the file type.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = []
        unexpected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Use --file-type-hint to feed clamscan a different file type for the test file.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-file-type --file-type-hint JPEG'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            'logo.png FileType: CL_TYPE_JPEG',
        ]
        unexpected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Use --file-type-hint to feed clamscan the real file type for the test file.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-file-type --file-type-hint png'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        expected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        unexpected_stdout = []
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)

        #
        # Verify that feeding it an unknown file type properly ignores the hint and determines the file type itself.
        #
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfiles} --log-file-type --file-type-hint faketype'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'good.ldb',
            testfiles=TC.testfiles,
        )
        output = self.execute_command(command)

        assert output.ec == 1  # virus

        expected_stdout = [
            'logo.png FileType: CL_TYPE_PNG',
        ]
        unexpected_stdout = [
            'logo.png FileType: faketype',
        ]
        self.verify_output(output.out, expected=expected_stdout, unexpected=unexpected_stdout)


    def test_html_file_type_tag_signatures_require_tag_boundary(self):
        self.step_name('Test that HTML file type tag signatures require a tag boundary.')

        (TC.path_tmp / 'good.ldb').write_text(
            "logo.png.good;Engine:150-255,Target:0;0;fuzzy_img#af2ad01ed42993c7#0\n"
        )

        def check_file_type(filename, contents, expected_type, unexpected_types=None):
            if unexpected_types is None:
                unexpected_types = []

            testfile = TC.path_tmp / filename
            testfile.write_bytes(contents)

            command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile} --log-file-type'.format(
                valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
                path_db=TC.path_tmp / 'good.ldb',
                testfile=testfile,
            )
            output = self.execute_command(command)

            assert output.ec == 0  # clean

            self.verify_output(
                output.out,
                expected=[
                    '{}: OK'.format(filename),
                    '{} FileType: {}'.format(filename, expected_type),
                ],
                unexpected=[
                    '{} FileType: {}'.format(filename, file_type)
                    for file_type in unexpected_types
                ]
            )

        non_html_xml_files = {
            'iframe_prefix.xml': b'<?xml version="1.0"?><root><iframeView/></root>',
            'iframe_upper_prefix.xml': b'<?xml version="1.0"?><root><IFRAMEVIEW/></root>',
            'img_prefix.xml': b'<?xml version="1.0"?><root><imgData/></root>',
            'img_mixed_prefix.xml': b'<?xml version="1.0"?><root><ImgData/></root>',
            'img_upper_prefix.xml': b'<?xml version="1.0"?><root><IMGDATA/></root>',
            'object_prefix.xml': b'<?xml version="1.0"?><root><objectId/></root>',
            'object_mixed_prefix.xml': b'<?xml version="1.0"?><root><ObjectId/></root>',
            'object_upper_prefix.xml': b'<?xml version="1.0"?><root><OBJECTID/></root>',
            'script_prefix.xml': b'<?xml version="1.0"?><root><scriptlet/></root>',
            'script_mixed_prefix.xml': b'<?xml version="1.0"?><root><Scriptlet/></root>',
            'script_upper_prefix.xml': b'<?xml version="1.0"?><root><SCRIPTLET/></root>',
            'table_styles.xml': (
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b'<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                b'<dxfs count="0"/><tableStyles count="0" defaultTableStyle="TableStyleMedium2"/>'
                b'</styleSheet>'
            ),
            'table_upper_prefix.xml': b'<?xml version="1.0"?><root><TABLESTYLES/></root>',
        }

        for filename, contents in non_html_xml_files.items():
            check_file_type(filename, contents, 'CL_TYPE_TEXT_ASCII', ['CL_TYPE_HTML'])

        html_tag_files = {
            'iframe_close.html': b'<iframe></iframe>',
            'iframe_space.html': b'<iframe src="sample"></iframe>',
            'iframe_slash.html': b'<iframe/>',
            'iframe_uppercase.html': b'<IFRAME></IFRAME>',
            'img_close.html': b'<img>sample',
            'img_space.html': b'<img src="sample">',
            'img_slash.html': b'<img/>',
            'img_mixedcase.html': b'<Img>sample',
            'img_uppercase.html': b'<IMG>sample',
            'object_close.html': b'<object></object>',
            'object_space.html': b'<object data="sample"></object>',
            'object_slash.html': b'<object/>',
            'object_mixedcase.html': b'<Object></Object>',
            'object_uppercase.html': b'<OBJECT></OBJECT>',
            'script_close.html': b'<script></script>',
            'script_space.html': b'<script type="text/javascript"></script>',
            'script_slash.html': b'<script/>',
            'script_mixedcase.html': b'<Script></Script>',
            'script_uppercase.html': b'<SCRIPT></SCRIPT>',
            'table_close.html': b'<table></table>',
            'table_space.html': b'<table class="sample"></table>',
            'table_tab.html': b'<table\tclass="sample"></table>',
            'table_lf.html': b'<table\nclass="sample"></table>',
            'table_vtab.html': b'<table\vclass="sample"></table>',
            'table_ff.html': b'<table\fclass="sample"></table>',
            'table_cr.html': b'<table\rclass="sample"></table>',
            'table_slash.html': b'<table/>',
            'table_uppercase.html': b'<TABLE></TABLE>',
        }

        for filename, contents in html_tag_files.items():
            check_file_type(filename, contents, 'CL_TYPE_HTML')
