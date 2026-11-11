# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.

Embedded file streams whose dictionary holds a nested dictionary with a hex
string before /Filter, e.g.

    << /Params << /CheckSum <hex> /Size N >> /Type /EmbeddedFile /Filter /FlateDecode >>

(the layout qpdf and pikepdf write for attachments) must still be decoded
before scanning. See https://github.com/Cisco-Talos/clamav/issues/1773
"""

import hashlib
import os
import shutil
import sys
import zlib

sys.path.append('../unit_tests')
import testcase


PAYLOAD = b'ClamAV unit test payload for PDF embedded file dictionaries (#1773)\n'
SIG_NAME = 'Clamav.Test.PDF.EmbeddedFile'


def build_pdf(stream_dict: bytes, stream_data: bytes) -> bytes:
    '''Build a minimal PDF with one embedded file whose stream dictionary is `stream_dict`.'''
    objs = [
        b'<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(payload.bin) 4 0 R] >> >> >>',
        b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>',
        b'<< /Type /Filespec /F (payload.bin) /EF << /F 5 0 R >> >>',
        b'<< ' + stream_dict + b' >>\nstream\n' + stream_data + b'\nendstream',
    ]
    out = bytearray(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')
    offsets = []
    for num, obj in enumerate(objs, 1):
        offsets.append(len(out))
        out += b'%d 0 obj\n' % num + obj + b'\nendobj\n'
    xref = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objs) + 1)
    for off in offsets:
        out += b'%010d 00000 n \n' % off
    out += b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(objs) + 1, xref)
    return bytes(out)


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

        md5 = hashlib.md5(PAYLOAD).hexdigest()
        (TC.path_tmp / 'pdf-embedded.hdb').write_text(
            '{}:{}:{}\n'.format(md5, len(PAYLOAD), SIG_NAME)
        )

        compressed = zlib.compress(PAYLOAD)
        checksum = md5.encode()
        length = str(len(compressed)).encode()
        size = str(len(PAYLOAD)).encode()

        cases = {
            # Control: /Filter comes before the nested dictionary.
            'filter-first.pdf':
                b'/Type /EmbeddedFile /Length ' + length + b' /Filter /FlateDecode '
                b'/Params << /CheckSum <' + checksum + b'> /Size ' + size + b' >>',
            # Control: nested dictionary first, but with a literal string.
            'params-literal-first.pdf':
                b'/Params << /CheckSum (' + checksum + b') /Size ' + size + b' >> '
                b'/Type /EmbeddedFile /Length ' + length + b' /Filter /FlateDecode',
            # Issue #1773: nested dictionary with a hex string before /Filter.
            'params-hex-first.pdf':
                b'/Params << /CheckSum <' + checksum + b'> /Size ' + size + b' >> '
                b'/Type /EmbeddedFile /Length ' + length + b' /Filter /FlateDecode',
            # Hex string immediately followed by the closing ">>" of the nested dictionary.
            'params-hex-adjacent-close.pdf':
                b'/Params << /CheckSum <' + checksum + b'>>> '
                b'/Type /EmbeddedFile /Length ' + length + b' /Filter /FlateDecode',
            # ">>" inside a literal string before /Filter.
            'literal-with-close.pdf':
                b'/Desc (a >> b) /Type /EmbeddedFile /Length ' + length + b' /Filter /FlateDecode',
        }
        for name, stream_dict in cases.items():
            (TC.path_tmp / name).write_bytes(build_pdf(stream_dict, compressed))

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def _scan(self, filename):
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'pdf-embedded.hdb',
            testfile=TC.path_tmp / filename,
        )
        output = self.execute_command(command)
        assert output.ec == 1  # virus found
        self.verify_output(output.out, expected=['{}: {}.UNOFFICIAL FOUND'.format(filename, SIG_NAME)])

    def test_pdf_embedded_filter_first(self):
        self.step_name('Embedded file stream with /Filter before the nested dictionary is decoded')
        self._scan('filter-first.pdf')

    def test_pdf_embedded_params_literal_first(self):
        self.step_name('Embedded file stream with a nested dictionary holding a literal string is decoded')
        self._scan('params-literal-first.pdf')

    def test_pdf_embedded_params_hex_first(self):
        self.step_name('Embedded file stream with a nested dictionary holding a hex string is decoded (#1773)')
        self._scan('params-hex-first.pdf')

    def test_pdf_embedded_params_hex_adjacent_close(self):
        self.step_name('Embedded file stream with a hex string adjacent to ">>" is decoded')
        self._scan('params-hex-adjacent-close.pdf')

    def test_pdf_embedded_literal_with_close(self):
        self.step_name('Embedded file stream with ">>" inside a literal string is decoded')
        self._scan('literal-with-close.pdf')
