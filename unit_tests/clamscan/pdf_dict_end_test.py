# Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan tests.

Embedded file streams whose dictionary holds a nested dictionary with a hex
string before /Filter, e.g.

    << /Params << /CheckSum <hex> /Size N >> /Type /EmbeddedFile /Filter /FlateDecode >>

(the layout qpdf and pikepdf write for attachments) must still be decoded
before scanning. See https://github.com/Cisco-Talos/clamav/issues/1773

Names inside literal strings and comments are not part of the dictionary, so
a fake /Filter there must not be applied to an unfiltered stream.
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

# Valid ASCIIHex text, so a fake /ASCIIHexDecode would decode it successfully
# and only the decoded bytes would be scanned.
RAW_PAYLOAD = b'436c616d4156207261772073747265616d207061796c6f6164'
RAW_SIG_NAME = 'Clamav.Test.PDF.RawStream'


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
        # The extracted raw stream keeps the end-of-line before "endstream".
        raw_extracted = RAW_PAYLOAD + b'\n'
        (TC.path_tmp / 'pdf-embedded.hdb').write_text(
            '{}:{}:{}\n'.format(md5, len(PAYLOAD), SIG_NAME) +
            '{}:{}:{}\n'.format(hashlib.md5(raw_extracted).hexdigest(), len(raw_extracted), RAW_SIG_NAME)
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
            # A comment right after a name ('%' ends the name), with a '(' inside it.
            'name-comment.pdf':
                b'/A%(\n/Type /EmbeddedFile /Length ' + length + b' /Filter /FlateDecode',
            # Form feed (PDF whitespace) between /Filter and its value.
            'filter-formfeed.pdf':
                b'/Type /EmbeddedFile /Length ' + length + b' /Filter\x0c/FlateDecode',
            # Literal string that is never closed: the names after it are still read.
            'unterminated-literal.pdf':
                b'/Desc (abc /Type /EmbeddedFile /Length ' + length + b' /Filter /FlateDecode',
        }
        for name, stream_dict in cases.items():
            (TC.path_tmp / name).write_bytes(build_pdf(stream_dict, compressed))

        raw_length = str(len(RAW_PAYLOAD)).encode()
        raw_cases = {
            # Control: unfiltered stream, scanned as is.
            'raw-control.pdf':
                b'/Type /EmbeddedFile /Length ' + raw_length,
            # Fake /Filter inside a literal string.
            'raw-literal-filter.pdf':
                b'/Desc (x /Filter /ASCIIHexDecode ) /Type /EmbeddedFile /Length ' + raw_length,
            # Fake /Filter inside a literal string, after a ">>" in the same string.
            'raw-literal-close-filter.pdf':
                b'/Desc (x >> /Filter /ASCIIHexDecode ) /Type /EmbeddedFile /Length ' + raw_length,
            # Fake /Filter inside a comment.
            'raw-comment-filter.pdf':
                b'/Type /EmbeddedFile % /Filter /ASCIIHexDecode\n/Length ' + raw_length,
        }
        for name, stream_dict in raw_cases.items():
            (TC.path_tmp / name).write_bytes(build_pdf(stream_dict, RAW_PAYLOAD))

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def _scan(self, filename, sig_name=SIG_NAME):
        command = '{valgrind} {valgrind_args} {clamscan} -d {path_db} {testfile}'.format(
            valgrind=TC.valgrind, valgrind_args=TC.valgrind_args, clamscan=TC.clamscan,
            path_db=TC.path_tmp / 'pdf-embedded.hdb',
            testfile=TC.path_tmp / filename,
        )
        output = self.execute_command(command)
        assert output.ec == 1  # virus found
        self.verify_output(output.out, expected=['{}: {}.UNOFFICIAL FOUND'.format(filename, sig_name)])

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

    def test_pdf_embedded_name_comment(self):
        self.step_name('A comment right after a name does not hide the names that follow')
        self._scan('name-comment.pdf')

    def test_pdf_embedded_filter_formfeed(self):
        self.step_name('A form feed after /Filter is whitespace')
        self._scan('filter-formfeed.pdf')

    def test_pdf_embedded_unterminated_literal(self):
        self.step_name('An unterminated literal string does not hide the names that follow')
        self._scan('unterminated-literal.pdf')

    def test_pdf_raw_control(self):
        self.step_name('Unfiltered embedded file stream is scanned as is')
        self._scan('raw-control.pdf', RAW_SIG_NAME)

    def test_pdf_raw_literal_filter(self):
        self.step_name('A /Filter name inside a literal string is not applied')
        self._scan('raw-literal-filter.pdf', RAW_SIG_NAME)

    def test_pdf_raw_literal_close_filter(self):
        self.step_name('A /Filter name after ">>" inside a literal string is not applied')
        self._scan('raw-literal-close-filter.pdf', RAW_SIG_NAME)

    def test_pdf_raw_comment_filter(self):
        self.step_name('A /Filter name inside a comment is not applied')
        self._scan('raw-comment-filter.pdf', RAW_SIG_NAME)
