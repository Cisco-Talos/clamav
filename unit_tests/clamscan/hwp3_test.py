# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Run clamscan HWP3 tests.
"""

import hashlib
import re
import struct
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
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

    def test_malformed_paragraph_does_not_skip_attachment(self):
        self.step_name('Test malformed HWP3 paragraph does not skip a later attachment')

        payload = b'hwp3-attachment-after-malformed-paragraph'
        testfile = TC.path_tmp / 'malformed-paragraph.hwp'
        path_db = TC.path_tmp / 'hwp3-attachment.hdb'

        hwp3 = bytearray(b'HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05')
        hwp3.extend(bytes(128))  # Document information.
        hwp3.extend(bytes(1008))  # Document summary.
        hwp3.extend(bytes(2 * 7))  # Seven empty font tables.
        hwp3.extend(bytes(2))  # No styles.

        # Long paragraph header with an impossible line count. The parser rejects
        # this before reaching the additional information blocks below.
        hwp3.extend(struct.pack('<BHHB', 0, 1, 0xffff, 0))

        # Additional information block #1: embedded OLE2 data, then terminator.
        hwp3.extend(struct.pack('<II', 2, len(payload)))
        hwp3.extend(payload)
        hwp3.extend(struct.pack('<II', 0, 0))
        testfile.write_bytes(hwp3)

        path_db.write_text(
            '{}:{}:HWP3_RECOVERED_ATTACHMENT\n'.format(
                hashlib.sha256(payload).hexdigest(), len(payload)
            )
        )

        command = (
            '{valgrind} {valgrind_args} {clamscan} --scan-hwp3=yes '
            '-d {path_db} {testfile}'
        ).format(
            valgrind=TC.valgrind,
            valgrind_args=TC.valgrind_args,
            clamscan=TC.clamscan,
            path_db=path_db,
            testfile=testfile,
        )
        output = self.execute_command(command)

        assert output.ec == 1
        self.verify_output(
            output.out,
            expected=[re.escape('HWP3_RECOVERED_ATTACHMENT.UNOFFICIAL FOUND')],
        )
