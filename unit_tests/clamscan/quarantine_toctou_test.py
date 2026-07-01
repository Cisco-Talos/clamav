# Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""Regression test for quarantine destination TOCTOU handling."""

import errno
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import threading
import time
import unittest

sys.path.append('../unit_tests')
import testcase


operating_system = platform.platform().split('-')[0].lower()


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

    @staticmethod
    def _write_hdb_signature(sig_path: Path, payload: bytes, signature_name: str):
        sig_path.write_text(
            '{}:{}:{}\n'.format(
                hashlib.sha256(payload).hexdigest(),
                len(payload),
                signature_name,
            )
        )

    @staticmethod
    def _write_padding_hdb(sig_path: Path, count: int):
        with sig_path.open('w') as handle:
            for i in range(count):
                pad = 'padding-entry-{:05d}'.format(i).encode('utf-8')
                handle.write(
                    '{}:{}:Padding-{:05d}\n'.format(
                        hashlib.sha256(pad).hexdigest(),
                        len(pad),
                        i,
                    )
                )

    @staticmethod
    def _watch_debug_output(stream, milestone_lines, matched_event, collected_lines):
        try:
            for line in iter(stream.readline, ''):
                collected_lines.append(line)
                if not matched_event.is_set():
                    for milestone in milestone_lines:
                        if milestone in line:
                            matched_event.set()
                            break
        finally:
            stream.close()

    @staticmethod
    def _quarantine_lock_exists(quarantine_dir: Path):
        try:
            return any(entry.name.startswith('.clamav-quarantine-lock.') for entry in quarantine_dir.iterdir())
        except FileNotFoundError:
            return False
        except NotADirectoryError:
            return False

    @staticmethod
    def _can_create_directory_symlink(parent_dir: Path):
        target = parent_dir / 'symlink-target'
        link = parent_dir / 'symlink-link'

        target.mkdir()
        try:
            TC._create_directory_redirect(link, target)
        except OSError:
            return False
        else:
            TC._remove_directory_redirect(link)
            return True
        finally:
            target.rmdir()

    @staticmethod
    def _create_directory_redirect(link_path: Path, target_path: Path):
        try:
            os.symlink(target_path, link_path, target_is_directory=True)
            return
        except OSError:
            if operating_system != 'windows':
                raise

        completed = subprocess.run(
            ['cmd', '/c', 'mklink', '/J', str(link_path), str(target_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        if completed.returncode != 0:
            raise OSError('Failed to create directory redirect: {}'.format(completed.stdout.strip()))

    @staticmethod
    def _remove_directory_redirect(link_path: Path):
        if not link_path.exists():
            return

        if operating_system == 'windows' and not link_path.is_symlink():
            subprocess.run(
                ['cmd', '/c', 'rmdir', str(link_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                check=False,
            )
            return

        link_path.unlink()

    @staticmethod
    def _can_create_file_symlink(parent_dir: Path):
        target = parent_dir / 'symlink-file-target'
        link = parent_dir / 'symlink-file-link'

        target.write_bytes(b'CLAM-2976 file symlink probe\n')
        try:
            TC._create_file_redirect(link, target)
        except OSError:
            return False
        else:
            link.unlink()
            return True
        finally:
            if target.exists():
                target.unlink()

    @staticmethod
    def _create_file_redirect(link_path: Path, target_path: Path):
        try:
            os.symlink(target_path, link_path)
            return
        except OSError:
            if operating_system != 'windows':
                raise

        completed = subprocess.run(
            ['cmd', '/c', 'mklink', str(link_path), str(target_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        if completed.returncode != 0:
            raise OSError('Failed to create file redirect: {}'.format(completed.stdout.strip()))

    @staticmethod
    def _write_xattr(file_path: Path, attr_name: str, attr_value: str):
        subprocess.run(
            ['xattr', '-w', attr_name, attr_value, str(file_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=True,
        )

    @staticmethod
    def _read_xattr(file_path: Path, attr_name: str):
        completed = subprocess.run(
            ['xattr', '-p', attr_name, str(file_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=True,
        )
        return completed.stdout.rstrip('\n')

    def _exercise_quarantine_directory_replacement(self, action_mode: str):
        assert action_mode in ('copy', 'move')

        db_dir = TC.path_tmp / ('db-{}'.format(action_mode))
        db_dir.mkdir()

        payload = b'CLAM-2959 quarantine TOCTOU payload\n'
        scan_dir = TC.path_tmp / ('scanme-{}'.format(action_mode))
        scan_dir.mkdir()
        payload_path = scan_dir / 'backdoor'
        payload_path.write_bytes(payload)

        self._write_hdb_signature(db_dir / 'trigger.hdb', payload, 'CLAM-2959-TOCTOU')
        # Pad the database a bit so we have a more reliable window to replace the
        # quarantine directory after argument setup but before the copy/move action.
        self._write_padding_hdb(db_dir / 'padding.hdb', 500000)

        parent_dir = TC.path_tmp / ('srv-{}'.format(action_mode))
        parent_dir.mkdir()
        if not self._can_create_directory_symlink(parent_dir):
            self.skipTest('Directory symlink creation is not permitted in this test environment.')
        quarantine_dir = parent_dir / 'quarantine'
        quarantine_dir.mkdir()

        redirect_dir = TC.path_tmp / ('redirect-{}'.format(action_mode))
        redirect_dir.mkdir()

        command = []
        if str(TC.valgrind):
            command.append(str(TC.valgrind))
            if TC.valgrind_args:
                command.extend(TC.valgrind_args.split())
        command.extend(
            [
                str(TC.clamscan),
                '--debug',
                '-d',
                str(db_dir),
                '--{}={}'.format(action_mode, quarantine_dir),
                str(scan_dir),
            ]
        )

        milestone_lines = ['{} loaded'.format(db_dir / 'trigger.hdb')]
        if operating_system == 'windows':
            milestone_lines.append('{} loaded'.format(str(db_dir / 'trigger.hdb')).replace('/', '\\'))

        self.log.info('Starting clamscan command: %s', ' '.join(command))
        proc = subprocess.Popen(
            command,
            cwd=str(TC.path_tmp),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            preexec_fn=os.setsid if operating_system != 'windows' else None,
        )
        output_lines = []
        saw_db_load_event = threading.Event()
        output_thread = threading.Thread(
            target=self._watch_debug_output,
            args=(proc.stdout, milestone_lines, saw_db_load_event, output_lines),
            daemon=True,
        )
        output_thread.start()

        try:
            swapped = False
            replacement_blocked = False
            saw_setup_event = False
            deadline = time.time() + 10

            while time.time() < deadline and proc.poll() is None:
                if operating_system == 'windows':
                    saw_setup_event = saw_db_load_event.is_set()
                else:
                    # POSIX action setup creates this lock in the validated
                    # destination. Watching the filesystem avoids depending on
                    # debug stdout timing, which is fragile under Valgrind.
                    saw_setup_event = self._quarantine_lock_exists(quarantine_dir)

                if not saw_setup_event:
                    time.sleep(0.01)
                    continue

                try:
                    quarantine_dir.rmdir()
                    self._create_directory_redirect(quarantine_dir, redirect_dir)
                    swapped = True
                    self.log.info('Replaced quarantine directory with symlink to %s', redirect_dir)
                    break
                except FileNotFoundError:
                    pass
                except OSError as err:
                    if err.errno == errno.ENOTEMPTY:
                        replacement_blocked = True
                        self.log.info('Quarantine directory replacement was blocked while clamscan was running.')
                        break
                    time.sleep(0.01)

            proc.wait(timeout=60)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)
            output_thread.join(timeout=10)

        stdout = ''.join(output_lines)
        self.log.info('clamscan stdout:\n%s', stdout)

        return {
            'payload_path': payload_path,
            'quarantine_dir': quarantine_dir,
            'redirect_dir': redirect_dir,
            'saw_setup_event': saw_setup_event,
            'saw_db_load_event': saw_db_load_event,
            'swapped': swapped,
            'replacement_blocked': replacement_blocked,
            'returncode': proc.returncode,
            'stdout': stdout,
        }

    def _exercise_source_link_quarantine(self, action_mode: str):
        assert action_mode in ('copy', 'move', 'remove')

        parent_dir = TC.path_tmp / ('src-link-{}'.format(action_mode))
        parent_dir.mkdir()
        if not self._can_create_file_symlink(parent_dir):
            self.skipTest('File symlink creation is not permitted in this test environment.')

        db_dir = TC.path_tmp / ('db-src-link-{}'.format(action_mode))
        db_dir.mkdir()

        payload = b'CLAM-2976 quarantine source link payload\n'
        payload_path = parent_dir / 'payload.bin'
        payload_path.write_bytes(payload)

        link_path = parent_dir / 'payload-link'
        self._create_file_redirect(link_path, payload_path)

        self._write_hdb_signature(db_dir / 'trigger.hdb', payload, 'CLAM-2976-SOURCE-LINK')

        quarantine_dir = None
        command = []
        if str(TC.valgrind):
            command.append(str(TC.valgrind))
            if TC.valgrind_args:
                command.extend(TC.valgrind_args.split())
        command.extend(
            [
                str(TC.clamscan),
                '--debug',
                '--follow-file-symlinks=2',
                '-d',
                str(db_dir),
            ]
        )

        if action_mode == 'remove':
            command.append('--remove=yes')
        else:
            quarantine_dir = TC.path_tmp / ('quarantine-src-link-{}'.format(action_mode))
            quarantine_dir.mkdir()
            command.append('--{}={}'.format(action_mode, quarantine_dir))

        command.append(str(link_path))

        self.log.info('Starting clamscan command: %s', ' '.join(command))
        completed = subprocess.run(
            command,
            cwd=str(TC.path_tmp),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        self.log.info('clamscan stdout:\n%s', completed.stdout)

        return {
            'payload_path': payload_path,
            'link_path': link_path,
            'quarantine_dir': quarantine_dir,
            'returncode': completed.returncode,
            'stdout': completed.stdout,
        }

    def _exercise_source_link_replacement_quarantine(self, action_mode: str, attempt: int):
        assert action_mode in ('copy', 'move', 'remove')

        parent_dir = TC.path_tmp / ('src-replace-{}-{}'.format(action_mode, attempt))
        parent_dir.mkdir()
        if not self._can_create_file_symlink(parent_dir):
            self.skipTest('File symlink creation is not permitted in this test environment.')

        db_dir = TC.path_tmp / ('db-src-replace-{}-{}'.format(action_mode, attempt))
        db_dir.mkdir()

        payload = b'CLAM-2959 quarantine source replacement payload\n' + (b'A' * (32 * 1024 * 1024))
        payload_path = parent_dir / 'payload.bin'
        payload_path.write_bytes(payload)

        decoy = b'CLAM-2959 quarantine source replacement decoy\n'
        decoy_path = parent_dir / 'decoy.bin'
        decoy_path.write_bytes(decoy)

        link_path = parent_dir / 'payload-link'
        self._create_file_redirect(link_path, payload_path)

        self._write_hdb_signature(db_dir / 'trigger.hdb', payload, 'CLAM-2959-SOURCE-REPLACEMENT')

        quarantine_dir = None
        command = []
        if str(TC.valgrind):
            command.append(str(TC.valgrind))
            if TC.valgrind_args:
                command.extend(TC.valgrind_args.split())
        command.extend(
            [
                str(TC.clamscan),
                '--debug',
                '--follow-file-symlinks=2',
                '-d',
                str(db_dir),
            ]
        )

        if action_mode == 'remove':
            command.append('--remove=yes')
        else:
            quarantine_dir = TC.path_tmp / ('quarantine-src-replace-{}-{}'.format(action_mode, attempt))
            quarantine_dir.mkdir()
            command.append('--{}={}'.format(action_mode, quarantine_dir))

        command.append(str(link_path))

        milestone_lines = [
            'cli_get_filepath_from_filedesc: File path for fd',
            'cli_get_filepath_from_handle: File path for handle',
        ]

        self.log.info('Starting clamscan command: %s', ' '.join(command))
        proc = subprocess.Popen(
            command,
            cwd=str(TC.path_tmp),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            preexec_fn=os.setsid if operating_system != 'windows' else None,
        )
        output_lines = []
        saw_scan_event = threading.Event()
        output_thread = threading.Thread(
            target=self._watch_debug_output,
            args=(proc.stdout, milestone_lines, saw_scan_event, output_lines),
            daemon=True,
        )
        output_thread.start()

        try:
            swapped = False
            deadline = time.time() + 10

            while time.time() < deadline and proc.poll() is None:
                if not saw_scan_event.is_set():
                    time.sleep(0.01)
                    continue

                try:
                    link_path.unlink()
                    self._create_file_redirect(link_path, decoy_path)
                    swapped = True
                    self.log.info('Replaced source symlink with symlink to %s', decoy_path)
                    break
                except FileNotFoundError:
                    pass
                except OSError:
                    time.sleep(0.01)

            proc.wait(timeout=90)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=10)
            output_thread.join(timeout=10)

        stdout = ''.join(output_lines)
        self.log.info('clamscan stdout:\n%s', stdout)

        return {
            'payload': payload,
            'decoy': decoy,
            'payload_path': payload_path,
            'decoy_path': decoy_path,
            'link_path': link_path,
            'quarantine_dir': quarantine_dir,
            'swapped': swapped,
            'returncode': proc.returncode,
            'stdout': stdout,
        }

    def _exercise_source_link_replacement_until_infected(self, action_mode: str):
        result = None
        for attempt in range(6):
            result = self._exercise_source_link_replacement_quarantine(action_mode, attempt)
            if result['swapped'] and result['returncode'] == 1:
                return result

        self.fail(
            'Failed to hit the source replacement race window for clamscan --{}; last return code was {}.'.format(
                action_mode,
                None if result is None else result['returncode'],
            )
        )

    def _exercise_search_only_quarantine_directory(self, action_mode: str):
        assert action_mode in ('copy', 'move')

        db_dir = TC.path_tmp / ('db-search-only-{}'.format(action_mode))
        db_dir.mkdir()

        payload = 'CLAM-2959 search-only quarantine payload {}\n'.format(action_mode).encode('utf-8')
        scan_dir = TC.path_tmp / ('scanme-search-only-{}'.format(action_mode))
        scan_dir.mkdir()
        payload_path = scan_dir / 'backdoor'
        payload_path.write_bytes(payload)

        self._write_hdb_signature(db_dir / 'trigger.hdb', payload, 'CLAM-2959-SEARCH-ONLY-{}'.format(action_mode.upper()))

        quarantine_dir = TC.path_tmp / ('quarantine-search-only-{}'.format(action_mode))
        quarantine_dir.mkdir()

        command = []
        if str(TC.valgrind):
            command.append(str(TC.valgrind))
            if TC.valgrind_args:
                command.extend(TC.valgrind_args.split())
        command.extend(
            [
                str(TC.clamscan),
                '--debug',
                '-d',
                str(db_dir),
                '--{}={}'.format(action_mode, quarantine_dir),
                str(scan_dir),
            ]
        )

        try:
            quarantine_dir.chmod(0o300)
            self.log.info('Starting clamscan command: %s', ' '.join(command))
            completed = subprocess.run(
                command,
                cwd=str(TC.path_tmp),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                check=False,
            )
        finally:
            quarantine_dir.chmod(0o700)

        self.log.info('clamscan stdout:\n%s', completed.stdout)

        return {
            'payload': payload,
            'payload_path': payload_path,
            'quarantine_dir': quarantine_dir,
            'returncode': completed.returncode,
            'stdout': completed.stdout,
        }

    @unittest.skipIf(not hasattr(os, 'symlink'), 'This platform does not support symlink creation in the test environment.')
    def test_quarantine_directory_replacement_does_not_redirect_copy_target(self):
        self.step_name('Test quarantine destination TOCTOU resistance for clamscan --copy')
        result = self._exercise_quarantine_directory_replacement('copy')

        payload_path = result['payload_path']
        quarantine_dir = result['quarantine_dir']
        redirect_dir = result['redirect_dir']
        stdout = result['stdout']

        assert result['saw_setup_event'], 'Failed to observe clamscan setup before attempting the directory replacement.'
        assert (result['swapped'] or result['replacement_blocked']), 'Failed to replace or pin the quarantine directory during the test window.'
        assert result['returncode'] == 1, 'Expected a virus-found exit code from clamscan.'

        redirected_payload = redirect_dir / payload_path.name
        quarantined_payload = quarantine_dir / payload_path.name
        copied_to_line = "{}: copied to '{}'".format(payload_path, quarantine_dir / payload_path.name)
        self.assertFalse(
            redirected_payload.exists(),
            'Quarantine copy was redirected through the replaced directory entry.',
        )
        if copied_to_line in stdout:
            self.assertTrue(
                quarantined_payload.exists(),
                'Expected a reported successful quarantine copy to create the destination file.',
            )
        else:
            self.assertIn(
                "Can't copy file",
                stdout,
                'Expected clamscan to either quarantine successfully or fail safely once the directory entry was replaced.',
            )
            self.assertFalse(
                quarantined_payload.exists(),
                'Expected safe failure to avoid creating a destination file after the directory entry was replaced.',
            )

    @unittest.skipIf(not hasattr(os, 'symlink'), 'This platform does not support symlink creation in the test environment.')
    def test_quarantine_directory_replacement_does_not_redirect_move_target(self):
        self.step_name('Test quarantine destination TOCTOU resistance for clamscan --move')
        result = self._exercise_quarantine_directory_replacement('move')

        payload_path = result['payload_path']
        quarantine_dir = result['quarantine_dir']
        redirect_dir = result['redirect_dir']
        stdout = result['stdout']

        assert result['saw_setup_event'], 'Failed to observe clamscan setup before attempting the directory replacement.'
        assert (result['swapped'] or result['replacement_blocked']), 'Failed to replace or pin the quarantine directory during the test window.'
        assert result['returncode'] == 1, 'Expected a virus-found exit code from clamscan.'

        redirected_payload = redirect_dir / payload_path.name
        quarantined_payload = quarantine_dir / payload_path.name
        moved_to_line = "{}: moved to '{}'".format(payload_path, quarantine_dir / payload_path.name)
        self.assertFalse(
            redirected_payload.exists(),
            'Quarantine move was redirected through the replaced directory entry.',
        )
        if moved_to_line in stdout:
            self.assertFalse(
                payload_path.exists(),
                'Expected clamscan --move to remove the source file after quarantining it.',
            )
            self.assertTrue(
                quarantined_payload.exists(),
                'Expected a reported successful quarantine move to create the destination file.',
            )
        else:
            self.assertIn(
                "Can't move file",
                stdout,
                'Expected clamscan to either quarantine successfully or fail safely once the directory entry was replaced.',
            )
            self.assertTrue(
                payload_path.exists(),
                'Expected safe failure to leave the source file in place when the quarantine destination is unavailable.',
            )
            self.assertFalse(
                quarantined_payload.exists(),
                'Expected safe failure to avoid creating a destination file after the directory entry was replaced.',
            )

    @unittest.skipIf(not hasattr(os, 'symlink'), 'This platform does not support symlink creation in the test environment.')
    def test_quarantine_copy_uses_real_source_path_for_symlink_source(self):
        self.step_name('Test quarantine copy uses the real source path for symlink sources')
        result = self._exercise_source_link_quarantine('copy')

        payload_path = result['payload_path']
        link_path = result['link_path']
        quarantined_path = result['quarantine_dir'] / payload_path.name

        self.assertEqual(1, result['returncode'], 'Expected a virus-found exit code from clamscan.')
        self.assertIn('{}:'.format(link_path), result['stdout'], 'Expected clamscan to report the unresolved source path.')
        self.assertNotIn('{}:'.format(payload_path), result['stdout'], 'Expected clamscan to avoid reporting the resolved target path.')
        self.assertTrue(payload_path.exists(), 'Expected the symlink target to remain in place after the quarantine copy.')
        self.assertTrue(link_path.exists(), 'Expected the symlink source to remain in place after the quarantine copy.')
        self.assertFalse((result['quarantine_dir'] / link_path.name).exists(), 'Expected quarantine copy to avoid naming the destination after the symlink.')
        self.assertTrue(quarantined_path.exists(), 'Expected quarantine copy to use the resolved source basename.')
        self.assertEqual(payload_path.read_bytes(), quarantined_path.read_bytes(), 'Expected the quarantined file to contain the target file bytes.')

    @unittest.skipIf(not hasattr(os, 'symlink'), 'This platform does not support symlink creation in the test environment.')
    def test_quarantine_move_uses_real_source_path_for_symlink_source(self):
        self.step_name('Test quarantine move uses the real source path for symlink sources')
        result = self._exercise_source_link_quarantine('move')

        payload_path = result['payload_path']
        link_path = result['link_path']
        quarantined_path = result['quarantine_dir'] / payload_path.name

        self.assertEqual(1, result['returncode'], 'Expected a virus-found exit code from clamscan.')
        self.assertIn('{}:'.format(link_path), result['stdout'], 'Expected clamscan to report the unresolved source path.')
        self.assertNotIn('{}:'.format(payload_path), result['stdout'], 'Expected clamscan to avoid reporting the resolved target path.')
        self.assertFalse(payload_path.exists(), 'Expected the quarantine move to unlink the resolved target path.')
        self.assertTrue(link_path.is_symlink(), 'Expected the original symlink entry to remain in place after the quarantine move.')
        self.assertTrue(quarantined_path.exists(), 'Expected quarantine move to use the resolved source basename.')

    @unittest.skipIf(not hasattr(os, 'symlink'), 'This platform does not support symlink creation in the test environment.')
    def test_quarantine_remove_uses_real_source_path_for_symlink_source(self):
        self.step_name('Test quarantine remove uses the real source path for symlink sources')
        result = self._exercise_source_link_quarantine('remove')

        payload_path = result['payload_path']
        link_path = result['link_path']

        self.assertEqual(1, result['returncode'], 'Expected a virus-found exit code from clamscan.')
        self.assertIn('{}:'.format(link_path), result['stdout'], 'Expected clamscan to report the unresolved source path.')
        self.assertNotIn('{}:'.format(payload_path), result['stdout'], 'Expected clamscan to avoid reporting the resolved target path.')
        self.assertFalse(payload_path.exists(), 'Expected quarantine removal to unlink the resolved target path.')
        self.assertTrue(link_path.is_symlink(), 'Expected the original symlink entry to remain in place after the quarantine remove.')

    @unittest.skipIf(not hasattr(os, 'symlink'), 'This platform does not support symlink creation in the test environment.')
    def test_quarantine_copy_does_not_act_on_replaced_source_link(self):
        self.step_name('Test quarantine copy stays bound to the opened source object')
        result = self._exercise_source_link_replacement_until_infected('copy')

        payload_path = result['payload_path']
        decoy_path = result['decoy_path']
        link_path = result['link_path']
        quarantined_path = result['quarantine_dir'] / payload_path.name

        self.assertTrue(link_path.is_symlink(), 'Expected the source path to remain a symlink after replacement.')
        self.assertTrue(decoy_path.exists(), 'Expected the replacement decoy to remain in place.')
        self.assertEqual(result['decoy'], decoy_path.read_bytes(), 'Expected quarantine copy not to modify the replacement decoy.')
        self.assertTrue(payload_path.exists(), 'Expected quarantine copy to leave the opened source file in place.')
        self.assertTrue(quarantined_path.exists(), 'Expected quarantine copy to create a copy of the opened source file.')
        self.assertEqual(result['payload'], quarantined_path.read_bytes(), 'Expected the quarantine copy to contain the opened source bytes.')

    @unittest.skipIf(not hasattr(os, 'symlink'), 'This platform does not support symlink creation in the test environment.')
    def test_quarantine_move_does_not_act_on_replaced_source_link(self):
        self.step_name('Test quarantine move stays bound to the opened source object')
        result = self._exercise_source_link_replacement_until_infected('move')

        payload_path = result['payload_path']
        decoy_path = result['decoy_path']
        link_path = result['link_path']
        quarantined_path = result['quarantine_dir'] / payload_path.name

        self.assertTrue(link_path.is_symlink(), 'Expected the source path to remain a symlink after replacement.')
        self.assertTrue(decoy_path.exists(), 'Expected the replacement decoy to remain in place.')
        self.assertEqual(result['decoy'], decoy_path.read_bytes(), 'Expected quarantine move not to modify the replacement decoy.')
        self.assertFalse(payload_path.exists(), 'Expected quarantine move to unlink the opened source file.')
        self.assertTrue(quarantined_path.exists(), 'Expected quarantine move to create a copy of the opened source file.')
        self.assertEqual(result['payload'], quarantined_path.read_bytes(), 'Expected the quarantine move to preserve the opened source bytes.')

    @unittest.skipIf(not hasattr(os, 'symlink'), 'This platform does not support symlink creation in the test environment.')
    def test_quarantine_remove_does_not_act_on_replaced_source_link(self):
        self.step_name('Test quarantine remove stays bound to the opened source object')
        result = self._exercise_source_link_replacement_until_infected('remove')

        payload_path = result['payload_path']
        decoy_path = result['decoy_path']
        link_path = result['link_path']

        self.assertTrue(link_path.is_symlink(), 'Expected the source path to remain a symlink after replacement.')
        self.assertTrue(decoy_path.exists(), 'Expected the replacement decoy to remain in place.')
        self.assertEqual(result['decoy'], decoy_path.read_bytes(), 'Expected quarantine remove not to modify the replacement decoy.')
        self.assertFalse(payload_path.exists(), 'Expected quarantine remove to unlink the opened source file.')

    @unittest.skipIf(operating_system == 'windows', 'This test uses POSIX directory permissions.')
    def test_quarantine_copy_allows_search_only_destination_dir(self):
        self.step_name('Test quarantine copy allows a write/search-only destination directory')
        result = self._exercise_search_only_quarantine_directory('copy')

        payload_path = result['payload_path']
        quarantined_path = result['quarantine_dir'] / payload_path.name

        self.assertEqual(1, result['returncode'], 'Expected a virus-found exit code from clamscan.')
        self.assertTrue(payload_path.exists(), 'Expected quarantine copy to leave the source file in place.')
        self.assertTrue(quarantined_path.exists(), 'Expected quarantine copy to create the destination file.')
        self.assertEqual(result['payload'], quarantined_path.read_bytes(), 'Expected the quarantined copy to contain the source bytes.')

    @unittest.skipIf(operating_system == 'windows', 'This test uses POSIX directory permissions.')
    def test_quarantine_move_allows_search_only_destination_dir(self):
        self.step_name('Test quarantine move allows a write/search-only destination directory')
        result = self._exercise_search_only_quarantine_directory('move')

        payload_path = result['payload_path']
        quarantined_path = result['quarantine_dir'] / payload_path.name

        self.assertEqual(1, result['returncode'], 'Expected a virus-found exit code from clamscan.')
        self.assertFalse(payload_path.exists(), 'Expected quarantine move to unlink the source file.')
        self.assertTrue(quarantined_path.exists(), 'Expected quarantine move to create the destination file.')
        self.assertEqual(result['payload'], quarantined_path.read_bytes(), 'Expected the quarantined copy to contain the source bytes.')

    @unittest.skipUnless(operating_system in ('darwin', 'macos'), 'This test requires macOS copyfile semantics.')
    def test_quarantine_copy_preserves_xattr(self):
        self.step_name('Test quarantine copy preserves macOS xattrs')

        if shutil.which('xattr') is None:
            self.skipTest('The xattr command is not available in this test environment.')

        db_dir = TC.path_tmp / 'db-xattr'
        db_dir.mkdir()

        payload = b'CLAM-2959 quarantine xattr payload\n'
        scan_dir = TC.path_tmp / 'scanme-xattr'
        scan_dir.mkdir()
        payload_path = scan_dir / 'backdoor'
        payload_path.write_bytes(payload)
        self._write_xattr(payload_path, 'com.clamav.test', 'preserve-me')

        self._write_hdb_signature(db_dir / 'trigger.hdb', payload, 'CLAM-2959-XATTR')

        quarantine_dir = TC.path_tmp / 'quarantine-xattr'
        quarantine_dir.mkdir()

        command = []
        if str(TC.valgrind):
            command.append(str(TC.valgrind))
            if TC.valgrind_args:
                command.extend(TC.valgrind_args.split())
        command.extend(
            [
                str(TC.clamscan),
                '--debug',
                '-d',
                str(db_dir),
                '--copy={}'.format(quarantine_dir),
                str(scan_dir),
            ]
        )

        self.log.info('Starting clamscan command: %s', ' '.join(command))
        completed = subprocess.run(
            command,
            cwd=str(TC.path_tmp),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        self.log.info('clamscan stdout:\n%s', completed.stdout)

        quarantined_path = quarantine_dir / payload_path.name
        self.assertEqual(1, completed.returncode, 'Expected a virus-found exit code from clamscan.')
        self.assertTrue(quarantined_path.exists(), 'Expected clamscan to create the quarantined copy.')
        self.assertEqual(
            'preserve-me',
            self._read_xattr(quarantined_path, 'com.clamav.test'),
            'Expected the quarantined copy to preserve the source extended attribute.',
        )
