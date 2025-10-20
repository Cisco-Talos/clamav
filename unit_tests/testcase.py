# Copyright (C) 2017-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
Wrapper for unittest to provide ClamAV specific test environment features.
"""

from typing import NamedTuple
import hashlib
import logging
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from typing import Union
import unittest

from pathlib import Path

EXECUTION_TIMEOUT = 600
TIMEOUT_EXIT_CODE = 111

STRICT_ORDER = 0
ANY_ORDER = 1
CHUNK_SIZE = 100

loggers = {}

#TODO: replace w/ this when Python 3.5 support is dropped.
# class CmdResult(NamedTuple):
#     ec: int
#     out: bytes
#     err: bytes

# Use older Python 3.5 syntax.
CmdResult = NamedTuple('CmdResult', [('ec', int), ('out', bytes), ('err', bytes)])

class TestCase(unittest.TestCase):
    """
    This wrapper around unittest.TestCase provides added utilities and environment information.
    """

    version = ""

    path_source = None
    path_build = None
    path_tmp = None

    check_clamav = None
    check_clamd = None
    check_fpu_endian = None
    milter = None
    clambc = None
    clamd = None
    clamdscan = None
    clamdtop = None
    clamscan = None
    clamsubmit = None
    clamconf = None
    clamonacc = None
    freshclam = None
    sigtool = None

    path_sample_config = None

    valgrind = "" # Not 'None' because we'll use this variable even if valgrind not found.
    valgrind_args = ""
    log_suffix = '.log'

    original_working_directory = ""

    @classmethod
    def setUpClass(cls):
        """
        Initialize, to provide logging and test paths.

        Also initializes internal Executor and LogChecker required
        for execute_command(), and verify_log()
        """
        global loggers

        if loggers.get(cls.__name__):
            cls.log = loggers.get(cls.__name__)
        else:
            cls.log = Logger(cls.__name__)
            loggers[cls.__name__] = cls.log

        cls._executor = Executor()
        cls._log_checker = LogChecker()

        os_platform = platform.platform()
        cls.operating_system = os_platform.split("-")[0].lower()

        # Get test paths from environment variables.
        cls.version = os.getenv("VERSION")
        if cls.version == None:
            raise Exception("VERSION environment variable not defined! Aborting...")

        cls.path_source =      Path(os.getenv("SOURCE"))
        cls.path_build =       Path(os.getenv("BUILD"))
        cls.path_tmp =         Path(tempfile.mkdtemp(prefix=(cls.__name__ + "-"), dir=os.getenv("TMP")))
        cls.check_clamav =     Path(os.getenv("CHECK_CLAMAV"))     if os.getenv("CHECK_CLAMAV") != None else None
        cls.check_clamd =      Path(os.getenv("CHECK_CLAMD"))      if os.getenv("CHECK_CLAMD") != None else None
        cls.check_fpu_endian = Path(os.getenv("CHECK_FPU_ENDIAN")) if os.getenv("CHECK_FPU_ENDIAN") != None else None
        cls.milter =           Path(os.getenv("CLAMAV_MILTER"))    if os.getenv("CLAMAV_MILTER") != None else None
        cls.clambc =           Path(os.getenv("CLAMBC"))           if os.getenv("CLAMBC") != None else None
        cls.clamd =            Path(os.getenv("CLAMD"))            if os.getenv("CLAMD") != None else None
        cls.clamdscan =        Path(os.getenv("CLAMDSCAN"))        if os.getenv("CLAMDSCAN") != None else None
        cls.clamdtop =         Path(os.getenv("CLAMDTOP"))         if os.getenv("CLAMDTOP") != None else None
        cls.clamscan =         Path(os.getenv("CLAMSCAN"))         if os.getenv("CLAMSCAN") != None else None
        cls.clamsubmit =       Path(os.getenv("CLAMSUBMIT"))       if os.getenv("CLAMSUBMIT") != None else None
        cls.clamconf =         Path(os.getenv("CLAMCONF"))         if os.getenv("CLAMCONF") != None else None
        cls.clamonacc =        Path(os.getenv("CLAMONACC"))        if os.getenv("CLAMONACC") != None else None
        cls.freshclam =        Path(os.getenv("FRESHCLAM"))        if os.getenv("FRESHCLAM") != None else None
        cls.sigtool =          Path(os.getenv("SIGTOOL"))          if os.getenv("SIGTOOL") != None else None

        if cls.operating_system == "windows":
            cls.path_sample_config = cls.path_source / "win32" / "conf_examples"
        else:
            cls.path_sample_config = cls.path_source / "etc"

        # Check if Valgrind testing is requested
        if os.getenv('VALGRIND') != None:
            cls.log_suffix = '.valgrind.log'
            cls.valgrind = Path(os.getenv("VALGRIND"))
            cls.valgrind_args = '-v --trace-children=yes --track-fds=yes --leak-check=full --show-possibly-lost=no ' + \
                                '--show-leak-kinds=definite --errors-for-leak-kinds=definite --main-stacksize=16777216 --gen-suppressions=all ' + \
                                '--suppressions={} '.format(cls.path_source / "unit_tests" / "valgrind.supp") + \
                                '--log-file={} '.format(cls.path_tmp / "valgrind.log")                        + \
                                '--error-exitcode=123'

        # cls.log.info(f"{cls.__name__} Environment:")
        # cls.log.info(f"  version:           {cls.version}")
        # cls.log.info(f"  path_source:       {cls.path_source}")
        # cls.log.info(f"  path_build:        {cls.path_build}")
        # cls.log.info(f"  path_tmp:          {cls.path_tmp}")
        # cls.log.info(f"  check_clamav:      {cls.check_clamav}")
        # cls.log.info(f"  check_clamd:       {cls.check_clamd}")
        # cls.log.info(f"  check_fpu_endian:  {cls.check_fpu_endian}")
        # cls.log.info(f"  milter:            {cls.milter}")
        # cls.log.info(f"  clambc:            {cls.clambc}")
        # cls.log.info(f"  clamd:             {cls.clamd}")
        # cls.log.info(f"  clamdscan:         {cls.clamdscan}")
        # cls.log.info(f"  clamdtop:          {cls.clamdtop}")
        # cls.log.info(f"  clamscan:          {cls.clamscan}")
        # cls.log.info(f"  clamsubmit:        {cls.clamsubmit}")
        # cls.log.info(f"  clamconf:          {cls.clamconf}")
        # cls.log.info(f"  clamonacc:         {cls.clamonacc}")
        # cls.log.info(f"  freshclam:         {cls.freshclam}")
        # cls.log.info(f"  sigtool:           {cls.sigtool}")
        # cls.log.info(f"  valgrind:          {cls.valgrind}")

        # Perform all tests with cwd set to the cls.path_tmp, created above.
        cls.original_working_directory = os.getcwd()
        os.chdir(str(cls.path_tmp))

    @classmethod
    def tearDownClass(cls):
        """
        Clean up after ourselves,
        Delete the generated tmp directory.
        """
        print("")

        # Restore current working directory before deleting cls.path_tmp.
        os.chdir(cls.original_working_directory)

        if None == os.getenv("KEEPTEMP"):
            try:
                shutil.rmtree(cls.path_tmp)
                cls.log.info("Removed tmp directory: {}".format(cls.path_tmp))
            except Exception:
                cls.log.info("No tmp directory to clean up.")

    def setUp(self):
        print("")

        log_path = Path(self.path_build / 'unit_tests' / '{}{}'.format(self._testMethodName, self.log_suffix))
        try:
            log_path.unlink()
        except Exception:
            pass # missing_ok=True is too for common use.
        self.log = Logger(self._testMethodName, log_file=str(log_path))

    def tearDown(self):
        print("")

    def step_name(self, name):
        """Log name of a step.

        :Parameters:
            - `name`: a string with name of the step to print.
        """
        self.log.info("~" * 72)
        self.log.info(name.center(72, " "))
        self.log.info("~" * 72)

    def execute(self, cmd, cwd=None, **kwargs):
        """Execute command.

        This method composes shell command from passed args and executes it.
        Command template: '[sudo] cmd [options] data'
        Example:
            cmd='cp', data='source_file dest_file', options=['r','f'],
            sudo=True
        Composed result: 'sudo cp -rf source_file dest_file'.

        :Parameters:
            - `cmd`: a string with a shell command to execute.
            - `cwd`: a string with a current working directory to set.

        :Keywords:
            - `data`: args for `cmd`(e.g. filename, dirname,).
            - `options`: options for the shell command.
            - `sudo`: use `sudo`? Default value is False.
            - `timeout`: execution timeout in seconds.
            - `env_vars`: a dictionary with custom environment variables.
            - `interact`: a string to enter to the command stdin during
                          execution.

        :Return:
            - namedtuple(ec, out, err).

        :Exceptions:
            - `AssertionError`: is raised if `options` is not a list.
        """
        executor = Executor(logger=self.log)
        return executor.execute(cmd, cwd=cwd, kwargs=kwargs)

    def verify_output(self, text, expected=[], unexpected=[], order=ANY_ORDER):
        """Method verifies text. Check for expected or unexpected results.

        :Parameters:
            - `text`: text to verify.
            - `expected`: (iterable) expected items to be found.
            - `unexpected`: (iterable) unexpected items to be found.
            - `order`: expected appearance order. Default: any order.
        """
        log_checker = LogChecker(self.log)

        if unexpected:
            log_checker.verify_unexpected_output(unexpected, text)
        if expected:
            log_checker.verify_expected_output(expected, text, order=order)

    def verify_log(
        self, log_file, expected=[], unexpected=[], ignored=[], order=ANY_ORDER
    ):
        """Method verifies log file. Check for expected or unexpected results.

        :Parameters:
            - `log_file`: path to log file.
            - `expected`: (iterable) expected items to be found.
            - `unexpected`: (iterable) unexpected items to be found.
            - `ignored`: (iterable) unexpected items which should be ignored.
            - `order`: expected appearance order. Default: any order.
        """
        log_checker = LogChecker(self.log)

        if unexpected:
            log_checker.verify_unexpected_log(log_file, unexpected=unexpected, ignored=ignored)
        if expected:
            log_checker.verify_expected_log(log_file, expected=expected, order=order)

    def verify_valgrind_log(self, log_file: Union[Path, None]=None):
        """Method verifies a valgrind log file.

        If valgrind not enabled this is basically a nop.

        :Parameters:
            - `log_file`: path to log file.
        """
        if self.valgrind == "":
            return

        if log_file == None:
            log_file = self.path_tmp / 'valgrind.log'

        if not log_file.exists():
            raise AssertionError('{} not found. Valgrind failed to run?'.format(log_file))

        errors = False
        self.log.info('Verifying {}...'.format(log_file))
        try:
            self.verify_log(
                str(log_file),
                expected=['ERROR SUMMARY: 0 errors'],
                unexpected=[],
                ignored=[]
            )
        except AssertionError:
            self.log.warning("*" * 69)
            self.log.warning('Valgrind test failed!'.center(69, ' '))
            self.log.warning('Please submit this log to https://github.com/Cisco-Talos/clamav/issues:'.center(69, ' '))
            self.log.warning(str(log_file).center(69, ' '))
            self.log.warning("*" * 69)
            errors = True
        finally:
            with log_file.open('r') as log:
                found_summary = False
                for line in log.readlines():
                    if 'ERROR SUMMARY' in line:
                        found_summary = True
                    if (found_summary or errors) and len(line) < 500:
                        self.log.info(line.rstrip('\n'))
            if errors:
                raise AssertionError('Valgrind test FAILED!')

    def verify_cmd_result(
        self,
        result,
        exit_code=0,
        stderr_expected=[],
        stderr_unexpected=[],
        stdout_expected=[],
        stdout_unexpected=[],
        order=ANY_ORDER,
    ):
        """Check command result for expected/unexpected stdout/stderr.

        :Parameters:
            - `result`: tuple(ec, out, err).
            - `exit_code`: expected exit code value.
            - `stderr_expected`: (iterable) expected items in stderr.
            - `stderr_unexpected`: (iterable) unexpected items in stderr.
            - `stdout_expected`: (iterable) expected items in stdout.
            - `stdout_unexpected`: (iterable) unexpected items in stdout.
            - `order`: expected appearance order. Default: any order.

        :Exceptions:
            - `AssertionError`: is raised if:
                1) format of `result` is wrong.
                2) actual exit code value doesn't match expected.
        """
        try:
            ec, stdout, stderr = result
        except:
            raise AssertionError("Wrong result format: %s" % (result,))

        assert ec == exit_code, (
            "Code mismatch.\nExpected: %s\nActual: %s\nError: %s"
            % (exit_code, ec, stderr)
        )
        if stderr_expected:
            self.verify_expected_output(
                stderr_expected, stderr, order=order
            )
        if stderr_unexpected:
            self.verify_unexpected_output(stderr_unexpected, stderr)

        if stdout_expected:
            self.verify_expected_output(
                stdout_expected, stdout, order=order
            )
        if stdout_unexpected:
            self.verify_unexpected_output(stdout_unexpected, stdout)

    def _sha2_256(self, filepath):
        """Get sha2-256 hash sum of a given file.

        :Parameters:
            - `filepath`: path to file.

        :Return:
            - hash string

        :Exceptions:
            - `AssertionError`: is raised if `filepath` is not a string
                                or is empty.
        """
        assert isinstance(filepath, str), "Invalid filepath: %s." % (filepath,)
        assert os.path.exists(filepath), "file does not exist: %s." % (filepath,)

        hash_sha2_256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha2_256.update(chunk)
        return hash_sha2_256.hexdigest()

    def get_sha2_256(self, files):
        """Get sha2-256 hash sum of every given file.

        :Parameters:
            - `files`: a list or a tuple of files.

        :Return:
            - dictionary like {file: sha2_256_sum}.

        :Exceptions:
            - `AssertionError`: is raised if `files` is empty.
        """
        assert files, "`files` should not be empty."
        files = files if isinstance(files, (list, tuple)) else [files]
        sha2_256_dict = {}
        for path in files:
            if os.path.isfile(path):
                sha2_256_dict[path] = self._sha2_256(path)
        return sha2_256_dict

    def _pkill(self, process, options=["-9 -f"], sudo=False):
        """Wrapper for CLI *nix `pkill` command.

        *nix only.

        :Parameters:
            - `process`: a string with pattern for process to kill.
            - `options`: options for `pkill` command.
            - `sudo`: use `sudo`? Default value is False.

        :Return:
            - namedtuple(ec, out, err).

        :Exceptions:
            - `AssertionError`: is raised if `process` is empty or is
                                not a string.
        """
        assert self.operating_system != "windows"
        assert (
            isinstance(process, str) and process
        ), "`process` must be a non-empty string."

        result = ""
        error = ""
        code = None

        res = self.execute(
            "pkill", data='"%s"' % (process,), options=options, sudo=sudo
        )
        if res.ec != 0:
            self.log.warning("Failed to pkill `%s` process." % (process,))
        code, error, result = (
            res.ec if not code or code == 0 else code,
            "\n".join([error, res.err]),
            "\n".join([result, res.out]),
        )
        return CmdResult(code, result, error)

    def _taskkill(self, process, match_all=True):
        """Stop processes matching the given name.

        Windows only.

        :Parameters:
            - `processes`: process name.
            - `match_all`: find all processes that match 'process'.

        :Return:
            - namedtuple(ec, out, err).

        :Exceptions:
            - `AssertionError`: is raised if:
                1) `processes` is not a string or is an empty string.
        """
        assert self.operating_system == "windows"

        wildcard = "*" if match_all else ""
        result = ""
        error = ""
        code = None

        res = self.execute('taskkill /F /IM "%s%s"' % (process, wildcard))
        if res.ec != 0:
            self.log.error("Failed to `stop` process.\nError: %s." % (res.err,))
        code, error, result = (
            res.ec if not code or code == 0 else code,
            "\n".join([error, res.err]),
            "\n".join([result, res.out]),
        )
        return CmdResult(code, result, error)

    def stop_process(self, processes, options=["-9 -f"], sudo=False):
        """Stop all specified processes.

        :Parameters:
            - `processes`: string name of a process, or a list or a tuple of processes to stop.
            - `match_all`: find all processes that match 'processes'.

        :Return:
            - namedtuple(ec, out, err).

        :Exceptions:
            - `AssertionError`: is raised if:
                1) `processes` is not a string or is an empty string.
        """
        assert processes, "`processes` should not be empty."

        processes = processes if isinstance(processes, (list, tuple)) else [processes]
        results = []

        for process in processes:
            if self.operating_system == "windows":
                res = self._taskkill(process, match_all=True)
            else:
                res = self._pkill(process, options, sudo)
            results.append(res)

        return results

    def execute_command(self, cmd, **kwargs):
        """Execute custom command.

        :Return:
            - namedtuple(ec, out, err).
        """
        return self.execute(cmd, **kwargs)

    # Find the metadata.json file and verify its contents.
    def verify_metadata_json(self, tempdir, expected=[], unexpected=[]):
        for parent, dirs, files in os.walk(tempdir):
            for f in files:
                if "metadata.json" == f:
                    with open(os.path.join(parent, f)) as handle:
                        metadata_json = handle.read()
                        self.verify_output(metadata_json, expected=expected, unexpected=unexpected)

                    # There is only one metadata.json per scan.
                    # We found it, so we can break out of the loop.
                    break



class Logger(object):

    """Logger class."""

    _format = "[%(levelname)s]: %(message)s"

    _level = logging.DEBUG

    levels = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }

    def __init__(self, name, level="debug", log_file=""):
        """Initialize Logger instance."""

        self.core = logging.getLogger(name)
        self.core.propagate = False

        self.set_level(level)

        formatter = logging.Formatter(self._format, "%Y-%m-%d %H:%M:%S")
        try:
            handler = logging.StreamHandler(strm=sys.stdout)
        except TypeError:
            handler = logging.StreamHandler(stream=sys.stdout)
        finally:
            handler.setFormatter(formatter)

        self.core.addHandler(handler)

        if log_file != "":
            filehandler = logging.FileHandler(filename=log_file)
            filehandler.setLevel(self.levels[level.lower()])
            filehandler.setFormatter(formatter)
            self.core.addHandler(filehandler)

    def set_level(self, level):
        """Set logging level."""
        self.core.setLevel(self.levels[level.lower()])

    def __getattr__(self, attr):
        return getattr(self.core, attr)


class Executor(object):
    """Common CLI executor class."""

    def __init__(self, logger=None):
        """Initialize BaseExecutor instance."""
        global loggers

        if logger != None:
            self._logger = logger
        else:
            if loggers.get(self.__class__.__name__):
                self._logger = loggers.get(self.__class__.__name__)
            else:
                self._logger = Logger(self.__class__.__name__)
                loggers[self.__class__.__name__] = self._logger

        self._process = None
        self._process_pid = None
        self.result = None
        self.error = None
        self.code = None
        self.terminated = False

    def _log_cmd_results(self):
        """Log exit code, stdout and stderr of the executed command."""
        self._logger.debug("Exit code: %s" % self.code)
        self._logger.debug("stdout: %s" % self.result)
        if self.code:
            self._logger.debug("stderr: %s" % self.error)

    def _start_cmd_thread(self, target, target_args, timeout=EXECUTION_TIMEOUT):
        """Start command thread and kill it if timeout exceeds.

        :Return:
            - namedtuple(ec, out, err).
        """
        # Start monitor thread.
        thread = threading.Thread(target=target, args=target_args)
        thread.start()
        thread.join(timeout)

        # Kill process if timeout exceeded.
        if thread.is_alive():
            if platform.system() == "Windows":
                os.kill(self._process_pid, signal.CTRL_C_EVENT)
            else:
                os.killpg(self._process_pid, signal.SIGTERM)
            self.terminated = True
            thread.join()

        return CmdResult(self.code, self.result, self.error)

    def __run(self, cmd, cwd=None, env_vars={}, interact=""):
        """Execute command in separate thread."""
        if platform.system() == "Windows":
            self._logger.debug("Run command: %s" % (cmd,))
            self._process = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
            )

        else:
            sys_env = os.environ.copy()
            sys_env.update(env_vars)

            if sys.platform == 'darwin':
                # macOS doesn't propagate 'LD_LIBRARY_PATH' or 'DYLD_LIBRARY_PATH'
                # to subprocesses, presumably as a security feature.
                # We will likely need these for testing and can propagate them
                # manually, like so:
                if "LD_LIBRARY_PATH" in sys_env:
                    cmd = "export LD_LIBRARY_PATH={} && {}".format(sys_env['LD_LIBRARY_PATH'], cmd)
                if "DYLD_LIBRARY_PATH" in sys_env:
                    cmd = "export DYLD_LIBRARY_PATH={} && {}".format(sys_env['DYLD_LIBRARY_PATH'], cmd)

            self._logger.debug("Run command: %s" % (cmd,))
            self._process = subprocess.Popen(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
                env=sys_env,
                shell=True,
            )

        self._process_pid = self._process.pid
        self.result, self.error = self._process.communicate(interact)
        if self.result != None:
            self.result = self.result.decode("utf-8", "ignore")
            self.error = self.error.decode("utf-8", "ignore")
        self.code = self._process.returncode

        if self.terminated:
            self.error = 'Execution timeout exceeded for "%s" command.' % (cmd,)
            self.code = TIMEOUT_EXIT_CODE
            self.terminated = False

        self._log_cmd_results()

    def execute(self, cmd, cwd=None, **kwargs):
        """Execute command.

        This method composes shell command from passed args and executes it.
        Command template: '[sudo] cmd [options] data'
        Example:
            cmd='cp', data='source_file dest_file', options=['r','f'],
            sudo=True
        Composed result: 'sudo cp -rf source_file dest_file'.

        :Parameters:
            - `cmd`: a string with a shell command to execute.
            - `cwd`: a string with a current working directory to set.

        :Keywords:
            - `data`: args for `cmd`(e.g. filename, dirname,).
            - `options`: options for the shell command.
            - `sudo`: use `sudo`? Default value is False.
            - `timeout`: execution timeout in seconds.
            - `env_vars`: a dictionary with custom environment variables.
            - `interact`: a string to enter to the command stdin during
                          execution.

        :Return:
            - namedtuple(ec, out, err).

        :Exceptions:
            - `AssertionError`: is raised if `options` is not a list.
        """
        data = kwargs.get("data", "")
        options = kwargs.get("options", [])
        sudo = kwargs.get("sudo", False)
        timeout = int(kwargs.get("timeout") or EXECUTION_TIMEOUT)
        env_vars = kwargs.get("env_vars", {})
        interact = kwargs.get("interact", "")
        assert isinstance(options, list), "`options` must be a list."

        if platform.system() == "Windows":
            timeout = EXECUTION_TIMEOUT
            return self._start_cmd_thread(self.__run, (cmd, cwd, interact), timeout)

        else:
            opts = ""
            if options:
                # Remove duplicates preserving the order:
                unq_opts = []
                for option in options:
                    option = option.strip("- ")
                    if option not in unq_opts:
                        unq_opts.append(option)

                opts = "-%s " % ("".join(unq_opts),)

            # Build command.
            execute_cmd = "%s %s%s" % (cmd, opts, data)
            if sudo:
                execute_cmd = "sudo %s" % (execute_cmd,)

            return self._start_cmd_thread(
                self.__run, (execute_cmd, cwd, env_vars, interact), timeout
            )


class LogChecker:

    """This class provides methods to check logs and strings."""

    def __init__(self, logger=None):
        """Initialize LogChecker instance."""
        global loggers

        if logger != None:
            self._logger = logger
        else:
            if loggers.get(self.__class__.__name__):
                self._logger = loggers.get(self.__class__.__name__)
            else:
                self._logger = Logger(self.__class__.__name__)
                loggers[self.__class__.__name__] = self._logger

    @staticmethod
    def _prepare_value(value):
        """Convert given value to a list if needed."""
        return value if isinstance(value, (tuple, list)) else [value]

    def __crop_output(self, output, limit=(2000, 2000)):
        """Crop string with output to specified limits.

        :Parameters:
            - `output`: a string to be cropped.
            - `limit`: a tuple with a range to be cropped from `output`.

        :Return:
            - cropped `output` if its length exceeds limit, otherwise -
              `output`.
        """
        crop_message = (
            ""
            if len(output) <= sum(limit)
            else "\n\n----- CROPPED -----\n        ...\n----- CROPPED -----\n\n"
        )
        if crop_message:
            return "".join((output[: limit[0]], crop_message, output[-limit[1] :]))
        return output

    def verify_expected_output(self, expected_items, output, order=STRICT_ORDER):
        """Check presence of regex patterns in output string.

        :Parameters:
            - `expected_items`: a list of regex patterns that should be found
                                in `output`.
            - `output`: a string with output to verify.
            - `order`: STRICT_ORDER, ANY_ORDER.

        :Exceptions:
            - `AssertionError`: is raised if:
                1)`output` is not a string.
                2) one of expected items was not found in `output`.
                3) items were found in wrong order.
        """
        if output != None and not isinstance(output, str):
            output = output.decode("utf-8", "ignore")
        assert isinstance(output, str), "`output` must be a string."
        expected_items = self._prepare_value(expected_items)

        last_found_position = 0
        for item in expected_items:
            pattern = re.compile(item)
            match = pattern.search(output)
            assert match, "Expected item `%s` not found in output:\n%s" % (
                item,
                output,
            )
            current_found_position = match.start()
            # Compare current found position with last found position
            if order == STRICT_ORDER:
                assert current_found_position >= last_found_position, (
                    "Expected item `%s` order is wrong in output:\n%s"
                    % (item, output)
                )
            last_found_position = current_found_position

    def verify_unexpected_output(self, unexpected_items, output):
        """Check absence of regex patterns in output string.

        :Parameters:
            - `unexpected_items`: a list of regex patterns that should be
                                  absent in `output`.
            - `output`: a string with output to verify.

        :Exceptions:
            - `AssertionError`: is raised if:
                1)`output` is not a string.
                2) one of unexpected items was found in `output`.
        """
        if output != None and not isinstance(output, str):
            output = output.decode("utf-8", "ignore")
        assert isinstance(output, str), "`output` must be a string."
        unexpected_items = self._prepare_value(unexpected_items)

        for item in unexpected_items:
            pattern = re.compile(item)
            match = pattern.search(output)
            assert not match, (
                "Unexpected item `%s` which should be absent "
                "found in output:\n%s" % (item, output)
            )

    def verify_expected_log(self, filename, expected=[], order=STRICT_ORDER):
        """Check presence of regex patterns in specified file.

        :Parameters:
            - `filename`: a string with absolute path to a file.
            - `expected`: a list of regex patterns that should be found in
                          the file.
            - `order`: STRICT_ORDER, ANY_ORDER.

        :Exceptions:
            - `AssertionError`: is raised if:
                1)`filename` is not a string.
                2) specified file doesn't exist.
                3) one of expected items was not found in the file.
                4) items were found in wrong order.
        """
        if filename != None and not isinstance(filename, str):
            filename = filename.decode("utf-8", "ignore")
        assert isinstance(filename, str), "`filename` must be a string."
        assert os.path.isfile(filename), "No such file: %s." % (filename,)
        expected = self._prepare_value(expected)

        def read_log():
            """Read log file in chunks."""
            with open(filename, "r") as file_reader:
                prev_lines, lines = [], []
                for idx, line in enumerate(file_reader, 1):
                    lines.append(line)
                    if idx % CHUNK_SIZE == 0:
                        yield idx, "".join(prev_lines + lines)
                        prev_lines, lines = lines, []
                if lines:
                    yield idx, "".join(prev_lines + lines)

        results = {}
        for line_idx, chunk in read_log():
            chunk_size = chunk.count("\n")
            for item in expected:
                matches_iterator = re.finditer(
                    r"%s" % (item,), chunk, flags=re.MULTILINE
                )
                for match in matches_iterator:
                    relative_line = chunk.count("\n", 0, match.start()) + 1
                    line = max(relative_line, line_idx - chunk_size + relative_line)
                    results[item] = results.get(item, [line])
                    if line not in results[item]:
                        results[item].append(line)

        if order == STRICT_ORDER:
            last_found_position = 0
            for item in expected:
                found_matches = results.get(item)
                assert found_matches, "Expected item `%s` not found in " "file: %s." % (
                    item,
                    filename,
                )
                if len(found_matches) > 1:
                    self._logger.warning("More than one match for item `%s`." % (item,))
                # Item(s) found. Let's get line number of first appearance.
                current_found_position = found_matches[0]
                # Compare first appearances of current and previous items.
                assert current_found_position > last_found_position, (
                    "Expected item `%s` order is wrong in file: %s.\n"
                    "Current position: %s.\nPrevious position: %s."
                    % (item, filename, current_found_position, last_found_position)
                )
                last_found_position = current_found_position
        else:
            for item in expected:
                found_matches = results.get(item)
                assert found_matches, "Expected item `%s` not found in " "file: %s." % (
                    item,
                    filename,
                )
                if len(found_matches) > 1:
                    self._logger.warning("More than one match for item `%s`." % (item,))

    def verify_unexpected_log(self, filename, unexpected=[], ignored=[]):
        """Check absence of regex patterns in specified file.

        :Parameters:
            - `filename`: a string with absolute path to a file.
            - `unexpected`: a list of regex patterns that should be absent in
                            the file.
            - `ignored`: a list of regex patterns that should be ignored.

        :Exceptions:
            - `AssertionError`: is raised if:
                1)`filename` is not a string.
                2) specified file doesn't exist.
                3) one of unexpected items was found in the file.
        """
        if filename != None and not isinstance(filename, str):
            filename = filename.decode("utf-8", "ignore")
        assert isinstance(filename, str), "`filename` must be a string."
        assert os.path.isfile(filename), "No such file: %s." % (filename,)
        unexpected = self._prepare_value(unexpected)
        ignored = self._prepare_value(ignored)

        with open(filename, "r") as file_reader:
            found_items = []
            for line in file_reader:
                for item in unexpected:
                    if re.search(r"%s" % (item,), line):
                        found_items.append(line.strip())
        if ignored:
            for item in ignored:
                for line in found_items[:]:
                    if re.search(r"%s" % (item,), line):
                        found_items.remove(line)

        assert len(found_items) == 0, "Unexpected items were found in %s:\n%s" % (
            filename,
            found_items,
        )
