#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Unit test for check_log_ng"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import unittest
import warnings
import os
import glob
import io
import time
import datetime
import subprocess
from check_log_ng import LogChecker


class LogCheckerTestCase(unittest.TestCase):

    """Unit test."""

    # Class constant
    MESSAGE_OK = "OK - No matches found."
    MESSAGE_WARNING_ONE = "WARNING: Found 1 lines (limit=1/0): {0} at {1}"
    MESSAGE_WARNING_TWO = "WARNING: Found 2 lines (limit=1/0): {0},{1} at {2}"
    MESSAGE_WARNING_TWO_IN_TWO_FILES = (
        "WARNING: Found 2 lines (limit=1/0): {0} at {1},{2} at {3}")
    MESSAGE_CRITICAL_ONE = "CRITICAL: Critical Found 1 lines: {0} at {1}"
    MESSAGE_UNKNOWN_LOCK_TIMEOUT = (
        "UNKNOWN: Lock timeout. Another process is running.")

    # Class variablesex
    BASEDIR = None
    TESTDIR = None
    LOGDIR = None
    STATEDIR = None

    @classmethod
    def setUpClass(cls):
        cls.BASEDIR = os.getcwd()
        cls.TESTDIR = os.path.join(cls.BASEDIR, 'test')
        cls.LOGDIR = os.path.join(cls.TESTDIR, 'log')
        cls.STATEDIR = os.path.join(cls.TESTDIR, 'state')
        if not os.path.isdir(cls.TESTDIR):
            os.mkdir(cls.TESTDIR)
        if not os.path.isdir(cls.LOGDIR):
            os.mkdir(cls.LOGDIR)
        if not os.path.isdir(cls.STATEDIR):
            os.mkdir(cls.STATEDIR)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.LOGDIR):
            os.removedirs(cls.LOGDIR)
        if os.path.exists(cls.STATEDIR):
            os.removedirs(cls.STATEDIR)
        if os.path.exists(cls.TESTDIR):
            os.removedirs(cls.TESTDIR)

    def setUp(self):
        # log files
        self.logfile = os.path.join(self.LOGDIR, 'testlog')
        self.logfile1 = os.path.join(self.LOGDIR, 'testlog.1')
        self.logfile2 = os.path.join(self.LOGDIR, 'testlog.2')
        self.logfile_pattern = os.path.join(self.LOGDIR, 'testlog*')

        # seek files
        self.tag1 = 'tag1'
        self.tag2 = 'tag2'
        self.seekfile = os.path.join(self.STATEDIR, 'testlog.seek')

        # lock file
        self.lockfile = os.path.join(self.STATEDIR, 'check_log_ng.lock')

        # configuration
        # Set cachetime to 0 for convenience in testing.
        self.config = {
            "logformat": LogChecker.FORMAT_SYSLOG,
            "state_directory": self.STATEDIR,
            "pattern_list": [],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "encoding": "utf-8",
            "warning": 1,
            "critical": 0,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200,
            "cachetime": 0,
            "lock_timeout": 3
        }

    def tearDown(self):
        # remove log files.
        for logfile in [self.logfile, self.logfile1, self.logfile2]:
            if os.path.exists(logfile):
                os.unlink(logfile)

        # remove seek files.
        seekfiles = glob.glob(
            os.path.join(self.STATEDIR, '*' + LogChecker._SUFFIX_SEEK))
        for seekfile in seekfiles:
            if os.path.exists(seekfile):
                os.unlink(seekfile)

        # remove a cache file.
        cachefiles = glob.glob(
            os.path.join(self.STATEDIR, '*' + LogChecker._SUFFIX_CACHE))
        for cachefile in cachefiles:
            if os.path.exists(cachefile):
                os.unlink(cachefile)

        # remove a lock file.
        lockfiles = glob.glob(
            os.path.join(self.STATEDIR, '*' + LogChecker._SUFFIX_LOCK))
        for lockfile in lockfiles:
            if os.path.exists(lockfile):
                os.unlink(lockfile)

    def test_format(self):
        """--format option
        """
        self.config["logformat"] = r"^(\[%a %b %d %T %Y\] \[\S+\]) (.*)$"
        self.config["pattern_list"] = ["ERROR"]
        log = LogChecker(self.config)

        # [Thu Dec 05 12:34:50 2013] [error] ERROR
        line = self._make_customized_line(
            self._get_customized_timestamp(), "error", "ERROR")
        self._write_customized_logfile(self.logfile, line)
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line, self.logfile))

    def test_pattern(self):
        """--pattern option
        """
        self.config["pattern_list"] = ["ERROR"]
        log = LogChecker(self.config)

        # 1 line matched
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line1)
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line1, self.logfile))

        # 2 lines matched
        # Dec  5 12:34:50 hostname test: ERROR1
        # Dec  5 12:34:50 hostname test: ERROR2
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR1")
        line3 = self._make_line(self._get_timestamp(), "test", "ERROR2")
        self._write_logfile(self.logfile, [line2, line3])
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_TWO.format(line2, line3, self.logfile))

        # no line matched
        # Dec  5 12:34:50 hostname noop: NOOP
        line4 = self._make_line(self._get_timestamp(), "noop", "NOOP")
        self._write_logfile(self.logfile, line4)
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), self.MESSAGE_OK)

    def test_critical_pattern(self):
        """--critical-pattern option
        """
        self.config["critical_pattern_list"] = ["FATAL"]
        log = LogChecker(self.config)

        # Dec  5 12:34:50 hostname test: FATAL
        line = self._make_line(self._get_timestamp(), "test", "FATAL")
        self._write_logfile(self.logfile, line)
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_CRITICAL)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_CRITICAL_ONE.format(line, self.logfile))

    def test_negpattern(self):
        """--negpattern option
        """
        self.config["pattern_list"] = ["ERROR"]
        self.config["critical_pattern_list"] = ["FATAL"]
        self.config["negpattern_list"] = ["IGNORE"]
        log = LogChecker(self.config)

        # check --pattern
        # Dec  5 12:34:50 hostname test: ERROR IGNORE
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR IGNORE")
        self._write_logfile(self.logfile, line1)
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), self.MESSAGE_OK)

        # check --critical-pattern
        # Dec  5 12:34:50 hostname test: FATAL IGNORE
        line2 = self._make_line(self._get_timestamp(), "test", "FATAL IGNORE")
        self._write_logfile(self.logfile, line2)
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_CRITICAL)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_CRITICAL_ONE.format(line2, self.logfile))

    def test_critical_negpattern(self):
        """--critical-negpattern option
        """
        self.config["pattern_list"] = ["ERROR"]
        self.config["critical_pattern_list"] = ["FATAL"]
        self.config["critical_negpattern_list"] = ["IGNORE"]
        log = LogChecker(self.config)

        # check --pattern and --critical-negpattern
        # Dec  5 12:34:50 hostname test: ERROR IGNORE
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR IGNORE")
        self._write_logfile(self.logfile, line1)
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), self.MESSAGE_OK)

        # check --critical-pattern and --ciritical-negpattern
        # Dec  5 12:34:50 hostname test: FATAL IGNORE
        line2 = self._make_line(self._get_timestamp(), "test", "FATAL IGNORE")
        self._write_logfile(self.logfile, line2)
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), self.MESSAGE_OK)

        # check --pattern, --critical-pattern and --critical-negpattern
        # Dec  5 12:34:50 hostname test: ERROR FATAL IGNORE
        line3 = self._make_line(
            self._get_timestamp(), "test", "ERROR FATAL IGNORE")
        self._write_logfile(self.logfile, line3)
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), self.MESSAGE_OK)

    def test_case_insensitive(self):
        """--case-insensitive option
        """
        self.config["pattern_list"] = ["error"]
        self.config["critical_pattern_list"] = ["fatal"]
        self.config["negpattern_list"] = ["ignore"]
        self.config["case_insensitive"] = True
        log = LogChecker(self.config)

        # check --pattern
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line1)
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line1, self.logfile))

        # check --critical-pattern
        # Dec  5 12:34:50 hostname test: FATAL
        line2 = self._make_line(self._get_timestamp(), "test", "FATAL")
        self._write_logfile(self.logfile, line2)
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_CRITICAL)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_CRITICAL_ONE.format(line2, self.logfile))

        # check --pattern and --negpattern
        # Dec  5 12:34:50 hostname test: ERROR ERROR IGNORE
        line3 = self._make_line(self._get_timestamp(), "test", "ERROR IGNORE")
        self._write_logfile(self.logfile, line3)
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), self.MESSAGE_OK)

    def test_encoding(self):
        """--pattern and --encoding
        """
        self.config["pattern_list"] = ["エラー"]
        self.config["encoding"] = "EUC-JP"
        log = LogChecker(self.config)

        # Dec  5 12:34:50 hostname test: エラー
        line = self._make_line(self._get_timestamp(), "test", "エラー")
        self._write_logfile(self.logfile, line, encoding='EUC-JP')
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line, self.logfile))

    def test_multiline(self):
        """--multiline
        """
        self.config["pattern_list"] = ["ERROR1.*ERROR2"]
        self.config["negpattern_list"] = ["IGNORE"]
        self.config["multiline"] = True
        log = LogChecker(self.config)

        # check --pattern, --multiline
        # Dec  5 12:34:50 hostname test: ERROR1
        # Dec  5 12:34:50 hostname test: ERROR2
        timestamp = self._get_timestamp()
        lines = []
        messages = ["ERROR1", "ERROR2"]
        for message in messages:
            lines.append(self._make_line(timestamp, "test", message))
        self._write_logfile(self.logfile, lines)
        log.clear_state()
        log.check(self.logfile)

        # detected line: Dec  5 12:34:50 hostname test: ERROR1 ERROR2
        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(
                lines[0] + " " + messages[1], self.logfile))

        # check --pattern, --negpattern and --multiline
        # Dec  5 12:34:50 hostname test: ERROR
        # Dec  5 12:34:50 hostname test: ERROR IGNORE
        timestamp = self._get_timestamp()
        lines = []
        messages = ["ERROR", "ERROR IGNORE"]
        for message in messages:
            lines.append(self._make_line(timestamp, "test", message))
        self._write_logfile(self.logfile, lines)
        log.clear_state()
        log.check(self.logfile)

        # detected line: Dec  5 12:34:50 hostname test: ERROR ERROR IGNORE
        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), self.MESSAGE_OK)

    def test_logfile(self):
        """--logfile option
        """
        self.config["pattern_list"] = ["ERROR"]
        log = LogChecker(self.config)

        # check -logfile option with wild card '*'
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile1, line1)

        # Dec  5 12:34:50 hostname test: ERROR
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile2, line2)
        log.clear_state()
        log.check(self.logfile_pattern)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_TWO_IN_TWO_FILES.format(
                line1, self.logfile1, line2, self.logfile2))

        # --logfile option with multiple filenames
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile1, line1)

        # Dec  5 12:34:50 hostname test: ERROR
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile2, line2)
        logfile_pattern = "{0} {1}".format(self.logfile1, self.logfile2)
        log.clear_state()
        log.check(logfile_pattern)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_TWO_IN_TWO_FILES.format(
                line1, self.logfile1, line2, self.logfile2))

    def test_trace_inode(self):
        """--trace_inode
        """
        self.config["pattern_list"] = ["ERROR"]
        self.config["trace_inode"] = True
        log = LogChecker(self.config)

        # within expiration
        # create logfile
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line1)

        # create seekfile of logfile
        log.check(self.logfile_pattern)
        seekfile_1 = log._create_seek_filename(
            self.logfile_pattern, self.logfile, trace_inode=True)

        # update logfile
        # Dec  5 12:34:51 hostname test: ERROR
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line2)

        # log rotation
        os.rename(self.logfile, self.logfile1)

        # create a new logfile
        # Dec  5 12:34:52 hostname noop: NOOP
        line3 = self._make_line(self._get_timestamp(), "noop", "NOOP")
        self._write_logfile(self.logfile, line3)

        # create seekfile of logfile
        log.clear_state()
        log.check(self.logfile_pattern)
        seekfile_2 = log._create_seek_filename(
            self.logfile_pattern, self.logfile, trace_inode=True)
        seekfile1_2 = log._create_seek_filename(
            self.logfile_pattern, self.logfile1, trace_inode=True)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line2, self.logfile1))
        self.assertEqual(seekfile_1, seekfile1_2)
        self.assertTrue(os.path.exists(seekfile_2))
        self.assertTrue(os.path.exists(seekfile1_2))

    def test_scantime(self):
        """--scantime option
        """
        self.config["pattern_list"] = ["ERROR"]
        self.config["scantime"] = 2
        log = LogChecker(self.config)

        # within scantime.
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile1, line1)
        log.clear_state()
        log.check(self.logfile_pattern)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line1, self.logfile1))

        # over scantime
        # Dec  5 12:34:50 hostname test: ERROR
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile1, line2)
        time.sleep(4)
        log.clear_state()
        log.check(self.logfile_pattern)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), self.MESSAGE_OK)

        # multiple logfiles.
        # Dec  5 12:34:50 hostname test: ERROR
        line3 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile1, line3)
        time.sleep(4)

        # Dec  5 12:34:54 hostname test: ERROR
        line4 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile2, line4)

        # logfile1 should be older than spantime. Therefore, don't scan it.
        log.clear_state()
        log.check(self.logfile_pattern)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line4, self.logfile2))

    def test_remove_seekfile(self):
        """--expiration and --remove-seekfile options
        """
        self.config["pattern_list"] = ["ERROR"]
        self.config["scantime"] = 2
        self.config["expiration"] = 4
        log = LogChecker(self.config)

        # within expiration
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile1, line1)

        log.check(self.logfile_pattern, remove_seekfile=True)
        self.seekfile1 = log._create_seek_filename(
            self.logfile_pattern, self.logfile1)
        time.sleep(2)

        # Dec  5 12:34:54 hostname test: ERROR
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile2, line2)

        # seek file of logfile1 should not be purged.
        log.clear_state()
        log.check(self.logfile_pattern, remove_seekfile=True)
        self.seekfile2 = log._create_seek_filename(
            self.logfile_pattern, self.logfile2)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line2, self.logfile2))
        self.assertTrue(os.path.exists(self.seekfile1))
        self.assertTrue(os.path.exists(self.seekfile2))

        # over expiration
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile1, line1)

        log.check(self.logfile_pattern, remove_seekfile=True)
        time.sleep(6)

        # Dec  5 12:34:54 hostname test: ERROR
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile2, line2)

        # seek file of logfile1 should be purged.
        log.clear_state()
        log.check(self.logfile_pattern, remove_seekfile=True)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line2, self.logfile2))
        self.assertFalse(os.path.exists(self.seekfile1))
        self.assertTrue(os.path.exists(self.seekfile2))

    def test_remove_seekfile_inode(self):
        """--trace_inode, --expiration and --remove-seekfile options
        """
        self.config["pattern_list"] = ["ERROR"]
        self.config["trace_inode"] = True
        self.config["scantime"] = 2
        self.config["expiration"] = 3
        log = LogChecker(self.config)

        # create logfile
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line1)

        # log rotation
        os.rename(self.logfile, self.logfile1)

        # create new logfile
        # Dec  5 12:34:50 hostname test: ERROR
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line2)

        # do check_log_multi, and create seekfile and seekfile1
        log.clear_state()
        log.check(self.logfile_pattern, remove_seekfile=True)
        seekfile_1 = log._create_seek_filename(
            self.logfile_pattern, self.logfile, trace_inode=True)
        seekfile1_1 = log._create_seek_filename(
            self.logfile_pattern, self.logfile1, trace_inode=True)
        time.sleep(4)

        # update logfile
        # Dec  5 12:34:54 hostname test: ERROR
        line3 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line3)

        # log rotation, purge old logfile2
        os.rename(self.logfile1, self.logfile2)
        os.rename(self.logfile, self.logfile1)

        # seek file of old logfile1 should be purged.
        log.clear_state()
        log.check(
            self.logfile_pattern, remove_seekfile=True)
        seekfile1_2 = log._create_seek_filename(
            self.logfile_pattern, self.logfile1, trace_inode=True)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line3, self.logfile1))
        self.assertEqual(seekfile_1, seekfile1_2)
        self.assertFalse(os.path.exists(seekfile1_1))
        self.assertTrue(os.path.exists(seekfile1_2))

    def test_replace_pipe_symbol(self):
        """replace pipe symbol
        """
        line = "Dec | 5 12:34:56 hostname test: ERROR"
        self.config["pattern_list"] = ["ERROR"]
        log = LogChecker(self.config)

        # Dec  5 12:34:50 hostname test: ERROR |
        line = self._make_line(self._get_timestamp(), "test", "ERROR |")
        self._write_logfile(self.logfile, line)
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(
                line.replace("|", "(pipe)"), self.logfile))

    def test_seekfile(self):
        """--seekfile option
        """
        self.config["pattern_list"] = ["ERROR"]
        log = LogChecker(self.config)

        # 1 line matched
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line1)
        log.check(self.logfile, seekfile=self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line1, self.logfile))

        # 2 lines matched
        # Dec  5 12:34:50 hostname test: ERROR1
        # Dec  5 12:34:50 hostname test: ERROR2
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR1")
        line3 = self._make_line(self._get_timestamp(), "test", "ERROR2")
        self._write_logfile(self.logfile, [line2, line3])
        log.clear_state()
        log.check(self.logfile, seekfile=self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_TWO.format(line2, line3, self.logfile))

        # no line matched
        # Dec  5 12:34:50 hostname noop: NOOP
        line4 = self._make_line(self._get_timestamp(), "noop", "NOOP")
        self._write_logfile(self.logfile, line4)
        log.clear_state()
        log.check(self.logfile, seekfile=self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), self.MESSAGE_OK)

    def test_tag(self):
        """--tag
        """
        self.config["pattern_list"] = ["ERROR"]
        log = LogChecker(self.config)

        # create new logfiles
        # Dec  5 12:34:50 hostname test: ERROR
        line1 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line1)

        # Dec  5 12:34:50 hostname test: ERROR
        line2 = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile1, line2)

        # Dec  5 12:34:50 hostname test: ERROR
        line3 = self._make_line(self._get_timestamp(), "noop", "NOOP")
        self._write_logfile(self.logfile2, line3)

        # create seekfile of logfile
        seekfile_1 = log._create_seek_filename(
            self.logfile_pattern, self.logfile, tag=self.tag1)
        seekfile_2 = log._create_seek_filename(
            self.logfile_pattern, self.logfile, tag=self.tag1)
        seekfile_3 = log._create_seek_filename(
            self.logfile_pattern, self.logfile, tag=self.tag2)
        log.check(self.logfile, seekfile=seekfile_3)
        log.clear_state()
        log.check(
            self.logfile_pattern, tag=self.tag2)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line2, self.logfile1))
        self.assertEqual(seekfile_1, seekfile_2)
        self.assertNotEqual(seekfile_1, seekfile_3)
        self.assertTrue(seekfile_1.find(self.tag1))
        self.assertTrue(os.path.exists(seekfile_3))

    def test_cachetime(self):
        """--cachetime
        """
        self.config["pattern_list"] = ["ERROR"]
        self.config["cachetime"] = 2
        log = LogChecker(self.config)

        cachefile = log._create_cache_filename(self.logfile)

        # within cachetime
        # Dec  5 12:34:50 hostname test: ERROR
        line = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line)

        # check
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line, self.logfile))

        # check again
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line, self.logfile))

        log._remove_cache(cachefile)

        # over cachetime
        # Dec  5 12:34:50 hostname test: ERROR
        line = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line)

        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line, self.logfile))

        # check again
        time.sleep(self.config["cachetime"] + 1)
        log.clear_state()
        log.check(self.logfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)

        log._remove_cache(cachefile)

    def test_lock_timeout(self):
        """--lock-timeout
        """
        self.config["pattern_list"] = ["ERROR"]
        self.config["lock_timeout"] = 6
        log = LogChecker(self.config)

        lockfile = log._create_lock_filename(self.logfile)

        # within lock_timeout
        #   |time|sub        |main       |
        #   |----|-----------|-----------|
        #   |   0|fork       |sleep      |
        #   |   1|lock OK    |sleep      |
        #   |   1|           |check      |
        #   |   1|           |lock fail  |
        #   |   *|           |sleep      |
        #   |   5|unlock OK  |sleep      |
        #   |   5|           |lock OK    |
        #   |   5|           |unlock OK  |
        # Dec  5 12:34:50 hostname test: ERROR
        line = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line)

        # locked by an another process
        locked_time = 4
        wait_interval = 0.1
        proc = self._run_locked_subprocess(lockfile, locked_time)
        for _ in range(100):
            if os.path.isfile(lockfile):
                break
            time.sleep(wait_interval)

        # check
        log.clear_state()
        start_time = time.time()
        log.check(self.logfile)
        elapsed_time = time.time() - start_time
        proc.wait()

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(
            log.get_message(),
            self.MESSAGE_WARNING_ONE.format(line, self.logfile))
        self.assertTrue(elapsed_time < self.config["lock_timeout"])
        self.assertTrue(elapsed_time > locked_time - wait_interval)

        # over lock_timeout
        #   |time|sub        |main       |
        #   |----|-----------|-----------|
        #   |   0|fork       |sleep      |
        #   |   1|lock OK    |sleep      |
        #   |   1|           |check      |
        #   |   1|           |lock fail  |
        #   |   *|           |sleep      |
        #   |   7|           |timeout    |
        #   |   9|unlock OK  |           |
        # Dec  5 12:34:50 hostname test: ERROR
        line = self._make_line(self._get_timestamp(), "test", "ERROR")
        self._write_logfile(self.logfile, line)

        # locked by an another process
        locked_time = 8
        wait_interval = 0.1
        proc = self._run_locked_subprocess(lockfile, locked_time)
        for _ in range(100):
            if os.path.isfile(lockfile):
                break
            time.sleep(wait_interval)

        # check
        log.clear_state()
        start_time = time.time()
        log.check(self.logfile)
        elapsed_time = time.time() - start_time
        proc.wait()

        self.assertEqual(log.get_state(), LogChecker.STATE_UNKNOWN)
        self.assertEqual(log.get_message(), self.MESSAGE_UNKNOWN_LOCK_TIMEOUT)
        self.assertTrue(elapsed_time > self.config["lock_timeout"])
        self.assertTrue(elapsed_time < locked_time)

    def test_lock(self):
        """LogChecker.lock()
        """
        # lock succeeded
        lockfileobj = LogChecker.lock(self.lockfile)
        self.assertNotEqual(lockfileobj, None)
        LogChecker.unlock(self.lockfile, lockfileobj)

        # locked by an another process
        locked_time = 4
        wait_interval = 0.1
        proc = self._run_locked_subprocess(self.lockfile, locked_time)
        for _ in range(100):
            if os.path.isfile(self.lockfile):
                break
            time.sleep(wait_interval)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            lockfileobj = LogChecker.lock(self.lockfile)
        proc.wait()
        self.assertEqual(lockfileobj, None)

    def test_unlock(self):
        """LogChecker.unlock()
        """
        lockfileobj = LogChecker.lock(self.lockfile)
        LogChecker.unlock(self.lockfile, lockfileobj)
        self.assertFalse(os.path.exists(self.lockfile))
        self.assertTrue(lockfileobj.closed)

    def _get_timestamp(self):
        # format: Dec  5 12:34:00
        timestamp = LogChecker.to_unicode(
            datetime.datetime.now().strftime("%b %e %T"))
        return timestamp

    def _get_customized_timestamp(self):
        # format: Thu Dec 05 12:34:56 2013
        timestamp = LogChecker.to_unicode(
            datetime.datetime.now().strftime("%a %b %d %T %Y"))
        return timestamp

    def _make_line(self, timestamp, tag, message):
        # format: Dec  5 12:34:00 hostname noop: NOOP
        line = "{0} hostname {1}: {2}".format(timestamp, tag, message)
        return line

    def _make_customized_line(self, timestamp, level, message):
        # format: [Thu Dec 05 12:34:56 2013] [info] NOOP
        line = "[{0}] [{1}] {2}".format(timestamp, level, message)
        return line

    def _write_logfile(self, logfile, lines, encoding='utf-8'):
        """Write log file for syslog format."""
        fileobj = io.open(logfile, mode='a', encoding=encoding)
        fileobj.write(self._make_line(self._get_timestamp(), "noop", "NOOP"))
        fileobj.write("\n")
        if isinstance(lines, list):
            for line in lines:
                fileobj.write(line)
                fileobj.write("\n")
        else:
            fileobj.write(lines)
            fileobj.write("\n")
        fileobj.write(self._make_line(self._get_timestamp(), "noop", "NOOP"))
        fileobj.write("\n")
        fileobj.flush()
        fileobj.close()

    def _write_customized_logfile(self, logfile, lines, encoding='utf-8'):
        """Write log file for customized format."""
        fileobj = io.open(logfile, mode='a', encoding=encoding)
        fileobj.write(
            self._make_customized_line(
                self._get_customized_timestamp(), "info", "NOOP"))
        fileobj.write("\n")
        if isinstance(lines, list):
            for line in lines:
                fileobj.write(line)
                fileobj.write("\n")
        else:
            fileobj.write(lines)
            fileobj.write("\n")
        fileobj.write(
            self._make_customized_line(
                self._get_customized_timestamp(), "info", "NOOP"))
        fileobj.write("\n")
        fileobj.flush()
        fileobj.close()

    def _run_locked_subprocess(self, lockfile, sleeptime):
        code = (
            "import time\n"
            "from check_log_ng import LogChecker\n"
            "lockfile = '{0}'\n"
            "lockfileobj = LogChecker.lock(lockfile)\n"
            "time.sleep({1})\n"
            "LogChecker.unlock(lockfile, lockfileobj)\n"
        ).format(lockfile, LogChecker.to_unicode(str(sleeptime)))
        code = code.replace("\n", ";")
        proc = subprocess.Popen(['python', '-c', code])
        return proc


if __name__ == "__main__":
    unittest.main()

# vim: set ts=4 sw=4 et:
