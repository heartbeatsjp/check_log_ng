#!/usr/bin/env python
# coding: utf-8

from check_log_ng import LogChecker
import unittest
import os
import time
# import sys
# import pikzie


class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        curdir = os.getcwd()
        testdir = os.path.join(curdir, 'test')
        self.testdir = testdir
        if not os.path.isdir(testdir):
            os.mkdir(testdir)

        logdir = os.path.join(testdir, 'log')
        if not os.path.isdir(logdir):
            os.mkdir(logdir)
        self.logdir = logdir
        self.logfile = os.path.join(logdir, 'testlog')
        self.logfile1 = os.path.join(logdir, 'testlog.1')
        self.logfile2 = os.path.join(logdir, 'testlog.2')
        self.logfile_pattern = os.path.join(logdir, 'testlog*')

        seekdir = os.path.join(testdir, 'seek')
        if not os.path.isdir(seekdir):
            os.mkdir(seekdir)
        self.seekdir = seekdir
        self.seekfile = os.path.join(seekdir, 'testlog.seek')
        self.seekfile1 = LogChecker.get_seekfile(self.logfile_pattern, seekdir, self.logfile1)
        self.seekfile2 = LogChecker.get_seekfile(self.logfile_pattern, seekdir, self.logfile2)

        self.logformat_syslog = LogChecker.FORMAT_SYSLOG

    def tearDown(self):
        if os.path.exists(self.seekfile):
            os.unlink(self.seekfile)
        if os.path.exists(self.seekfile1):
            os.unlink(self.seekfile1)
        if os.path.exists(self.seekfile2):
            os.unlink(self.seekfile2)

        if os.path.exists(self.logfile):
            seekfile = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile, trace_inode=True)
            if os.path.exists(seekfile):
                os.unlink(seekfile)
            os.unlink(self.logfile)

        if os.path.exists(self.logfile1):
            seekfile1 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile1, trace_inode=True)
            if os.path.exists(seekfile1):
                os.unlink(seekfile1)
            os.unlink(self.logfile1)

        if os.path.exists(self.logfile2):
            seekfile2 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile2, trace_inode=True)
            if os.path.exists(seekfile2):
                os.unlink(seekfile2)
            os.unlink(self.logfile2)
        if os.path.exists(self.logdir):
            os.removedirs(self.logdir)
        if os.path.exists(self.seekdir):
            os.removedirs(self.seekdir)
        if os.path.exists(self.testdir):
            os.removedirs(self.testdir)

    def test_format(self):
        """--format option
        """
        initial_data = {
            "logformat": "^(\[%a %b %d %T %Y\] \[\S+\]) (.*)$",
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("[Thu Dec 05 12:34:56 2013] [error] NOOP\n")
        f.write("[Thu Dec 05 12:34:56 2013] [error] ERROR\n")
        f.write("[Thu Dec 05 12:34:57 2013] [error] NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), "WARNING: Found 1 lines (limit=1/0): [Thu Dec 05 12:34:56 2013] [error] ERROR at %s" % self.logfile)

    def test_pattern(self):
        """--pattern option
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 1 lines (limit=1/0): Dec  5 12:34:56 hostname test: ERROR at %s' % self.logfile)

    def test_pattern_no_matches(self):
        """--pattern option
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), 'OK - No matches found.')

    def test_pattern_with_case_insensitive(self):
        """--pattern and --case-insensitive options
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["error"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": True,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 1 lines (limit=1/0): Dec  5 12:34:56 hostname test: ERROR at %s' % self.logfile)

    def test_criticalpattern(self):
        """--criticalpattern option
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": [],
            "critical_pattern_list": ["ERROR"],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_CRITICAL)
        self.assertEqual(log.get_message(), 'CRITICAL: Critical Found 1 lines: Dec  5 12:34:56 hostname test: ERROR at %s' % self.logfile)

    def test_criticalpattern_with_negpattern(self):
        """--criticalpattern option
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": [],
            "critical_pattern_list": ["ERROR"],
            "negpattern_list": ["IGNORE"],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR IGNORE\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_CRITICAL)
        self.assertEqual(log.get_message(), 'CRITICAL: Critical Found 1 lines: Dec  5 12:34:56 hostname test: ERROR IGNORE at %s' % self.logfile)

    def test_criticalpattern_with_case_sensitive(self):
        """--criticalpattern and --case-insensitive options
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": [],
            "critical_pattern_list": ["error"],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": True,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_CRITICAL)
        self.assertEqual(log.get_message(), 'CRITICAL: Critical Found 1 lines: Dec  5 12:34:56 hostname test: ERROR at %s' % self.logfile)

    def test_negpattern(self):
        """--negpattern option
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": ["IGNORE"],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR IGNORE\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), 'OK - No matches found.')

    def test_critical_negpattern(self):
        """--critical-negpattern option
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": [],
            "critical_pattern_list": ["FATAL"],
            "negpattern_list": [],
            "critical_negpattern_list": ["IGNORE"],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: FATAL ERROR IGNORE\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), 'OK - No matches found.')

    def test_critical_negpattern_with_pattern(self):
        """--criticalpattern option
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": [],
            "critical_pattern_list": ["FATAL"],
            "negpattern_list": [],
            "critical_negpattern_list": ["IGNORE"],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: IGNORE FATAL\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), 'OK - No matches found.')

    def test_critical_negpattern_with_pattern_and_criticalpattern(self):
        """--criticalpattern option
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": ["FATAL"],
            "negpattern_list": [],
            "critical_negpattern_list": ["IGNORE"],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR IGNORE FATAL\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), 'OK - No matches found.')

    def test_negpattern_with_case_insensitive(self):
        """--negpattern and --case-insensitive options
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": ["ignore"],
            "critical_negpattern_list": [],
            "case_insensitive": True,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR IGNORE\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), 'OK - No matches found.')

    def test_pattern_with_multiple_lines(self):
        """--pattern options with multiples lines
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR1.*ERROR2"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": True,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR1\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR2\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 1 lines (limit=1/0): Dec  5 12:34:56 hostname test: ERROR1 ERROR2 at %s' % self.logfile)

    def test_negpattern_with_multiple_lines(self):
        """--negpattern options with multiple lines
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": ["IGNORE"],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": True,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR IGNORE\n")
        f.flush()
        f.close()

        log.check_log(self.logfile, self.seekfile)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), 'OK - No matches found.')

    def test_logfile_with_wildcard(self):
        """--logfile option with wild card '*'
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile1, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        time.sleep(1)

        f = open(self.logfile2, 'a')
        f.write("Dec  5 12:34:58 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:59 hostname test: ERROR\n")
        f.write("Dec  5 12:34:59 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=False)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 2 lines (limit=1/0): Dec  5 12:34:56 hostname test: ERROR at %s,Dec  5 12:34:59 hostname test: ERROR at %s' % (self.logfile1, self.logfile2))

    def test_logfile_with_filename(self):
        """--logfile option with multiple filenames
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile1, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        time.sleep(1)

        f = open(self.logfile2, 'a')
        f.write("Dec  5 12:34:58 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:59 hostname test: ERROR\n")
        f.write("Dec  5 12:34:59 hostname noop: NOOP\n")
        f.flush()
        f.close()

        logfile_pattern = "%s %s" % (self.logfile1, self.logfile2)
        log.check_log_multi(logfile_pattern, self.seekdir, remove_seekfile=False)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 2 lines (limit=1/0): Dec  5 12:34:56 hostname test: ERROR at %s,Dec  5 12:34:59 hostname test: ERROR at %s' % (self.logfile1, self.logfile2))

    def test_scantime_without_scantime(self):
        """--scantime option without scantime.
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 2,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile1, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        time.sleep(4)
        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=False)

        self.assertEqual(log.get_state(), LogChecker.STATE_OK)
        self.assertEqual(log.get_message(), 'OK - No matches found.')

    def test_scantime_within_scantime(self):
        """--scantime option within scantime.
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 2,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile1, 'a')
        f.write("Dec  5 12:34:58 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:59 hostname test: ERROR\n")
        f.write("Dec  5 12:34:59 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # The first ERROR message should be older than scantime. Therefore, don't scan it.
        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=False)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 1 lines (limit=1/0): Dec  5 12:34:59 hostname test: ERROR at %s' % self.logfile1)

    def test_scantime_with_multiple_logfiles(self):
        """--scantime option with multiple logfiles.
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 2,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        f = open(self.logfile1, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        time.sleep(4)

        f = open(self.logfile2, 'a')
        f.write("Dec  5 12:34:58 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:59 hostname test: ERROR\n")
        f.write("Dec  5 12:34:59 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # logfile1 should be older than timespan. Therefore, don't scan it.
        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=False)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 1 lines (limit=1/0): Dec  5 12:34:59 hostname test: ERROR at %s' % self.logfile2)

    def test_remove_seekfile_without_expiration(self):
        """--expiration and --remove-seekfile options
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 2,
            "expiration": 3
        }
        log = LogChecker(initial_data)

        f = open(self.logfile1, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=True)
        log.clear_state()
        time.sleep(4)

        f = open(self.logfile2, 'a')
        f.write("Dec  5 12:34:58 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:59 hostname test: ERROR\n")
        f.write("Dec  5 12:34:59 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # seek file of logfile1 should be purged.
        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=True)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 1 lines (limit=1/0): Dec  5 12:34:59 hostname test: ERROR at %s' % self.logfile2)
        self.assertFalse(os.path.exists(self.seekfile1))
        self.assertTrue(os.path.exists(self.seekfile2))

    def test_remove_seekfile_within_expiration(self):
        """--expiration and --remove-seekfile options
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": False,
            "multiline": False,
            "scantime": 2,
            "expiration": 10
        }
        log = LogChecker(initial_data)

        f = open(self.logfile1, 'a')
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:56 hostname test: ERROR\n")
        f.write("Dec  5 12:34:57 hostname noop: NOOP\n")
        f.flush()
        f.close()

        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=True)
        log.clear_state()
        time.sleep(4)

        f = open(self.logfile2, 'a')
        f.write("Dec  5 12:34:58 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:59 hostname test: ERROR\n")
        f.write("Dec  5 12:34:59 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # seek file of logfile1 should be purged.
        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=True)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 1 lines (limit=1/0): Dec  5 12:34:59 hostname test: ERROR at %s' % self.logfile2)
        self.assertTrue(os.path.exists(self.seekfile1))
        self.assertTrue(os.path.exists(self.seekfile2))

    def test_trace_inode(self):
        """--trace_inode
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": True,
            "multiline": False,
            "scantime": 86400,
            "expiration": 691200
        }
        log = LogChecker(initial_data)

        # create logfile
        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:51 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:51 hostname test: ERROR\n")
        f.write("Dec  5 12:34:52 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # create seekfile of logfile
        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=False)
        log.clear_state()
        seekfile_1 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile, trace_inode=True)

        # update logfile
        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:55 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:55 hostname test: ERROR\n")
        f.write("Dec  5 12:34:56 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # log rotation
        os.rename(self.logfile, self.logfile1)

        # create a new logfile
        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:59 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # create seekfile of logfile
        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=False)
        seekfile_2 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile, trace_inode=True)
        seekfile1_2 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile1, trace_inode=True)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 1 lines (limit=1/0): Dec  5 12:34:55 hostname test: ERROR at %s' % self.logfile1)
        self.assertEqual(seekfile_1, seekfile1_2)
        self.assertTrue(os.path.exists(seekfile_2))
        self.assertTrue(os.path.exists(seekfile1_2))

    def test_trace_inode_without_expiration(self):
        """--trace_inode, --expiration and --remove-seekfile options
        """
        initial_data = {
            "logformat": self.logformat_syslog,
            "pattern_list": ["ERROR"],
            "critical_pattern_list": [],
            "negpattern_list": [],
            "critical_negpattern_list": [],
            "case_insensitive": False,
            "warning": 1,
            "critical": 0,
            "nodiff_warn": False,
            "nodiff_crit": False,
            "trace_inode": True,
            "multiline": False,
            "scantime": 2,
            "expiration": 3
        }
        log = LogChecker(initial_data)

        # create logfile
        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:50 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:51 hostname test: ERROR\n")
        f.write("Dec  5 12:34:52 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # log rotation
        os.rename(self.logfile, self.logfile1)

        # create new logfile
        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:53 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:53 hostname test: ERROR\n")
        f.write("Dec  5 12:34:54 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # do check_log_multi, and create seekfile and seekfile1
        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=True)
        log.clear_state()
        seekfile_1 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile, trace_inode=True)
        seekfile1_1 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile1, trace_inode=True)
        time.sleep(4)

        # update logfile
        f = open(self.logfile, 'a')
        f.write("Dec  5 12:34:58 hostname noop: NOOP\n")
        f.write("Dec  5 12:34:59 hostname test: ERROR\n")
        f.write("Dec  5 12:34:59 hostname noop: NOOP\n")
        f.flush()
        f.close()

        # log rotation, purge old logfile2
        os.rename(self.logfile1, self.logfile2)
        os.rename(self.logfile, self.logfile1)

        # seek file of old logfile1 should be purged.
        log.check_log_multi(self.logfile_pattern, self.seekdir, remove_seekfile=True)
        seekfile1_2 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile1, trace_inode=True)

        self.assertEqual(log.get_state(), LogChecker.STATE_WARNING)
        self.assertEqual(log.get_message(), 'WARNING: Found 1 lines (limit=1/0): Dec  5 12:34:59 hostname test: ERROR at %s' % self.logfile1)
        self.assertEqual(seekfile_1, seekfile1_2)
        self.assertFalse(os.path.exists(seekfile1_1))
        self.assertTrue(os.path.exists(seekfile1_2))


# class TestCommandLineParser(pikzie.TestCase):
#
#     def setup(self):
#         curdir = os.getcwd()
#         testdir = os.path.join(curdir, 'test')
#         if not os.path.isdir(testdir):
#             os.mkdir(testdir)
#
#         logdir = os.path.join(testdir, 'log')
#         if not os.path.isdir(logdir):
#             os.mkdir(logdir)
#         self.logfile = os.path.join(logdir, 'testlog')
#         self.logfile1 = os.path.join(logdir, 'testlog.1')
#         self.logfile2 = os.path.join(logdir, 'testlog.2')
#         self.logfile_pattern = os.path.join(logdir, 'testlog*')
#
#         seekdir = os.path.join(testdir, 'seek')
#         if not os.path.isdir(seekdir):
#             os.mkdir(seekdir)
#         self.seekdir = seekdir
#         self.seekfile = os.path.join(seekdir, 'testlog.seek')
#         self.seekfile1 = LogChecker.get_seekfile(self.logfile_pattern, seekdir, self.logfile1)
#         self.seekfile2 = LogChecker.get_seekfile(self.logfile_pattern, seekdir, self.logfile2)
#
#         self.logformat_syslog = LogChecker.FORMAT_SYSLOG
#
#     def teardown(self):
#         if os.path.exists(self.seekfile):
#             os.unlink(self.seekfile)
#         if os.path.exists(self.seekfile1):
#             os.unlink(self.seekfile1)
#         if os.path.exists(self.seekfile2):
#             os.unlink(self.seekfile2)
#
#         if os.path.exists(self.logfile):
#             seekfile = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile, trace_inode=True)
#             if os.path.exists(seekfile):
#                 os.unlink(seekfile)
#             os.unlink(self.logfile)
#
#         if os.path.exists(self.logfile1):
#             seekfile1 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile1, trace_inode=True)
#             if os.path.exists(seekfile1):
#                 os.unlink(seekfile1)
#             os.unlink(self.logfile1)
#
#         if os.path.exists(self.logfile2):
#             seekfile2 = LogChecker.get_seekfile(self.logfile_pattern, self.seekdir, self.logfile2, trace_inode=True)
#             if os.path.exists(seekfile2):
#                 os.unlink(seekfile2)
#             os.unlink(self.logfile2)

#     @pikzie.data("from01", ["prog", "-l", "hogehoge", "-s", "hogehoge", "hogehoge", "-S", "0", "-j"])
#     def test_error_true(self, argv):
#         print self.logfile
#         argv.append(self.logfile1)
#         sys.argv = argv
#         parser = LogChecker.make_parser()
#         opts, args = LogChecker.check_parser_options(parser)
#         self.assert_true(opts.error)
#         self.assert_equal(args, argv[-1:])


if __name__ == "__main__":
    unittest.main()

# vim: set ts=4 sw=4 et:
