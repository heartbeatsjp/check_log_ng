#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""A log file regular expression-based parser plugin for Nagios.

Features are as follows:

- You can specify the character string you want to detect with regular
  expressions.
- You can specify the character string you do not want to detect with
  regular expressions.
- You can specify the character encoding of a log file.
- You can check multiple log files at once and also check log-rotated files.
- This script uses seek files which record the position where the check is
  completed for each log file.
  With these seek files, you can check only the differences from the last check.
- You can check multiple lines outputed at once as one message.
- The result can be cached within the specified time period.
  This will help multiple monitoring servers and multiple attempts.

This module is available in Python 2.6, 2.7, 3.5, 3.6.
Require argparse module in python 2.6.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import sys
import os
import io
import glob
import time
import re
import hashlib
import base64
import fcntl
import warnings
import argparse

# Globals
__version__ = '2.0.3'


class LogChecker(object):
    """LogChecker."""

    # Class constant
    STATE_OK = 0
    STATE_WARNING = 1
    STATE_CRITICAL = 2
    STATE_UNKNOWN = 3
    STATE_DEPENDENT = 4
    STATE_NO_CACHE = -1
    FORMAT_SYSLOG = (
        r'^((?:%b\s%e\s%T|%FT%T\S*)\s[-_0-9A-Za-z.]+\s'
        r'(?:[^ :\[\]]+(?:\[\d+?\])?:\s)?)(.*)$')
    _SUFFIX_SEEK = ".seek"
    _SUFFIX_SEEK_WITH_INODE = ".inode.seek"
    _SUFFIX_CACHE = ".cache"
    _SUFFIX_LOCK = ".lock"
    _RETRY_PERIOD = 0.5
    _LOGFORMAT_EXPANSION_LIST = [
        {'%%': '_PERCENT_'},
        {'%F': '%Y-%m-%d'},
        {'%T': '%H:%M:%S'},
        {'%a': '(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)'},
        {'%b': '(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)'},
        {'%Y': '20[0-9][0-9]'},
        {'%y': '[0-9][0-9]'},
        {'%m': '(?:0[1-9]|1[0-2])'},
        {'%d': '(?:0[1-9]|[12][0-9]|3[01])'},
        {'%e': '(?: [1-9]|[12][0-9]|3[01])'},
        {'%H': '(?:[01][0-9]|2[0-3])'},
        {'%M': '[0-5][0-9]'},
        {'%S': '(?:[0-5][0-9]|60)'},
        {'_PERCENT_': '%'},
    ]

    def __init__(self, config):
        """Constructor.

        The keys of configuration parameters are::

            logformat (str): Regular expression for log format.
            state_directory (str): The directory to store seek files, cache
                file and lock file.
            pattern_list (list): The list of regular expressions to scan for
                in the log file.
            critical_pattern_list (list): The list of regular expressions to
                scan for in the log file. If found, return CRITICAL.
            negpattern_list (list): The list of regular expressions which all
                will be skipped except as critical pattern in the log file.
            critical_negpattern_list (list): The list of regular expressions
                which all will be skipped except as critical pattern in the
                log file. If found, return CRITICAL.
            case_insensitive (bool): Do a case insensitive scan.
            encoding (str): Specify the character encoding in the log file.
            warning (int): The number of times found that be needed to return WARNING.
            critical (int): The number of times found that be needed to return CRITICAL.
            trace_inode (bool): Trace the inode of the log file.
            multiline (bool): Treat multiple lines outputed at once as one message.
            scantime (int): The range of time to scan.
            expiration (int): The expiration of seek files.
            cachetime (int): The period to cache the result.
            lock_timeout (int): The period to wait for if another process is running.

        Args:
            config (dict): The dictionary of configuration parameters.

        """
        # set default value
        self.config = {}
        self.config['logformat'] = LogChecker.FORMAT_SYSLOG
        self.config['state_directory'] = None
        self.config['pattern_list'] = []
        self.config['critical_pattern_list'] = []
        self.config['negpattern_list'] = []
        self.config['critical_negpattern_list'] = []
        self.config['case_insensitive'] = False
        self.config['encoding'] = 'utf-8'
        self.config['warning'] = 1
        self.config['critical'] = 0
        self.config['trace_inode'] = False
        self.config['multiline'] = False
        self.config['scantime'] = 86400
        self.config['expiration'] = 691200
        self.config['cachetime'] = 60
        self.config['lock_timeout'] = 3

        # overwrite values with user's values
        for key in self.config:
            if key not in config:
                continue
            value = config[key]
            if isinstance(value, (bool, int)):
                pass
            elif isinstance(value, list):
                value = [LogChecker.to_unicode(x) for x in value]
            else:
                # On python 2.x, str, unicode or None reaches.
                # On python 3.x, bytes, str or None reaches.
                value = LogChecker.to_unicode(value)
            self.config[key] = value

        self.pattern_flags = 0
        if self.config['case_insensitive']:
            self.pattern_flags = re.IGNORECASE

        self.re_logformat = re.compile(LogChecker._expand_logformat_by_strftime(
            self.config['logformat']))

        # status variables
        self.state = None
        self.message = None
        self.messages = []
        self.found = []
        self.found_messages = []
        self.critical_found = []
        self.critical_found_messages = []

    def _check_updated(self, logfile, offset, filesize):
        """Check whether the log file is updated.

        If updated, return True.
        """
        if os.stat(logfile).st_mtime < time.time() - self.config['scantime']:
            _debug("Skipped: mtime < curtime - scantime")
            return False

        if filesize == offset:
            _debug("Skipped: filesize == offset")
            return False

        return True

    def _find_pattern(self, message, negative=False, critical=False):
        """Find pattern.

        If found, return True.
        """
        if negative:
            if critical:
                pattern_list = self.config['critical_negpattern_list']
                pattern_type = "critical_negpattern"
            else:
                pattern_list = self.config['negpattern_list']
                pattern_type = "negpattern"
        else:
            if critical:
                pattern_list = self.config['critical_pattern_list']
                pattern_type = "critical_pattern"
            else:
                pattern_list = self.config['pattern_list']
                pattern_type = "pattern"

        if not pattern_list:
            return False
        for pattern in pattern_list:
            if not pattern:
                continue
            matchobj = re.search(pattern, message, self.pattern_flags)
            if matchobj:
                _debug("{0}: '{1}' found".format(pattern_type, pattern))
                return True
        return False

    def _remove_old_seekfile(self, logfile_pattern_list, tag=''):
        """Remove old seek files."""
        cwd = os.getcwd()
        try:
            os.chdir(self.config['state_directory'])
        except OSError:
            print("Unable to chdir: {0}".format(
                self.config['state_directory']))
            sys.exit(LogChecker.STATE_UNKNOWN)

        curtime = time.time()
        for logfile_pattern in logfile_pattern_list.split():
            if not logfile_pattern:
                continue
            seekfile_pattern = (
                re.sub(r'[^-0-9A-Za-z*?]', '_', logfile_pattern) +
                tag + LogChecker._SUFFIX_SEEK)
            for seekfile in glob.glob(seekfile_pattern):
                if not os.path.isfile(seekfile):
                    continue
                if curtime - self.config['expiration'] <= os.stat(seekfile).st_mtime:
                    continue
                try:
                    _debug("remove seekfile: {0}".format(seekfile))
                    os.unlink(seekfile)
                except OSError:
                    print("Unable to remove old seekfile: {0}".format(
                        seekfile))
                    sys.exit(LogChecker.STATE_UNKNOWN)

        try:
            os.chdir(cwd)
        except OSError:
            print("Unable to chdir: {0}".format(cwd))
            sys.exit(LogChecker.STATE_UNKNOWN)

        return True

    def _remove_old_seekfile_with_inode(self, logfile_pattern, tag=''):
        """Remove old inode-based seek files."""
        prefix = None
        if self.config['trace_inode']:
            prefix = LogChecker.get_digest(logfile_pattern)

        cwd = os.getcwd()
        try:
            os.chdir(self.config['state_directory'])
        except OSError:
            print("Unable to chdir: {0}".format(
                self.config['state_directory']))
            sys.exit(LogChecker.STATE_UNKNOWN)

        curtime = time.time()
        seekfile_pattern = "{0}.[0-9]*{1}{2}".format(
            prefix, tag, LogChecker._SUFFIX_SEEK_WITH_INODE)
        for seekfile in glob.glob(seekfile_pattern):
            if not os.path.isfile(seekfile):
                continue
            if curtime - self.config['expiration'] <= os.stat(seekfile).st_mtime:
                continue
            try:
                _debug("remove seekfile: {0}".format(seekfile))
                os.unlink(seekfile)
            except OSError:
                print("Unable to remove old seekfile: {0}".format(seekfile))
                sys.exit(LogChecker.STATE_UNKNOWN)

        try:
            os.chdir(cwd)
        except OSError:
            print("Unable to chdir: {0}".format(cwd))
            sys.exit(LogChecker.STATE_UNKNOWN)

        return True

    def _get_logfile_list(self, filename_pattern_list):
        """Get the list of log files from pattern of filenames."""
        logfile_list = []
        for filename_pattern in filename_pattern_list.split():
            filename_list = glob.glob(filename_pattern)
            if filename_list:
                logfile_list.extend(filename_list)
        if logfile_list:
            logfile_list = sorted(
                logfile_list, key=lambda x: os.stat(x).st_mtime)
        return logfile_list

    def _update_state(self):
        """Update the state of the result."""
        num_critical = len(self.critical_found)
        if num_critical > 0:
            self.state = LogChecker.STATE_CRITICAL
            self.messages.append("Critical Found {0} lines: {1}".format(
                num_critical, ','.join(self.critical_found_messages)))
        num = len(self.found)
        if num > 0:
            self.messages.append(
                "Found {0} lines (limit={1}/{2}): {3}".format(
                    num, self.config['warning'], self.config['critical'],
                    ','.join(self.found_messages)))
            if self.config['critical'] > 0 and self.config['critical'] <= num:
                if self.state is None:
                    self.state = LogChecker.STATE_CRITICAL
            if self.config['warning'] > 0 and self.config['warning'] <= num:
                if self.state is None:
                    self.state = LogChecker.STATE_WARNING
        if self.state is None:
            self.state = LogChecker.STATE_OK
        return

    def _update_message(self):
        state_string = 'OK'
        message = 'OK - No matches found.'
        if self.state == LogChecker.STATE_WARNING:
            state_string = 'WARNING'
        elif self.state == LogChecker.STATE_CRITICAL:
            state_string = 'CRITICAL'
        if self.state != LogChecker.STATE_OK:
            message = "{0}: {1}".format(state_string, ', '.join(self.messages))
            message = message.replace('|', '(pipe)')
        self.message = message
        return

    def _set_found(self, message, found, critical_found):
        """Set the found and critical_found if matching pattern is found."""
        found_negpattern = self._find_pattern(message, negative=True)
        found_critical_negpattern = self._find_pattern(
            message, negative=True, critical=True)

        if not found_negpattern and not found_critical_negpattern:
            if self._find_pattern(message):
                found.append(message)
        if not found_critical_negpattern:
            if self._find_pattern(message, critical=True):
                critical_found.append(message)
        return

    def _check_each_multiple_lines(
            self, logfile, start_position, found, critical_found):
        """Match the pattern each multiple lines in the log file."""
        line_buffer = []
        pre_key = None
        cur_key = None
        message = None
        cur_message = None

        with io.open(logfile, mode='r', encoding=self.config['encoding'],
                     errors='replace') as fileobj:
            fileobj.seek(start_position, 0)

            for line in fileobj:
                line = line.rstrip()
                _debug("line='{0}'".format(line))

                matchobj = self.re_logformat.match(line)
                # set cur_key and cur_message.
                if matchobj:
                    cur_key = matchobj.group(1)
                    cur_message = matchobj.group(2)
                else:
                    cur_key = pre_key
                    cur_message = line

                if pre_key is None:  # for first iteration
                    pre_key = cur_key
                    line_buffer.append(line)
                elif pre_key == cur_key:
                    line_buffer.append(cur_message)
                else:
                    message = ' '.join(line_buffer)
                    _debug("message='{0}'".format(message))
                    self._set_found(message, found, critical_found)

                    # initialize variables for next loop
                    pre_key = cur_key
                    line_buffer = []
                    line_buffer.append(line)
            end_position = fileobj.tell()
            fileobj.close()

        # flush line buffer
        if line_buffer:
            message = ' '.join(line_buffer)
            _debug("message='{0}'".format(message))
            self._set_found(message, found, critical_found)
        return end_position

    def _check_each_single_line(
            self, logfile, start_position, found, critical_found):
        """Match the pattern each a single line in the log file."""
        with io.open(logfile, mode='r', encoding=self.config['encoding'],
                     errors='replace') as fileobj:
            fileobj.seek(start_position, 0)

            for line in fileobj:
                message = line.rstrip()
                _debug("message='{0}'".format(message))
                self._set_found(message, found, critical_found)
            end_position = fileobj.tell()
            fileobj.close()
        return end_position

    def _create_digest_condition(self, logfile_pattern):
        """Create the digest of search conditions."""
        strings = []
        for key in sorted(self.config):
            if key in ['expiration', 'cachetime', 'lock_timeout']:
                continue
            value = self.config[key]
            if isinstance(value, list):
                strings.append(
                    "{0}={1}".format(key, "\t".join(value)))
            elif isinstance(value, bool):
                strings.append(
                    "{0}={1}".format(key, LogChecker.to_unicode(str(value))))
            elif isinstance(value, int):
                strings.append(
                    "{0}={1}".format(key, LogChecker.to_unicode(str(value))))
            else:
                strings.append("{0}={1}".format(key, value))
        strings.append(logfile_pattern)
        digest_condition = LogChecker.get_digest('\n'.join(strings))
        return digest_condition

    def _create_seek_filename(
            self, logfile_pattern, logfile, trace_inode=False, tag=''):
        """Return the file name of seek file."""
        seekfile = LogChecker.create_seek_filename(
            logfile_pattern, self.config['state_directory'], logfile,
            trace_inode=trace_inode, tag=tag)
        return seekfile

    def _create_cache_filename(self, logfile_pattern, tag=''):
        """Return the file name of cache file."""
        digest_condition = self._create_digest_condition(logfile_pattern)
        filename_elements = []
        filename_elements.append(digest_condition)
        if tag:
            filename_elements.append(".")
            filename_elements.append(tag)
        filename_elements.append(LogChecker._SUFFIX_CACHE)
        cache_filename = os.path.join(
            self.config['state_directory'], "".join(filename_elements))
        return cache_filename

    def _create_lock_filename(self, logfile_pattern, tag=''):
        """Return the file name of lock file."""
        digest_condition = self._create_digest_condition(logfile_pattern)
        filename_elements = []
        filename_elements.append(digest_condition)
        if tag:
            filename_elements.append(".")
            filename_elements.append(tag)
        filename_elements.append(LogChecker._SUFFIX_LOCK)
        lock_filename = os.path.join(
            self.config['state_directory'], "".join(filename_elements))
        return lock_filename

    def check(
            self, logfile_pattern, seekfile=None,
            remove_seekfile=False, tag=''):
        """Check log files.

        If cache is enabled and exists, return cache.

        Args:
            logfile_pattern (str): The file names of log files to be scanned.
            seekfile (str, optional): The file name of the seek file.
            remove_seekfile (bool, optional): If true, remove expired seek files.
            tag (str, optional): The tag added in the file names of state files,
                to prevent names collisions.
        """
        logfile_pattern = LogChecker.to_unicode(logfile_pattern)
        seekfile = LogChecker.to_unicode(seekfile)
        tag = LogChecker.to_unicode(tag)
        cachefile = self._create_cache_filename(logfile_pattern, tag=tag)
        lockfile = self._create_lock_filename(logfile_pattern, tag=tag)

        locked = False
        cur_time = time.time()
        timeout_time = cur_time + self.config['lock_timeout']
        while cur_time < timeout_time:
            if self.config['cachetime'] > 0:
                state, message = self._get_cache(cachefile)
                if state != LogChecker.STATE_NO_CACHE:
                    self.state = state
                    self.message = message
                    return
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                lockfileobj = LogChecker.lock(lockfile)
            if lockfileobj:
                locked = True
                break
            cur_time = time.time()
            time.sleep(LogChecker._RETRY_PERIOD)
        if not locked:
            self.state = LogChecker.STATE_UNKNOWN
            self.message = "UNKNOWN: Lock timeout. Another process is running."
            return

        if LogChecker.is_multiple_logfiles(logfile_pattern):
            self._check_log_multi(
                logfile_pattern, remove_seekfile=remove_seekfile, tag=tag)
        else:
            # create seekfile
            if not seekfile:
                seekfile = self._create_seek_filename(
                    logfile_pattern, logfile_pattern,
                    trace_inode=self.config['trace_inode'], tag=tag)
            self._check_log(logfile_pattern, seekfile)

        if self.config['cachetime'] > 0:
            self._update_cache(cachefile)

        LogChecker.unlock(lockfile, lockfileobj)
        return

    def check_log(self, logfile, seekfile):
        """Check the log file.

        deprecated:: 2.0.1
        Use :func:`check` instead.
        """
        self.check(logfile, seekfile=seekfile)
        return

    def _check_log(self, logfile, seekfile):
        """Check the log file.

        Args:
            logfile (str): The file name of the log file to be scanned.
            seekfile (str): The file name of the seek file.

        """
        _debug("logfile='{0}', seekfile='{1}'".format(logfile, seekfile))
        logfile = LogChecker.to_unicode(logfile)
        if not os.path.exists(logfile):
            return

        filesize = os.path.getsize(logfile)
        # define seek positions.
        start_position = LogChecker._read_seekfile(seekfile)
        end_position = 0
        if not self._check_updated(logfile, start_position, filesize):
            return

        # if log was rotated, set start_position.
        if filesize < start_position:
            start_position = 0

        found = []
        critical_found = []
        if self.config['multiline']:
            end_position = self._check_each_multiple_lines(
                logfile, start_position, found, critical_found)
        else:
            end_position = self._check_each_single_line(
                logfile, start_position, found, critical_found)

        if found:
            self.found.extend(found)
            self.found_messages.append(
                "{0} at {1}".format(','.join(found), logfile))
        if critical_found:
            self.critical_found.extend(critical_found)
            self.critical_found_messages.append(
                "{0} at {1}".format(','.join(critical_found), logfile))

        LogChecker._update_seekfile(seekfile, end_position)
        return

    def check_log_multi(
            self, logfile_pattern, state_directory,
            remove_seekfile=False, tag=''):
        """Check the multiple log files.

        deprecated:: 2.0.1
        Use :func:`check` instead.
        """
        state_directory = state_directory  # not used
        self.check(logfile_pattern, remove_seekfile=remove_seekfile, tag=tag)

    def _check_log_multi(self, logfile_pattern, remove_seekfile=False, tag=''):
        """Check the multiple log files.

        Args:
            logfile_pattern (str): The file names of log files to be scanned.
            remove_seekfile (bool, optional): If true, remove expired seek files.
            tag (str, optional): The tag added in the file names of state files,
                to prevent names collisions.

        """
        logfile_list = self._get_logfile_list(logfile_pattern)
        for logfile in logfile_list:
            if not os.path.isfile(logfile):
                continue
            seekfile = self._create_seek_filename(
                logfile_pattern, logfile,
                trace_inode=self.config['trace_inode'], tag=tag)
            self._check_log(logfile, seekfile)

        if remove_seekfile:
            if self.config['trace_inode']:
                self._remove_old_seekfile_with_inode(logfile_pattern, tag)
            else:
                self._remove_old_seekfile(logfile_pattern, tag)
        return

    def clear_state(self):
        """Clear the state of the result."""
        self.state = None
        self.message = None
        self.messages = []
        self.found = []
        self.found_messages = []
        self.critical_found = []
        self.critical_found_messages = []
        return

    def get_state(self):
        """Get the state of the result.

        When get_state() or get_message() is executed,
        the state is retained until clear_state() is executed.
        """
        if self.state is None:
            self._update_state()
        return self.state

    def get_message(self):
        """Get the message of the result.

        When get_state() or get_message() is executed,
        the message is retained until clear_state() is executed.
        """
        if self.state is None:
            self._update_state()
        if self.message is None:
            self._update_message()
        return self.message

    def _get_cache(self, cachefile):
        """Get the cache."""
        if not os.path.exists(cachefile):
            return LogChecker.STATE_NO_CACHE, None
        if os.stat(cachefile).st_mtime < time.time() - self.config['cachetime']:
            _debug("Cache is expired: mtime < curtime - cachetime")
            return LogChecker.STATE_NO_CACHE, None
        with io.open(cachefile, mode='r', encoding='utf-8') as fileobj:
            line = fileobj.readline()
            fileobj.close()
        state, message = line.split("\t", 1)
        _debug("cache: state={0}, message='{1}'".format(state, message))
        return int(state), message

    def _update_cache(self, cachefile):
        """Update the cache."""
        tmp_cachefile = cachefile + "." + str(os.getpid())
        with io.open(tmp_cachefile, mode='w', encoding='utf-8') as cachefileobj:
            cachefileobj.write(LogChecker.to_unicode(str(self.get_state())))
            cachefileobj.write("\t")
            cachefileobj.write(self.get_message())
            cachefileobj.flush()
            cachefileobj.close()
        os.rename(tmp_cachefile, cachefile)
        return True

    def _remove_cache(self, cachefile):
        """Remove the cache file."""
        if os.path.isfile(cachefile):
            os.unlink(cachefile)

    @staticmethod
    def get_pattern_list(pattern_string, pattern_filename):
        """Get the pattern list.

        Args:
            pattern_string (str): The pattern to scan for.
            pattern_filename (str): The file name of file containing patterns.

        Returns:
            The list of patterns.

        """
        pattern_list = []
        if pattern_string:
            pattern_list.append(pattern_string)
        if pattern_filename:
            if os.path.isfile(pattern_filename):
                lines = []
                with io.open(pattern_filename, mode='r', encoding='utf-8') as fileobj:
                    for line in fileobj:
                        pattern = line.rstrip()
                        if pattern:
                            lines.append(pattern)
                    fileobj.close()
                if lines:
                    pattern_list.extend(lines)
        return pattern_list

    @staticmethod
    def _expand_logformat_by_strftime(logformat):
        """Expand log format by strftime variables.

        Args:
            logformat (str): The string of log format.

        Returns:
            The string expanded by strftime().

        """
        for item in LogChecker._LOGFORMAT_EXPANSION_LIST:
            key = list(item)[0]
            logformat = logformat.replace(key, item[key])
        return logformat

    @staticmethod
    def create_seek_filename(
            logfile_pattern, state_directory, logfile,
            trace_inode=False, tag=''):
        """Make filename of seekfile from logfile and get the filename.

        Args:
            logfile_pattern (str): The pattern of the file names of the log files.
            state_directory (str): The state directory.
            logfile (str): The file name of the log file.
            trace_inode (bool): Whether it traces inode information.
            tag (str): The tag.

        Returns:
            The file name of the seek file.

        """
        prefix = None
        filename = None
        if trace_inode:
            filename = (str(os.stat(logfile).st_ino) +
                        tag + LogChecker._SUFFIX_SEEK_WITH_INODE)
            prefix = LogChecker.get_digest(logfile_pattern)
        else:
            filename = (re.sub(r'[^-0-9A-Za-z]', '_', logfile) +
                        tag + LogChecker._SUFFIX_SEEK)
        if prefix:
            filename = prefix + '.' + filename
        seekfile = os.path.join(state_directory, filename)
        return seekfile

    @staticmethod
    def _update_seekfile(seekfile, position):
        """Update the seek file for the log file."""
        tmp_seekfile = seekfile + "." + str(os.getpid())
        with io.open(tmp_seekfile, mode='w', encoding='utf-8') as fileobj:
            fileobj.write(LogChecker.to_unicode(str(position)))
            fileobj.flush()
            fileobj.close()
        os.rename(tmp_seekfile, seekfile)
        return True

    @staticmethod
    def _read_seekfile(seekfile):
        """Read the offset of the log file from its seek file."""
        if not os.path.exists(seekfile):
            return 0
        with io.open(seekfile, mode='r', encoding='utf-8') as fileobj:
            offset = int(fileobj.readline())
            fileobj.close()
        return offset

    @staticmethod
    def lock(lockfile):
        """Lock.

        Args:
            lockfile (str): The file name of the lock file.

        Returns:
            The instance of the object of the lock file.
            If lock fails, return None.

        """
        lockfileobj = io.open(lockfile, mode='w')
        try:
            fcntl.flock(lockfileobj, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            return None
        lockfileobj.flush()
        return lockfileobj

    @staticmethod
    def unlock(lockfile, lockfileobj):
        """Unlock.

        Args:
            lockfile (str): The file name of the lock file.
            lockfileobj (file): The instance of the object of the lock file.

        Returns:
            True if unlock successes.

        """
        if lockfileobj is None:
            return False
        lockfileobj.close()
        if os.path.isfile(lockfile):
            os.unlink(lockfile)
        return True

    @staticmethod
    def get_digest(string):
        """Get digest string.

        Args:
            string (str): The string to be digested.

        Returns:
            The string of digest.

        """
        hashobj = hashlib.sha1()
        hashobj.update(LogChecker.to_bytes(string))
        digest = LogChecker.to_unicode(
            base64.urlsafe_b64encode(hashobj.digest()))
        return digest

    @staticmethod
    def is_multiple_logfiles(logfile_pattern):
        """Whether the pattern of the log file names is multiple files.

        Args:
            logfile_pattern (str): The pattern of the file names of log files.

        Returns:
            True if the string of the log file pattern is multiple log files.

        """
        matchobj = re.search('[*? ]', logfile_pattern)
        if matchobj:
            return True
        return False

    @staticmethod
    def to_unicode(string):
        """Convert str to unicode.

        Args:
            string (str or bytes): The string or bytes to convert to unicode string.

        Returns:
            The unicode string to be converted.

        """
        if sys.version_info >= (3,):
            if isinstance(string, bytes):
                # convert bytes to str.
                return string.decode('utf-8')
        else:
            if isinstance(string, str):
                # convert str to unicode.
                return string.decode('utf-8')
        return string

    @staticmethod
    def to_bytes(string):
        """Convert str to bytes.

        Args:
            string (str): The string to convert to bytes.

        Returns:
            The bytes to be converted.

        """
        if sys.version_info >= (3,):
            if isinstance(string, str):
                # convert str to bytes.
                return string.encode('utf-8')
        else:
            if not isinstance(string, str):
                # convert unicode to str.
                return string.encode('utf-8')
        return string


def _debug(string):
    if not __debug__:
        print("DEBUG: {0}".format(string))


def _make_parser():
    parser = argparse.ArgumentParser(
        description="A log file regular expression-based parser plugin for Nagios.",
        usage=("%(prog)s [options] [-p <pattern>|-P <filename>] "
               "-S <directory> -l <filename>"))
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s {0}".format(__version__)
    )
    parser.add_argument(
        "-l", "--logfile",
        action="store",
        dest="logfile_pattern",
        required=True,
        metavar="<filename>",
        help=("The file names of log files to be scanned. "
              "The metacharacters * and ? are available. "
              "To set multiple files, set a space between file names. "
              "See also --scantime.")
    )
    parser.add_argument(
        "-F", "--format",
        action="store",
        dest="logformat",
        metavar="<format>",
        default=LogChecker.FORMAT_SYSLOG,
        help=("Regular expression for log format. "
              "It requires two groups in format of '^(TIMESTAMP and TAG)(.*)$'. "
              "Also, it may use %%%%, %%Y, %%y, %%a, %%b, %%m, %%d, %%e, %%H, "
              "%%M, %%S, %%F and %%T of strftime(3). "
              "(default: regular expression for syslog.")
    )
    parser.add_argument(
        "-s", "--seekfile",
        action="store",
        dest="seekfile",
        metavar="<filename>",
        help=("Deprecated. Use -S option instead. "
              "The file name of the file to store the seek position of the last scan. ")
    )
    parser.add_argument(
        "-S", "--state-directory", "--seekfile-directory",
        action="store",
        dest="state_directory",
        metavar="<directory>",
        help=("The directory to store seek files, cache file and lock file. "
              "'--seekfile-directory' is for backwards compatibility.")
    )
    parser.add_argument(
        "-T", "--tag", "--seekfile-tag",
        action="store",
        dest="tag",
        default="",
        metavar="<tag>",
        help=("Add a tag in the file names of state files, to prevent names collisions. "
              "Useful to avoid maintaining many '-S' directories "
              "when you check the same files several times with different args. "
              "'--seekfile-tag' is for backwards compatibility.")
    )
    parser.add_argument(
        "-I", "--trace-inode",
        action="store_true",
        dest="trace_inode",
        default=False,
        help=("If set, trace the inode of the log file. "
              "After log rotatation, you can trace the log file.")
    )
    parser.add_argument(
        "-p", "--pattern",
        action="store",
        dest="pattern",
        metavar="<pattern>",
        help="The regular expression to scan for in the log file."
    )
    parser.add_argument(
        "-P", "--patternfile",
        action="store",
        dest="patternfile",
        metavar="<filename>",
        help="The file name of the file containing regular expressions, one per line. "
    )
    parser.add_argument(
        "--critical-pattern",
        action="store",
        dest="critical_pattern",
        metavar="<pattern>",
        help=("The regular expression to scan for in the log file. "
              "If found, return CRITICAL.")
    )
    parser.add_argument(
        "--critical-patternfile",
        action="store",
        dest="critical_patternfile",
        metavar="<filename>",
        help=("The file name of the file containing regular expressions, one per line. "
              "If found, return CRITICAL.")
    )
    parser.add_argument(
        "-n", "--negpattern",
        action="store",
        dest="negpattern",
        metavar="<pattern>",
        help=("The regular expression which all will be skipped except as critical pattern "
              "in the log file.")
    )
    parser.add_argument(
        "-N", "-f", "--negpatternfile",
        action="store",
        dest="negpatternfile",
        metavar="<filename>",
        help=("The file name of the file containing regular expressions "
              "which all will be skipped except as critical pattern, "
              "one per line. "
              "'-f' is for backwards compatibility.")
    )
    parser.add_argument(
        "--critical-negpattern",
        action="store",
        dest="critical_negpattern",
        metavar="<pattern>",
        help="The regular expression which all will be skipped in the log file."
    )
    parser.add_argument(
        "--critical-negpatternfile",
        action="store",
        dest="critical_negpatternfile",
        metavar="<filename>",
        help=("The file name of the file containing regular expressions "
              "which all will be skipped, one per line.")
    )
    parser.add_argument(
        "-i", "--case-insensitive",
        action="store_true",
        dest="case_insensitive",
        default=False,
        help="Do a case insensitive scan."
    )
    parser.add_argument(
        "--encoding",
        action="store",
        dest="encoding",
        default='utf-8',
        metavar="<encoding>",
        help=("Specify the character encoding in the log file. "
              "(default: %(default)s)")
    )
    parser.add_argument(
        "-w", "--warning",
        action="store",
        type=int,
        dest="warning",
        default=1,
        metavar="<number>",
        help=("Return WARNING if at least this many matches found. "
              "(default: %(default)s)")
    )
    parser.add_argument(
        "-c", "--critical",
        action="store",
        type=int,
        dest="critical",
        default=0,
        metavar="<number>",
        help=("Return CRITICAL if at least this many matches found. "
              "i.e. don't return critical alerts unless specified explicitly. "
              "(default: %(default)s)")
    )
    parser.add_argument(
        "-t", "--scantime",
        action="store",
        type=int,
        dest="scantime",
        default=86400,
        metavar="<seconds>",
        help=("The range of time to scan. "
              "The log files older than this time are not scanned. "
              "(default: %(default)s)")
    )
    parser.add_argument(
        "-E", "--expiration",
        action="store",
        type=int,
        dest="expiration",
        default=691200,
        metavar="<seconds>",
        help=("The expiration of seek files. "
              "This must be longer than the log rotation period. "
              "The expired seek files are deleted with -R option. "
              "(default: %(default)s)")
    )
    parser.add_argument(
        "-R", "--remove-seekfile",
        action="store_true",
        dest="remove_seekfile",
        default=False,
        help="Remove expired seek files. See also --expiration."
    )
    parser.add_argument(
        "-M", "--multiline",
        action="store_true",
        dest="multiline",
        default=False,
        help=("Treat multiple lines outputed at once as one message. "
              "See also --format.")
    )
    parser.add_argument(
        "--cachetime",
        action="store",
        type=int,
        dest="cachetime",
        default=60,
        metavar="<seconds>",
        help=("The period to cache the result. "
              "To disable this cache feature, set '0'. "
              "(default: %(default)s)")
    )
    parser.add_argument(
        "--lock-timeout",
        action="store",
        type=int,
        dest="lock_timeout",
        default=3,
        metavar="<seconds>",
        help=("The period to wait for if another process is running. "
              "If timeout occurs, UNKNOWN is returned. "
              "(default: %(default)s)")
    )
    return parser


def _check_parser_args(parser):
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(LogChecker.STATE_UNKNOWN)

    # check args
    if not args.logfile_pattern:
        parser.exit(
            LogChecker.STATE_UNKNOWN,
            "the following arguments are required: -l/--logfile")

    if args.state_directory:
        if not os.path.isdir(args.state_directory):
            parser.exit(
                LogChecker.STATE_UNKNOWN,
                "the state directory is not found: {0}".format(
                    args.state_directory))
        if (args.seekfile and
                os.path.dirname(args.seekfile) != args.state_directory):
            parser.exit(
                LogChecker.STATE_UNKNOWN,
                "the seek file is outside the state directory: {0}".format(
                    args.seekfile))
    else:
        if args.seekfile:
            state_directory = os.path.dirname(args.seekfile)
            if not os.path.isdir(state_directory):
                parser.exit(
                    LogChecker.STATE_UNKNOWN,
                    "the state directory is not found: {0}".format(
                        state_directory))
        else:
            parser.exit(
                LogChecker.STATE_UNKNOWN,
                "the following arguments are required: -S/--state-directory")

    if args.seekfile:
        if LogChecker.is_multiple_logfiles(args.logfile_pattern):
            parser.exit(
                LogChecker.STATE_UNKNOWN,
                "If check multiple log files, use arguments -s/--seekfile.")
        else:
            if not os.path.isfile(args.logfile_pattern):
                parser.exit(
                    LogChecker.STATE_UNKNOWN,
                    "the log file is not found: {0}".format(
                        args.logfile_pattern))

    pattern_list = LogChecker.get_pattern_list(args.pattern, args.patternfile)
    critical_pattern_list = LogChecker.get_pattern_list(
        args.critical_pattern, args.critical_patternfile)
    if not pattern_list and not critical_pattern_list:
        parser.exit(
            LogChecker.STATE_UNKNOWN,
            "any valid patterns are not found.")

    return args


def _generate_config(args):
    """Generate initial data."""
    if args.seekfile and not args.state_directory:
        state_directory = os.path.dirname(args.seekfile)
    else:
        state_directory = args.state_directory

    # make pattern list
    pattern_list = LogChecker.get_pattern_list(args.pattern, args.patternfile)
    critical_pattern_list = LogChecker.get_pattern_list(
        args.critical_pattern, args.critical_patternfile)
    negpattern_list = LogChecker.get_pattern_list(
        args.negpattern, args.negpatternfile)
    critical_negpattern_list = LogChecker.get_pattern_list(
        args.critical_negpattern, args.critical_negpatternfile)

    # set value of args
    config = {
        "logformat": args.logformat,
        "state_directory": state_directory,
        "pattern_list": pattern_list,
        "critical_pattern_list": critical_pattern_list,
        "negpattern_list": negpattern_list,
        "critical_negpattern_list": critical_negpattern_list,
        "case_insensitive": args.case_insensitive,
        "encoding": args.encoding,
        "warning": args.warning,
        "critical": args.critical,
        "trace_inode": args.trace_inode,
        "multiline": args.multiline,
        "scantime": args.scantime,
        "expiration": args.expiration,
        "cachetime": args.cachetime,
        "lock_timeout": args.lock_timeout
    }
    return config


def main():
    """Run check_log_ng."""
    parser = _make_parser()
    args = _check_parser_args(parser)
    config = _generate_config(args)
    log = LogChecker(config)
    log.check(
        args.logfile_pattern, seekfile=args.seekfile,
        remove_seekfile=args.remove_seekfile, tag=args.tag)
    state = log.get_state()
    print(log.get_message())
    sys.exit(state)


if __name__ == "__main__":
    main()

# vim: set ts=4 sw=4 et:
