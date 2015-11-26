#!/usr/bin/python
# coding: utf-8
# Python 2.4 - 2.7
import sys
import os
import glob
import time
import re
import base64
from optparse import OptionParser

# Globals
CHECK_LOG_NG_VERSION = '1.0.8'
debug = False


def _debug(string):
    if debug:
        print "DEBUG: %s" % string


class LogChecker:

    """LogChecker."""

    # Class constant
    STATE_OK = 0
    STATE_WARNING = 1
    STATE_CRITICAL = 2
    STATE_UNKNOWN = 3
    STATE_DEPENDENT = 4
    FORMAT_SYSLOG = '^((?:%b\s%e\s%T|%FT%T\S*)\s[-_0-9A-Za-z.]+\s(?:[^ :\[\]]+(?:\[\d+?\])?:\s)?)(.*)$'
    SUFFIX_SEEK = ".seek"
    SUFFIX_SEEK_WITH_INODE = ".inode.seek"

    def __init__(self, initial_data):
        """Constructor.

        Initialization of instance variable.
        """
        self.logformat = LogChecker.FORMAT_SYSLOG
        self.pattern_list = []
        self.critical_pattern_list = []
        self.negative_pattern_list = []
        self.critical_negative_pattern_list = []
        self.case_insensitive = False
        self.warning = 1
        self.critical = 0
        self.nodiff_warn = False
        self.nodiff_crit = False
        self.trace_inode = False
        self.multiline = False
        self.scantime = 86400
        self.expiration = 691200

        # set initial_data
        for key in initial_data:
            setattr(self, key, initial_data[key])

        self.pattern_flags = 0
        if self.case_insensitive:
            self.pattern_flags = re.IGNORECASE

        self.re_logformat = re.compile(LogChecker.expand_format_by_strftime(self.logformat))

        self.clear_state()

    def _check_updated(self, logfile, offset, filesize):
        """Check whether the log file is updated.

        If updated, return True.
        """
        if os.stat(logfile).st_mtime < time.time() - self.scantime:
            _debug("Skipped: mtime < curtime - scantime")
            return False

        if filesize == offset:
            _debug("Skipped: filesize == offset")
            return False

        return True

    def _check_negative_pattern(self, line):
        """Check whether the line matches negative pattern.

        If matched, return True.
        """
        if len(self.negpattern_list) == 0:
            return False
        for negpattern in self.negpattern_list:
            if negpattern is None or negpattern == '':
                continue
            m = re.search(negpattern, line, self.pattern_flags)
            if m is not None:
                _debug("Skip cause '%s'" % (negpattern))
                return True
        return False

    def _check_critical_negative_pattern(self, line):
        """Check whether the line matches critical negative pattern.

        If matched, return True.
        """
        if len(self.critical_negpattern_list) == 0:
            return False
        for critical_negpattern in self.critical_negpattern_list:
            if critical_negpattern is None or critical_negpattern == '':
                continue
            m = re.search(critical_negpattern, line, self.pattern_flags)
            if m is not None:
                _debug("Skip cause '%s'" % (critical_negpattern))
                return True
        return False

    def _find_pattern(self, line):
        """Find pattern.

        If found, return True.
        """
        if len(self.pattern_list) == 0:
            return False
        for pattern in self.pattern_list:
            if pattern is None or pattern == '':
                continue
            m = re.search(pattern, line, self.pattern_flags)
            if m is not None:
                _debug("'%s' found" % (pattern))
                return True
        return False

    def _find_critical_pattern(self, line):
        """Find critical pattern.

        If found, return True.
        """
        if len(self.critical_pattern_list) == 0:
            return False
        for pattern in self.critical_pattern_list:
            if pattern is None or pattern == '':
                continue
            m = re.search(pattern, line, self.pattern_flags)
            if m is not None:
                _debug("'%s' found as CRITICAL" % (pattern))
                return True
        return False

    def _remove_old_seekfile(self, seekfile_directory, logfile_pattern_list):
        """Remove old seek files."""
        cwd = os.getcwd()
        try:
            os.chdir(seekfile_directory)
        except OSError:
            print "Unable to chdir seekfile_directory: %s" % (seekfile_directory)
            sys.exit(LogChecker.STATE_UNKNOWN)

        curtime = time.time()
        for logfile_pattern in logfile_pattern_list.split():
            if logfile_pattern is None or logfile_pattern == '':
                continue
            seekfile_pattern = re.sub(r'[^-0-9A-Za-z*?]', '_', logfile_pattern) + LogChecker.SUFFIX_SEEK
            for seekfile in glob.glob(seekfile_pattern):

                if not os.path.isfile(seekfile):
                    continue
                if curtime - self.expiration <= os.stat(seekfile).st_mtime:
                    continue
                try:
                    _debug("remove seekfile: %s" % seekfile)
                    os.unlink(seekfile)
                except OSError:
                    print "Unable to remove old seekfile: %s" % (seekfile)
                    sys.exit(LogChecker.STATE_UNKNOWN)

        try:
            os.chdir(cwd)
        except OSError:
            print "Unable to chdir: %s" % (cwd)
            sys.exit(LogChecker.STATE_UNKNOWN)

        return True

    def _remove_old_seekfile_with_inode(self, logfile_pattern, seekfile_directory):
        """Remove old inode-based seek files."""
        prefix = None
        if self.trace_inode:
            prefix = LogChecker.get_digest(logfile_pattern)

        cwd = os.getcwd()
        try:
            os.chdir(seekfile_directory)
        except OSError:
            print "Unable to chdir seekfile_directory: %s" % (seekfile_directory)
            sys.exit(LogChecker.STATE_UNKNOWN)

        curtime = time.time()
        seekfile_pattern = prefix + '.[0-9]*' + LogChecker.SUFFIX_SEEK_WITH_INODE
        for seekfile in glob.glob(seekfile_pattern):
            if not os.path.isfile(seekfile):
                continue
            if curtime - self.expiration <= os.stat(seekfile).st_mtime:
                continue
            try:
                _debug("remove seekfile: %s" % seekfile)
                os.unlink(seekfile)
            except OSError:
                print "Unable to remove old seekfile: %s" % (seekfile)
                sys.exit(LogChecker.STATE_UNKNOWN)

        try:
            os.chdir(cwd)
        except OSError:
            print "Unable to chdir: %s" % (cwd)
            sys.exit(LogChecker.STATE_UNKNOWN)

        return True

    def _get_logfile_list(self, filename_pattern_list):
        """Get the list of log files from pattern of filenames."""
        logfile_list = []
        for filename_pattern in filename_pattern_list.split():
            list = glob.glob(filename_pattern)
            if len(list) > 0:
                logfile_list.extend(list)
        if len(logfile_list) > 0:
            logfile_list = sorted(logfile_list, key=lambda x: os.stat(x).st_mtime)
        return logfile_list

    def _update_state(self):
        """Update the state of the result."""
        num_critical = len(self.critical_found)
        if 0 < num_critical:
            self.state = LogChecker.STATE_CRITICAL
            self.messages.append("Critical Found %s lines: %s" %
                                 (num_critical, ','.join(self.critical_found_messages)))
        num = len(self.found)
        if 0 < num:
            self.messages.append("Found %s lines (limit=%s/%s): %s" %
                                 (num, self.warning, self.critical, ','.join(self.found_messages)))
            if 0 < self.critical and self.critical <= num:
                if self.state is None:
                    self.state = LogChecker.STATE_CRITICAL
            if 0 < self.warning and self.warning <= num:
                if self.state is None:
                    self.state = LogChecker.STATE_WARNING
        if self.state is None:
            self.state = LogChecker.STATE_OK
        return

    def _set_found(self, message, found, critical_found):
        """Set the found and critical_found if matching pattern is found."""
        if (not self._check_negative_pattern(message)) and (not self._check_critical_negative_pattern(message)):
            if self._find_pattern(message):
                found.append(message)
        if not self._check_critical_negative_pattern(message):
            if self._find_critical_pattern(message):
                critical_found.append(message)
        return

    def _pattern_matching_each_multiple_lines(self, logfile, start_position, found, critical_found):
        """Match the pattern each multiple lines in the log file."""
        line_buffer = []
        pre_key = None
        cur_key = None
        message = None
        cur_message = None

        f = open(logfile, 'r')
        f.seek(start_position, 0)

        for line in f:
            line = line.rstrip()
            _debug("line='%s'" % line)

            m = self.re_logformat.match(line)
            # set cur_key and cur_message.
            if m is not None:
                cur_key = m.group(1)
                cur_message = m.group(2)
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
                _debug("message='%s'" % message)
                self._set_found(message, found, critical_found)

                # initialize variables for next loop
                pre_key = cur_key
                line_buffer = []
                line_buffer.append(line)
        end_position = f.tell()
        f.close()

        # flush line buffer
        if len(line_buffer) > 0:
            message = ' '.join(line_buffer)
            _debug("message='%s'" % message)
            self._set_found(message, found, critical_found)
        return end_position

    def _pattern_matching_each_single_line(self, logfile, start_position, found, critical_found):
        """Match the pattern each a single line in the log file."""
        f = open(logfile, 'r')
        f.seek(start_position, 0)

        for line in f:
            message = line.rstrip()
            _debug("message='%s'" % message)
            self._set_found(message, found, critical_found)
        end_position = f.tell()
        f.close()
        return end_position

    def check_log(self, logfile, seekfile):
        """Check the log file."""
        _debug("logfile='%s', seekfile='%s'" % (logfile, seekfile))
        if not os.path.exists(logfile):
            return False

        filesize = os.path.getsize(logfile)
        # define seek positions.
        start_position = LogChecker.read_seekfile(seekfile)
        end_position = 0
        if not self._check_updated(logfile, start_position, filesize):
            return False

        # if log was rotated, set start_position.
        if filesize < start_position:
            start_position = 0

        found = []
        critical_found = []
        if self.multiline:
            end_position = self._pattern_matching_each_multiple_lines(logfile, start_position, found, critical_found)
        else:
            end_position = self._pattern_matching_each_single_line(logfile, start_position, found, critical_found)

        if len(found) > 0:
            self.found.extend(found)
            self.found_messages.append("%s at %s" % (','.join(found), logfile))
        if len(critical_found) > 0:
            self.critical_found.extend(critical_found)
            self.critical_found_messages.append("%s at %s" % (','.join(critical_found), logfile))

        LogChecker.update_seekfile(seekfile, end_position)
        return

    def check_log_multi(self, logfile_pattern, seekfile_directory, remove_seekfile=False):
        """Check the multiple log files."""
        logfile_list = self._get_logfile_list(logfile_pattern)
        for logfile in logfile_list:
            if not os.path.isfile(logfile):
                continue
            seekfile = LogChecker.get_seekfile(logfile_pattern, seekfile_directory, logfile,
                                               trace_inode=self.trace_inode)
            self.check_log(logfile, seekfile)

        if remove_seekfile:
            if self.trace_inode:
                self._remove_old_seekfile_with_inode(logfile_pattern, seekfile_directory)
            else:
                self._remove_old_seekfile(seekfile_directory, logfile_pattern)

    def clear_state(self):
        """Clear the state of the result."""
        self.state = None
        self.messages = []
        self.found = []
        self.found_messages = []
        self.critical_found = []
        self.critical_found_messages = []
        return

    def get_state(self):
        """Get the state of the result."""
        if self.state is None:
            self._update_state()
        return self.state

    def get_message(self):
        """Get the message of the result."""
        if self.state is None:
            self._update_state()
        state_string = 'OK'
        message = 'OK - No matches found.'
        if self.state == LogChecker.STATE_WARNING:
            state_string = 'WARNING'
        elif self.state == LogChecker.STATE_CRITICAL:
            state_string = 'CRITICAL'
        if self.state != LogChecker.STATE_OK:
            message = "%s: %s" % (state_string, ', '.join(self.messages))
        return message

    @classmethod
    def get_pattern_list(cls, pattern_string, pattern_filename):
        """Get the pattern list."""
        pattern_list = []
        if pattern_string:
            pattern_list.append(pattern_string)
        if pattern_filename:
            if os.path.isfile(pattern_filename):
                lines = []
                f = open(pattern_filename, 'r')
                for line in f:
                    line = line.rstrip()
                    lines.append(line)
                if len(lines) > 0:
                    pattern_list.extend(lines)
        return pattern_list

    @classmethod
    def expand_format_by_strftime(cls, format):
        format = format.replace('%%', '_PERCENT_') \
            .replace('%F', '%Y-%m-%d') \
            .replace('%T', '%H:%M:%S') \
            .replace('%a', '(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)') \
            .replace('%b', '(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)') \
            .replace('%Y', '20[0-9][0-9]') \
            .replace('%y', '[0-9][0-9]') \
            .replace('%m', '(?:0[1-9]|1[0-2])') \
            .replace('%d', '(?:0[1-9]|[12][0-9]|3[01])') \
            .replace('%e', '(?: [1-9]|[12][0-9]|3[01])') \
            .replace('%H', '(?:[01][0-9]|2[0-3])') \
            .replace('%M', '[0-5][0-9]') \
            .replace('%S', '(?:[0-5][0-9]|60)') \
            .replace('_PERCENT_', '%')
        return format

    @classmethod
    def get_seekfile(cls, logfile_pattern, seekfile_directory, logfile, trace_inode=False):
        """make filename of seekfile from logfile and get the filename."""
        prefix = None
        filename = None
        if trace_inode:
            filename = str(os.stat(logfile).st_ino) + LogChecker.SUFFIX_SEEK_WITH_INODE
            prefix = LogChecker.get_digest(logfile_pattern)
        else:
            filename = re.sub(r'[^-0-9A-Za-z]', '_', logfile) + LogChecker.SUFFIX_SEEK
        if prefix is not None:
            filename = prefix + '.' + filename
        seekfile = os.path.join(seekfile_directory, filename)
        return seekfile

    @classmethod
    def update_seekfile(cls, seekfile, position):
        """Update the seek file for the log file."""
        tmp_seekfile = seekfile + "." + str(os.getpid)
        f = open(tmp_seekfile, 'w')
        f.write(str(position))
        f.flush()
        f.close()
        os.rename(tmp_seekfile, seekfile)
        return True

    @classmethod
    def read_seekfile(cls, seekfile):
        """Read the offset of the log file from its seek file."""
        if not os.path.exists(seekfile):
            return 0
        f = open(seekfile)
        offset = int(f.readline())
        f.close()
        return offset

    @classmethod
    def get_digest(cls, string):
        """Get digest string."""
        m = None
        try:
            # for Python 2.5-2.7
            import hashlib
            m = hashlib.sha1()
        except:
            try:
                # for Python 2.4
                import sha
                m = sha.new()
            except:
                pass

        digest = None
        if m is not None:
            m.update(string)
            digest = base64.urlsafe_b64encode(m.digest())
        else:
            digest = base64.urlsafe_b64encode(string)
        return digest

    @classmethod
    def make_parser(cls):
        usage = "Usage: %prog [option ...]"
        version = "%%prog %s" % (CHECK_LOG_NG_VERSION)
        parser = OptionParser(usage=usage, version=version)

        parser.add_option("-l", "--logfile",
                          action="store",
                          dest="logfile_pattern",
                          metavar="<filename>",
                          help="The pattern of log files to be scanned. The metacharacter * and ? are allowed. If you want to set multiple patterns, set a space between patterns.")
        parser.add_option("-F", "--format",
                          action="store",
                          dest="logformat",
                          metavar="<format>",
                          default=LogChecker.FORMAT_SYSLOG,
                          help="The regular expression of format of log to parse. Required two group, format of '^(TIMESTAMP and TAG)(.*)$'. Also, may use %%, %Y, %y, %a, %b, %m, %d, %e, %H, %M, %S, %F and %T of strftime(3). Default: the regular expression for syslog.")
        parser.add_option("-s", "--seekfile",
                          action="store",
                          dest="seekfile",
                          metavar="<filename>",
                          help="The temporary file to store the seek position of the last scan. If check multiple log files, ignore this option. Use -S seekfile_directory.")
        parser.add_option("-S", "--seekfile-directory",
                          action="store",
                          dest="seekfile_directory",
                          metavar="<seekfile_directory>",
                          help="The directory of the temporary file to store the seek position of the last scan. If check multiple log files, require this option.")
        parser.add_option("-I", "--trace-inode",
                          action="store_true",
                          dest="trace_inode",
                          default=False,
                          help="Trace the inode of log files. If set, use inode information as a seek file.")
        parser.add_option("-p", "--pattern",
                          action="store",
                          dest="pattern",
                          metavar="<pattern>",
                          help="The regular expression to scan for in the log file.")
        parser.add_option("-P", "--patternfile",
                          action="store",
                          dest="patternfile",
                          metavar="<filename>",
                          help="File containing regular expressions, one per line.")
        parser.add_option("--critical-pattern",
                          action="store",
                          dest="critical_pattern",
                          metavar="<pattern>",
                          help="The regular expression to scan for in the log file. In spite of --critical option, return CRITICAL.")
        parser.add_option("--critical-patternfile",
                          action="store",
                          dest="critical_patternfile",
                          metavar="<filename>",
                          help="File containing regular expressions, one per line. In spite of --critical option, return CRITICAL.")
        parser.add_option("-n", "--negpattern",
                          action="store",
                          dest="negpattern",
                          metavar="<pattern>",
                          help="The regular expression to skip except as critical pattern in the log file.")
        parser.add_option("-N", "-f", "--negpatternfile",
                          action="store",
                          dest="negpatternfile",
                          metavar="<filename>",
                          help="Specifies a file with regular expressions which all will be skipped except as critical pattern, one per line.")
        parser.add_option("--critical-negpattern",
                          action="store",
                          dest="critical_negpattern",
                          metavar="<pattern>",
                          help="The regular expression to skip in the log file")
        parser.add_option("--critical-negpatternfile",
                          action="store",
                          dest="critical_negpatternfile",
                          metavar="<filename>",
                          help="Specifies a file with regular expressions which all will be skipped, one per line.")
        parser.add_option("-i", "--case-insensitive",
                          action="store_true",
                          dest="case_insensitive",
                          default=False,
                          help="Do a case insensitive scan")
        parser.add_option("-w", "--warning",
                          action="store",
                          type="int",
                          dest="warning",
                          default=1,
                          metavar="<number>",
                          help="Return WARNING if at least this many matches found.  The default is %default.")
        parser.add_option("-c", "--critical",
                          action="store",
                          type="int",
                          dest="critical",
                          default=0,
                          metavar="<number>",
                          help="Return CRITICAL if at least this many matches found.  The default is %default, i.e. don't return critical alerts unless specified explicitly.")
        parser.add_option("-d", "--nodiff-warn",
                          action="store_true",
                          dest="nodiff_warn",
                          default=False,
                          help="Return WARNING if the log file was not written to since the last scan. (not implemented)")
        parser.add_option("-D", "--nodiff-crit",
                          action="store_true",
                          dest="nodiff_crit",
                          default=False,
                          help="Return CRITICAL if the log was not written to since the last scan. (not impremented)")
        parser.add_option("-t", "--scantime",
                          action="store",
                          type="int",
                          dest="scantime",
                          default=86400,
                          metavar="<seconds>",
                          help="The range of time to scan. The log files older than this time are not scanned. Default is %default.")
        parser.add_option("-E", "--expiration",
                          action="store",
                          type="int",
                          dest="expiration",
                          default=691200,
                          metavar="<seconds>",
                          help="The expiration of seek files. Default is %default. This value must be greater than period of log rotation when use with -R option.")
        parser.add_option("-R", "--remove-seekfile",
                          action="store_true",
                          dest="remove_seekfile",
                          default=False,
                          help="Remove expired seek files. See also --expiration.")
        parser.add_option("-M", "--multiline",
                          action="store_true",
                          dest="multiline",
                          default=False,
                          help="Consider multiple lines with same key as one log output. See also --multiline.")
        parser.add_option("--debug",
                          action="store_true",
                          dest="debug",
                          default=False,
                          help="Enable debug.")
        return parser

    @classmethod
    def is_multiple_logifles(cls, pattern):
        m = re.search('[*? ]', pattern)
        if m is not None:
            return True

        return False

    @classmethod
    def check_parser_options(cls, parser):
        global debug
        (options, args) = parser.parse_args()
        debug = options.debug

        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(LogChecker.STATE_UNKNOWN)

        # check args
        if options.logfile_pattern is None or options.logfile_pattern is '':
            parser.error("option -l, --logfile is required.")
            sys.exit(LogChecker.STATE_UNKNOWN)
        if options.seekfile and options.seekfile_directory:
            parser.error("options '-s, --seekfile' and '-S, --seekfile-directory' are incompatible.\
                    If check multiple log files, Use -S. If check single log file, Use -s or -S.")
            sys.exit(LogChecker.STATE_UNKNOWN)

        is_multiple_logfiles = LogChecker.is_multiple_logifles(options.logfile_pattern)
        if is_multiple_logfiles:
            if options.seekfile:
                parser.error("If check multiple log files, options -s, --seekfile cannot be specified.")
                sys.exit(LogChecker.STATE_UNKNOWN)
            if options.seekfile_directory is None or options.seekfile_directory is '':
                parser.error("If check multiple log files, option -S, --seekfile-directory is required.")
                sys.exit(LogChecker.STATE_UNKNOWN)
            if ((options.seekfile is None or options.seekfile is '') and
                    (options.seekfile_directory is None or options.seekfile_directory is '')):
                parser.error("options '-S, --seekfile-directory' is required.")
                sys.exit(LogChecker.STATE_UNKNOWN)
            # check directory
            if (options.seekfile_directory) and not os.path.isdir(options.seekfile_directory):
                parser.error("seekfile directory is not found: %s" % (options.seekfile_directory))
                sys.exit(LogChecker.STATE_UNKNOWN)
        else:
            if ((options.seekfile is None or options.seekfile is '') and
                    (options.seekfile_directory is None or options.seekfile_directory is '')):
                parser.error("options '-S, --seekfile-directory' or '-s, --seekfile' is required.")
                sys.exit(LogChecker.STATE_UNKNOWN)
            # check file or directory
            if options.seekfile_directory and not os.path.isdir(options.seekfile_directory):
                parser.error("seekfile directory is not found: %s" % (options.seekfile_directory))
                sys.exit(LogChecker.STATE_UNKNOWN)
            if options.seekfile and not os.path.isfile(options.logfile_pattern):
                parser.error("logfile is not found: %s" % (options.logfile_pattern))
                sys.exit(LogChecker.STATE_UNKNOWN)

        pattern_list = LogChecker.get_pattern_list(options.pattern, options.patternfile)
        critical_pattern_list = LogChecker.get_pattern_list(options.critical_pattern, options.critical_patternfile)
        if len(pattern_list) == 0 and len(critical_pattern_list) == 0:
            parser.error("any valid pattern not found")
            sys.exit(LogChecker.STATE_UNKNOWN)

        return (options, args)


def main():
    parser = LogChecker.make_parser()
    (options, args) = LogChecker.check_parser_options(parser)

    # make pattern list
    pattern_list = LogChecker.get_pattern_list(options.pattern, options.patternfile)
    critical_pattern_list = LogChecker.get_pattern_list(options.critical_pattern, options.critical_patternfile)
    negpattern_list = LogChecker.get_pattern_list(options.negpattern, options.negpatternfile)
    critical_negpattern_list = LogChecker.get_pattern_list(options.critical_negpattern, options.critical_negpatternfile)

    # set value of options
    initial_data = {
        "logformat": options.logformat,
        "pattern_list": pattern_list,
        "critical_pattern_list": critical_pattern_list,
        "negpattern_list": negpattern_list,
        "critical_negpattern_list": critical_negpattern_list,
        "case_insensitive": options.case_insensitive,
        "warning": options.warning,
        "critical": options.critical,
        "nodiff_warn": options.nodiff_warn,
        "nodiff_crit": options.nodiff_crit,
        "trace_inode": options.trace_inode,
        "multiline": options.multiline,
        "scantime": options.scantime,
        "expiration": options.expiration
    }
    log = LogChecker(initial_data)
    state = LogChecker.STATE_OK

    # execute check_log_multi or check_log
    seekfile = None
    is_multiple_logfiles = LogChecker.is_multiple_logifles(options.logfile_pattern)
    if is_multiple_logfiles:
        log.check_log_multi(options.logfile_pattern, options.seekfile_directory, options.remove_seekfile)
        state = log.get_state()
        print log.get_message()
    else:
        # create seekfile
        if options.seekfile:
            seekfile = options.seekfile
        elif options.seekfile_directory:
            logfile = options.logfile_pattern
            seekfile = LogChecker.get_seekfile(options.logfile_pattern, options.seekfile_directory,
                                               logfile, trace_inode=options.trace_inode)

        log.check_log(options.logfile_pattern, seekfile)
        state = log.get_state()
        print log.get_message()

    sys.exit(state)


if __name__ == "__main__":
    main()

# vim: set ts=4 sw=4 et:
