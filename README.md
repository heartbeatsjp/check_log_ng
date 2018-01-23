# check_log_ng

![Build Status](https://travis-ci.org/heartbeatsjp/check_log_ng.svg?branch=master)

Log file regular expression based parser plugin for Nagios.

## Installation

Clone a copy of the main `check_log_ng` git repo and add execute permission.

```
$ git@github.com:heartbeatsjp/check_log_ng.git
$ cd check_log_ng
$ chmod 755 check_log_ng.py
```
Copy this plugin to nagios-plugins directory.

```
$ cp check_log_ng.py /usr/lib64/nagios/plugins/
```

Create a directory to save a cache file, a lock file and seek files.
Change the owner of the directory.
```
$ mkdir /var/spool/check_log_ng
$ chown nrpe:nrpe /var/spool/check_log_ng
```

If root privilege is necessary to read log files, edit a  sudoers file.

```
Defaults:nrpe !requiretty
nagios ALL=(root) NOPASSWD: /usr/lib64/nagios/plugins/check_log_ng.py
```

## Documentation

Japanese Version Only...

https://github.com/heartbeatsjp/check_log_ng/wiki

## Usage

```
Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -l <filename>, --logfile=<filename>
                        The pattern of log files to be scanned. The
                        metacharacter * and ? are allowed. If you want to set
                        multiple patterns, set a space between patterns.
  -F <format>, --format=<format>
                        The regular expression of format of log to parse.
                        Required two group, format of '^(TIMESTAMP and
                        TAG)(.*)$'. Also, may use %%, %Y, %y, %a, %b, %m, %d,
                        %e, %H, %M, %S, %F and %T of strftime(3). Default: the
                        regular expression for syslog.
  -s <filename>, --seekfile=<filename>
                        The temporary file to store the seek position of the
                        last scan. If check multiple log files, ignore this
                        option. Use -S seekfile_directory.
  -S <seekfile_directory>, --seekfile-directory=<seekfile_directory>
                        The directory of the temporary file to store the seek
                        position of the last scan. If check multiple log
                        files, require this option.
  -T <seekfile_tag>, --seekfile-tag=<seekfile_tag>
                        Add a tag in the seek files names, to prevent names
                        collisions. Useful to avoid maintaining many '-S'
                        temporary directories when you check the same files
                        several times with different options.
  -I, --trace-inode     Trace the inode of log files. If set, use inode
                        information as a seek file.
  -p <pattern>, --pattern=<pattern>
                        The regular expression to scan for in the log file.
  -P <filename>, --patternfile=<filename>
                        File containing regular expressions, one per line.
  --critical-pattern=<pattern>
                        The regular expression to scan for in the log file. In
                        spite of --critical option, return CRITICAL.
  --critical-patternfile=<filename>
                        File containing regular expressions, one per line. In
                        spite of --critical option, return CRITICAL.
  -n <pattern>, --negpattern=<pattern>
                        The regular expression to skip except as critical
                        pattern in the log file.
  -N <filename>, -f <filename>, --negpatternfile=<filename>
                        Specifies a file with regular expressions which all
                        will be skipped except as critical pattern, one per
                        line.
  --critical-negpattern=<pattern>
                        The regular expression to skip in the log file
  --critical-negpatternfile=<filename>
                        Specifies a file with regular expressions which all
                        will be skipped, one per line.
  -i, --case-insensitive
                        Do a case insensitive scan
  --encoding=<encoding>
                        Specify the character encoding in the log file. If not
                        specified, it is treated as it is.
  -w <number>, --warning=<number>
                        Return WARNING if at least this many matches found.
                        The default is 1.
  -c <number>, --critical=<number>
                        Return CRITICAL if at least this many matches found.
                        The default is 0, i.e. don't return critical alerts
                        unless specified explicitly.
  -d, --nodiff-warn     Return WARNING if the log file was not written to
                        since the last scan. (not implemented)
  -D, --nodiff-crit     Return CRITICAL if the log was not written to since
                        the last scan. (not impremented)
  -t <seconds>, --scantime=<seconds>
                        The range of time to scan. The log files older than
                        this time are not scanned. Default is 86400.
  -E <seconds>, --expiration=<seconds>
                        The expiration of seek files. Default is 691200. This
                        value must be greater than period of log rotation when
                        use with -R option.
  -R, --remove-seekfile
                        Remove expired seek files. See also --expiration.
  -M, --multiline       Consider multiple lines with same key as one log
                        output. See also --multiline.
  --cache               Cache the result for the period specified by the
                        option --cachetime.
  --cachetime=<seconds>
                        The period to cache the result. Default is 60.
  --lock-timeout=<seconds>
                        If another proccess is running, wait for the period of
                        this lock timeout. Default is 3.
  --debug               Enable debug.
```

### Note

The --encoding option is supported in Python 2.6 or higher.

## Contributing

If you have a problem, please [create an issue](https://github.com/heartbeatsjp/check_log_ng/issues) or a pull request.

1. Fork it
1. Create your feature branch (git checkout -b my-new-feature)
1. Commit your changes (git commit -am 'Add some feature')
1. Push to the branch (git push origin my-new-feature)
1. Create new Pull Request

## License

[BSD](https://github.com/heartbeatsjp/check_log_ng/blob/master/LICENSE.txt)

## Todo

- support python 3
- improve the current test code coverage
