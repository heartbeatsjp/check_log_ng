# check_log_ng

[![Build Status](https://travis-ci.org/heartbeatsjp/check_log_ng.svg?branch=master)](https://travis-ci.org/heartbeatsjp/check_log_ng)

A log file regular expression-based parser plugin for Nagios.

## Requirement

- Python 2.6, 2.7, 3.5 or 3.6.
- On python 2.6, argparse module.

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
$ sudo mkdir /var/spool/check_log_ng
$ sudo chown nrpe:nrpe /var/spool/check_log_ng
```

If root privilege is necessary to read log files, edit a  sudoers file.

```
Defaults:nrpe !requiretty
nagios ALL=(root) NOPASSWD: /usr/lib64/nagios/plugins/check_log_ng.py
```

If you run on python 2.6, install argparse module.
If you use RHEL6/CentOS6, you can run:

```
$ sudo yum install python-argparse
```

## Documentation

Japanese Version Only...

https://github.com/heartbeatsjp/check_log_ng/wiki

## Usage

### Help

```
usage: check_log_ng.py [options] [-p <pattern>|-P <filename>] -l <filename> -S <directory>

A log file regular expression-based parser plugin for Nagios.

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -l <filename>, --logfile <filename>
                        The pattern of log files to be scanned. The
                        metacharacter * and ? are allowed. If you want to set
                        multiple patterns, set a space between patterns.
  -F <format>, --format <format>
                        The regular expression of format of log to parse.
                        Required two group, format of '^(TIMESTAMP and
                        TAG)(.*)$'. Also, may use %%, %Y, %y, %a, %b, %m, %d,
                        %e, %H, %M, %S, %F and %T of strftime(3). (default:
                        the regular expression for syslog.
  -s <filename>, --seekfile <filename>
                        Deprecated. Use -S option. The file to store the seek
                        position of the last scan. If check multiple log
                        files, ignore this option.
  -S <directory>, --state-directory <directory>, --seekfile-directory <directory>
                        The directory that store seek files, cache file and
                        lock file. If check multiple log files, require this
                        option. '--seekfile-directory' is for backwards
                        compatibility.
  -T <tag>, --tag <tag>, --seekfile-tag <tag>
                        Add a tag in the file names of state files, to prevent
                        names collisions. Useful to avoid maintaining many
                        '-S' temporary directories when you check the same
                        files several times with different args. '--seekfile-
                        tag' is for backwards compatibility.
  -I, --trace-inode     Trace the inode of log files. If set, use inode
                        information as a seek file.
  -p <pattern>, --pattern <pattern>
                        The regular expression to scan for in the log file.
  -P <filename>, --patternfile <filename>
                        File containing regular expressions, one per line.
  --critical-pattern <pattern>
                        The regular expression to scan for in the log file. In
                        spite of --critical option, return CRITICAL.
  --critical-patternfile <filename>
                        File containing regular expressions, one per line. In
                        spite of --critical option, return CRITICAL.
  -n <pattern>, --negpattern <pattern>
                        The regular expression to skip except as critical
                        pattern in the log file.
  -N <filename>, -f <filename>, --negpatternfile <filename>
                        Specify a file with regular expressions which all will
                        be skipped except as critical pattern, one per line.
                        '-f' is for backwards compatibility.
  --critical-negpattern <pattern>
                        The regular expression to skip in the log file.
  --critical-negpatternfile <filename>
                        Specifiy a file with regular expressions which all
                        will be skipped, one per line.
  -i, --case-insensitive
                        Do a case insensitive scan.
  --encoding <encoding>
                        Specify the character encoding in the log file.
                        (default: utf-8)
  -w <number>, --warning <number>
                        Return WARNING if at least this many matches found.
                        (default: 1)
  -c <number>, --critical <number>
                        Return CRITICAL if at least this many matches found.
                        i.e. don't return critical alerts unless specified
                        explicitly. (default: 0)
  -t <seconds>, --scantime <seconds>
                        The range of time to scan. The log files older than
                        this time are not scanned. (default: 86400)
  -E <seconds>, --expiration <seconds>
                        The expiration of seek files. This value must be
                        greater than period of log rotation when use with -R
                        option. (default: 691200)
  -R, --remove-seekfile
                        Remove expired seek files. See also --expiration.
  -M, --multiline       Consider multiple lines with same key as one log
                        output. See also --format.
  --cachetime <seconds>
                        The period to cache the result. If you want to disable
                        this cache feature, set '0'. (default: 60)
  --lock-timeout <seconds>
                        If another proccess is running, wait for the period of
                        this lock timeout. (default: 3)
```

## Contributing

If you have a problem, please [create an issue](https://github.com/heartbeatsjp/check_log_ng/issues) or a pull request.

1. Fork it
1. Create your feature branch (git checkout -b my-new-feature)
1. Commit your changes (git commit -am 'Add some feature')
1. Push to the branch (git push origin my-new-feature)
1. Create new Pull Request

If you debug this script, use -O option.

```
python -O check_log_ng.py ...
```

## License

[BSD](https://github.com/heartbeatsjp/check_log_ng/blob/master/LICENSE.txt)

## Todo

- improve the current test code coverage
