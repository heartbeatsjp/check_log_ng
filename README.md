# check_log_ng

[![Build Status](https://travis-ci.org/heartbeatsjp/check_log_ng.svg?branch=master)](https://travis-ci.org/heartbeatsjp/check_log_ng)

A log file regular expression-based parser plugin for Nagios.

Features are as follows:

- You can specify the character string you want to detect with regular expressions.
- You can specify the character string you do not want to detect with regular expressions.
- You can specify the character encoding of a log file.
- You can check multiple log files at once and also check log-rotated files.
- This script uses seek files which record the position where the check is completed for each log file. With these seek files, you can check only the differences from the last check.
- You can check multiple lines outputed at once as one message.
- The result can be cached within the specified time period. This will help multiple monitoring servers and multiple attempts.

Originally, this script had be inspired by [`check_log3.pl`](https://exchange.nagios.org/directory/Plugins/Log-Files/check_log3-2Epl/details).
Currentlly, this has different options.

## Examples of usage

### Pattern

If you want to detect character strings, you can add `-p <pattern>` or `-P <filename>` option.

~~~sh
check_log_ng.py -p 'ERROR' -S /var/spool/check_log_ng -l '/var/log/messages'
~~~

Or

~~~sh
check_log_ng.py -P /path/to/pattern.txt -S /var/spool/check_log_ng -l '/var/log/messages'
~~~

~~~sh
$ cat /path/to/pattern.txt
ERROR
FATAL
~~~

### Negative pattern

If you have character strings not to detect, you can add `-n <pattern>` or `-N <filename>` option.

~~~sh
check_log_ng.py -p 'ERROR' -n 'no problem' -S /var/spool/check_log_ng -l '/var/log/messages'
~~~

Or

~~~sh
check_log_ng.py -P /path/to/pattern.txt -N /path/to/negpattern.txt -S /var/spool/check_log_ng -l '/var/log/messages'
~~~

~~~sh
$ cat /path/to/negpattern.txt
no problem
information
~~~

### Case insensitive

If you want to do a case insensitive scan, you can add `-i` option.

~~~sh
check_log_ng.py -i -p 'ERROR' -S /var/spool/check_log_ng -l '/var/log/messages'
~~~

### Multiple lines

When output to multiple lines at the same time such as the following, you can add `-F <format>` and `-M` option.

```
2013/12/05 09:36:51,024 jobs-thread-5 ERROR ~ *** Called URI is: https://www.example.com/submit
2013/12/05 09:36:51,024 jobs-thread-5 ERROR ~ *** Response code is: 500
```

~~~sh
check_log_ng.py -F '^(%Y/%m/%d\s%T,\d+ \S+ \S+) (.*)$' -M -p 'ERROR' -S /var/spool/check_log_ng -l '/var/log/application.log'
~~~

This is considered a message like the following:

```
2013/12/05 09:36:51,024 jobs-thread-5 ERROR ~ *** Called URI is: https://www.example.com/submit ~ *** Response code is: 500
```

### Multiple monitoring items

If you want use multiple monitoring items, you can add '-T <tag>' option to prevent name collisions of seek files.

~~~sh
check_log_ng.py -T 'log_error' -p 'ERROR' -S /var/spool/check_log_ng -l '/var/log/messages'
~~~

~~~sh
check_log_ng.py -T 'log_block' -p 'BLOCK' -S /var/spool/check_log_ng -l '/var/log/messages'
~~~

### Monitoring interval

If your monitoring interval is 180 seconds, you can add `--cachetime=180` option to cache the result within monitoring interval.
It is useful for multiple monitoring servers.

~~~sh
check_log_ng.py --cachetime=180 -p 'ERROR' -S /var/spool/check_log_ng -l '/var/log/messages'
~~~

### Multiple log files

If you want to check log-rotated files with the file name such as 'message.N' or 'message-YYYYMMDD', you can add `-I -R` options to trace inode informations.

~~~sh
check_log_ng.py -I -R -p 'ERROR' -S /var/spool/check_log_ng -l '/var/log/messages*'
~~~

If the log rotation period exceeds one week, you can add `-E <seconds>` option.
This value must be longer than the log rotation period.
If it is one month, you can add `-E 2764800`, which is 32 days.

~~~sh
check_log_ng.py -I -R -E 2764800 -p 'ERROR' -S /var/spool/check_log_ng -l '/var/log/messages*'
~~~


## Requirement

- Python 2.6, 2.7, 3.5 or 3.6.
- In python 2.6, argparse module.

## Installation

Clone a copy of the main `check_log_ng` git repository.

~~~sh
$ git clone git@github.com:heartbeatsjp/check_log_ng.git
$ cd check_log_ng
~~~

Add execute permission.

~~~sh
$ chmod 755 check_log_ng.py
~~~

Copy this plugin to a nagios-plugins directory.

~~~sh
$ sudo cp check_log_ng.py /usr/lib64/nagios/plugins/
~~~

Create a directory to store a cache file, a lock file and seek files.

~~~sh
$ sudo mkdir /var/spool/check_log_ng
~~~

Change the owner of the directory to the user who will run nrpe.

~~~sh
$ sudo chown nrpe: /var/spool/check_log_ng
~~~

If root privilege is necessary to read log files, add the following lines to a sudoers file.

```
Defaults:nrpe !requiretty
nagios ALL=(root) NOPASSWD: /usr/lib64/nagios/plugins/check_log_ng.py
```

If you use Python 2.6, install argparse module.
If you use RHEL6/CentOS6, you can run:

~~~sh
$ sudo yum install python-argparse
~~~

## Usage

### Help

```
usage: check_log_ng.py [options] [-p <pattern>|-P <filename>] -S <directory> -l <filename>

A log file regular expression-based parser plugin for Nagios.

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -l <filename>, --logfile <filename>
                        The file names of log files to be scanned. The
                        metacharacters * and ? are available. To set multiple
                        files, set a space between file names. See also
                        --scantime.
  -F <format>, --format <format>
                        Regular expression for log format. It requires two
                        groups in format of '^(TIMESTAMP and TAG)(.*)$'. Also,
                        it may use %%, %Y, %y, %a, %b, %m, %d, %e, %H, %M, %S,
                        %F and %T of strftime(3). (default: regular expression
                        for syslog.
  -s <filename>, --seekfile <filename>
                        Deprecated. Use -S option instead. The file name of
                        the file to store the seek position of the last scan.
  -S <directory>, --state-directory <directory>, --seekfile-directory <directory>
                        The directory to store seek files, cache file and lock
                        file. '--seekfile-directory' is for backwards
                        compatibility.
  -T <tag>, --tag <tag>, --seekfile-tag <tag>
                        Add a tag in the file names of state files, to prevent
                        names collisions. Useful to avoid maintaining many
                        '-S' directories when you check the same files several
                        times with different args. '--seekfile-tag' is for
                        backwards compatibility.
  -I, --trace-inode     If set, trace the inode of the log file. After log
                        rotatation, you can trace the log file.
  -p <pattern>, --pattern <pattern>
                        The regular expression to scan for in the log file.
  -P <filename>, --patternfile <filename>
                        The file name of the file containing regular
                        expressions, one per line.
  --critical-pattern <pattern>
                        The regular expression to scan for in the log file. If
                        found, return CRITICAL.
  --critical-patternfile <filename>
                        The file name of the file containing regular
                        expressions, one per line. If found, return CRITICAL.
  -n <pattern>, --negpattern <pattern>
                        The regular expression which all will be skipped
                        except as critical pattern in the log file.
  -N <filename>, -f <filename>, --negpatternfile <filename>
                        The file name of the file containing regular
                        expressions which all will be skipped except as
                        critical pattern, one per line. '-f' is for backwards
                        compatibility.
  --critical-negpattern <pattern>
                        The regular expression which all will be skipped in
                        the log file.
  --critical-negpatternfile <filename>
                        The file name of the file containing regular
                        expressions which all will be skipped, one per line.
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
                        The expiration of seek files. This must be longer than
                        the log rotation period. The expired seek files are
                        deleted with -R option. (default: 691200)
  -R, --remove-seekfile
                        Remove expired seek files. See also --expiration.
  -M, --multiline       Treat multiple lines outputed at once as one message.
                        See also --format.
  --cachetime <seconds>
                        The period to cache the result. To disable this cache
                        feature, set '0'. (default: 60)
  --lock-timeout <seconds>
                        The period to wait for if another process is running.
                        If timeout occurs, UNKNOWN is returned. (default: 3)
```

## Contributing

If you have a problem, please [create an issue](https://github.com/heartbeatsjp/check_log_ng/issues) or a pull request.

1. Fork it
1. Create your feature branch (git checkout -b my-new-feature)
1. Commit your changes (git commit -am 'Add some feature')
1. Push to the branch (git push origin my-new-feature)
1. Create new Pull Request

If you debug this script, use -O option.

~~~sh
python -O check_log_ng.py ...
~~~

## License

[BSD](https://github.com/heartbeatsjp/check_log_ng/blob/master/LICENSE.txt)

## Todo

- improve the current test code coverage
