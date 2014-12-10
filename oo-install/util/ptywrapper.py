#!/usr/bin/python -u

import fcntl
import getopt
import logging
import os
import pty
import re
import select
import subprocess
import sys
import tempfile

from shutil import rmtree


class PtyWrapperStreamFilter(logging.Filter):
    def __init__(self, streams=[]):
        self.streams = streams

    def filter(self, record):
        if record.childstream not in self.streams:
            return False
        return True


class PtyWrapperContentFilter(logging.Filter):
    regex = None

    def __init__(self, patterns=[]):
        if patterns:
            self.regex = re.compile("|".join(["(%s)" % p for p in patterns]))

    def filter(self, record):
        if self.regex and not self.regex.search(record.getMessage()):
            return False
        return True


class PtyWrapper:
    def __init__(self, options={}):
        # setup logging before validatating and setting other options
        log_level = logging.WARNING
        if "log_level" in options:
            log_level = options["log_level"]

        fmt = "[%(name)s %(funcName)s] %(levelname)s: %(message)s"
        logging.basicConfig(level=log_level, format=fmt)
        self.logger = logging.getLogger(__name__+"PtyWrapper")
        self.logger.debug("Options=%s" % (options))

        self._validate_options(options)

        val = options["tee"] if ("tee" in options) else False
        self.logger.debug("Setting option tee to %s" % val)
        self.tee = val

        for opt in ("stdout_logfile", "stderr_logfile", "stdout_filters",
                    "stderr_filters"):
            val = options[opt] if (opt in options) else None
            self.logger.debug("Setting option %s to %s" % (opt, val))
            setattr(self, opt, val)

    def _validate_options(self, options):
        self.logger.debug("Options=%s" % options)
        if "tee" in options and not("stdout_logfile" in options
                                    or "stderr_logfile" in options):
            raise SystemExit("tee option requires either stdout-logfile or " +
                             "stderr-logfile to be set")

    def _format_logging_attrs(self, items=[], attr_fun=lambda i: i,
                              tab_level=2):
        if items:
            tabs = "\t" * tab_level
            tab2 = "\t" * (tab_level + 1)
            li = ["{0}: {1}".format(i.__class__.__name__, attr_fun(i)) for i
                  in items]
            return "[%s%s%s]" % ("\n%s" % tab2 if len(items) > 1 else "",
                                 (",\n%s" % tab2).join(li),
                                 "\n%s" % tabs if len(items) > 1 else "")
        else:
            return "[]"

    def _format_logging_filters(self, filters=[], tab_level=2):
        def get_filter_attr(f):
            return (f.streams if hasattr(f, "streams")
                    else ("'%s'" % f.regex.pattern if f.regex else ""))

        return self._format_logging_attrs(filters, get_filter_attr, tab_level)

    def _format_logging_handlers(self, handlers=[], tab_level=2):
        attr_tab = "\t" * (tab_level + 2)

        def get_handler_attr(h):
            return ("\n{0}stream: {1}\n{2}filters: "
                    "{3}".format(attr_tab, h.stream.name, attr_tab,
                                 self._format_logging_filters(h.filters,
                                                              tab_level + 2)))

        return self._format_logging_attrs(handlers, get_handler_attr,
                                          tab_level)

    def _create_handler(self, handler_type, handler_arg, formatter,
                        stream_filters, content_filters):
        if handler_type == "stream":
            handler = logging.StreamHandler(handler_arg)
            if content_filters:
                handler.addFilter(PtyWrapperContentFilter(content_filters))
        else:
            handler = logging.FileHandler(handler_arg)

        if stream_filters:
            handler.addFilter(PtyWrapperStreamFilter(stream_filters))

        if formatter:
            handler.setFormatter(formatter)

        if self.logger.getEffectiveLevel() is logging.DEBUG:
            handler_filters = self._format_logging_filters(handler.filters)
            fmt = handler.formatter._fmt if handler.formatter else None
            self.logger.debug("\n\thandler: {0}\n\t\tformatter: {1}\n\t\t"
                              "stream: {2}\n\t\tfilters:"
                              " {3}".format(handler.__class__.__name__, fmt,
                                            handler.stream.name,
                                            handler_filters))

        return handler

    def _get_child_logging_adapters(self):
        logger = logging.getLogger(__name__+".PtyWrapper.run.child_logger")
        logger.setLevel(logging.CRITICAL)
        logger.propagate = False
        formatter = logging.Formatter("%(message)s")
        handlers = {}

        for stream in ("stdout", "stderr"):
            for handler_type in ("stream", "logfile"):
                handler_name = stream + "_" + handler_type
                stream_filters = [stream]
                content_filters = []

                if handler_type == "stream":
                    if not self.tee and getattr(self, stream + "_logfile"):
                        # no stream handler needed since tee is not set and
                        # a logfile is set
                        continue
                    # set the handler_arg to the associated stream
                    handler_arg = getattr(sys, stream)
                    filter_attr = getattr(self, stream + "_filters")
                    content_filters = filter_attr if filter_attr else []
                else:
                    # handler is logfile
                    handler_arg = getattr(self, handler_name)
                    if handler_arg is None:
                        continue
                    else:
                        if self.stdout_logfile == self.stderr_logfile:
                            if stream == "stdout":
                                # logging both stdout and stderr to same
                                # handler
                                stream_filters = ["stdout", "stderr"]
                            else:
                                # logging both stdout and stderr to same
                                # logfile do not add a second file handler
                                continue

                handlers[handler_name] = self._create_handler(handler_type,
                                                              handler_arg,
                                                              formatter,
                                                              stream_filters,
                                                              content_filters)

        for handler in handlers.values():
            logger.addHandler(handler)

        stdout_adapter = logging.LoggerAdapter(logger,
                                               {'childstream': 'stdout'})
        stderr_adapter = logging.LoggerAdapter(logger,
                                               {'childstream': 'stderr'})

        if self.logger.getEffectiveLevel() is logging.DEBUG:
            logger_filters = self._format_logging_filters(logger.filters)
            logger_handlers = self._format_logging_handlers(logger.handlers)

            self.logger.debug("\n\tlogger: {0}\n\t\tlevel: {1}\n\t\tpropagate:"
                              " {2}\n\t\thandlers: "
                              "{3}".format(self.logger.name,
                                           logging.getLevelName(logger.level),
                                           logger.propagate, logger_handlers))
            self.logger.debug("\n\tstdout_adapter:\n\t\tlogger: "
                              "{0}\n\t\textra_records: "
                              "{1}".format(stdout_adapter.logger.name,
                                           stdout_adapter.extra))
            self.logger.debug("\n\tstderr_adapter:\n\t\tlogger: "
                              "{0}\n\t\textra_records: "
                              "{1}".format(stderr_adapter.logger.name,
                                           stderr_adapter.extra))

        return stdout_adapter, stderr_adapter

    def _poll_child_output(self, proc_out, c_stdout, c_stderr,
                           stdout_adapter, stderr_adapter, poller):

                    read_write = {proc_out.fileno(): (proc_out.readline,
                                                      self.logger.debug,
                                                      "proc_out",
                                                      "pty stdout - {0}"),
                                  c_stdout.fileno(): (c_stdout.readline,
                                                      stdout_adapter.critical,
                                                      "child_stdout",
                                                      "subproc stdout - {0}"),
                                  c_stderr.fileno(): (c_stderr.readline,
                                                      stderr_adapter.critical,
                                                      "child_stderr",
                                                      "subproc stderr - {0}")}
                    stderr_alive = True
                    stdout_alive = True
                    proc_alive = True
                    while True:
                        self.logger.debug("Polling")
                        events = poller.poll(1)
                        if not events and (not proc_alive and
                                           not stdout_alive and
                                           not stderr_alive):
                            break
                        for fd, event in sorted(events,
                                                key=lambda tup: tup[1]):
                            if (event & select.EPOLLIN or
                                    event & select.EPOLLPRI):
                                read, write, fdname, formatstr = read_write[fd]
                                self.logger.debug("Caught EPOLLIN or "
                                                  "EPOLLPRI for %s" % fdname)
                                line = read()
                                if line:
                                    line = line.rstrip()
                                    self.logger.info(formatstr.format(line))
                                    write(line)
                            elif event & select.EPOLLHUP:
                                read, write, fdname, _ = read_write[fd]
                                self.logger.debug("Caught EPOLLHUP for %s" %
                                                  fdname)
                                if fd is c_stdout.fileno():
                                    poller.unregister(c_stdout)
                                    stdout_alive = False
                                elif fd is c_stderr.fileno():
                                    poller.unregister(c_stderr)
                                    stderr_alive = False
                                else:
                                    poller.unregister(proc_out)
                                    proc_alive = False
                            elif event & select.EPOLLERR:
                                self.logger.error("Polling error reading from "
                                                  "child process")
                            else:
                                assert 0

    def run(self, command):
        self.logger.debug("Command=%s" % command)
        (ch_out_adapter, ch_err_adapter) = self._get_child_logging_adapters()

        try:
            fifodir = tempfile.mkdtemp()
            child_out = os.path.join(fifodir, 'outfifo')
            child_err = os.path.join(fifodir, 'errfifo')
            os.mkfifo(child_out, 0600)
            os.mkfifo(child_err, 0600)
        except OSError as e:
            raise SystemExit("Error: Failed to created named pipes")

        # create a lock to ensure polling is configured before
        # child process starts
        lockfile = os.path.join(fifodir, 'lockfile')
        lock_fd = os.open(lockfile, os.W_OK | os.O_CREAT)
        fcntl.fcntl(lock_fd, fcntl.F_SETFD,
                    fcntl.fcntl(lock_fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
        fcntl.lockf(lock_fd, fcntl.LOCK_EX)
        self.logger.debug("Acquired lock on %s" % lockfile)

        pid, child_proc_fd = pty.fork()
        if pid == 0:
            # set child stdout to unbuffered
            stdout = open(child_out, 'w', 0)
            stderr = open(child_err, 'w', 0)

            # block on acquiring lock to know parent polling is configured
            fcntl.lockf(lock_fd, fcntl.LOCK_EX)
            print "[Child] Acquired lock on %s" % lockfile
            fcntl.lockf(lock_fd, fcntl.LOCK_UN)
            print "[Child] Released lock on %s" % lockfile

            print "[Child] Preparing to run command %s" % command
            exit_code = subprocess.call(command, shell=True,
                                        stdout=stdout.fileno(),
                                        stderr=stderr.fileno(),
                                        close_fds=True)
            print "[Child] exit code is: %s" % exit_code
            stdout.flush()
            stderr.flush()
            os._exit(exit_code)
        else:
            with os.fdopen(child_proc_fd, 'r', 0) as child_proc_out:
                poller = select.epoll()
                eventmask = (select.EPOLLIN | select.EPOLLPRI |
                             select.EPOLLERR | select.EPOLLHUP)
                poller.register(child_proc_out, eventmask)
                with open(child_out, 'r', 0) as child_stdout:
                    poller.register(child_stdout, eventmask)
                    with open(child_err, 'r', 0) as child_stderr:
                        poller.register(child_stderr, eventmask)

                        # release the lock now that the polling is configured
                        fcntl.lockf(lock_fd, fcntl.LOCK_UN)
                        self.logger.debug("Released lock on %s" % lockfile)

                        self._poll_child_output(child_proc_out, child_stdout,
                                                child_stderr, ch_out_adapter,
                                                ch_err_adapter, poller)
                        pid, child_status = os.wait()
                        child_exit_code = os.WEXITSTATUS(child_status)
                        self.logger.debug("Recieved exit_status: {0} from "
                                          "child pid: "
                                          "{1}".format(child_exit_code, pid))

        warn_fmt = "Warn: Failed to remove directory: {0}\n"
        rmtree(fifodir, False,
               lambda f, path, e: self.logger.warn(warn_fmt.format(path)))
        return child_exit_code


def _usage():
    print """\nUsage: %s [-vdts] [-l stdout-logfile] [-e stderr-logfile] [--output-filter] [--error-filter] command
-h, --help
        display this help and exit
-v, --verbose
        verbose output
-d, --debug
        debug output
-t, --tee
        tee output to normal stream as well as logfile if logfile specified.
-l, --stdout-logfile logfile
        file to log command stdout to
-e, --stderr-logfile logfile
        file to log command stderr to
--output-filter filter
        output filter to use for stdout(applies to stream output only)
--error-filter filter
        output filter to use for stderr(applies to stream output only)
command
        command to run
""" % os.path.basename(__file__)


def _parse_args():
    options = {}

    try:
        opts, args = getopt.gnu_getopt(sys.argv[1:], "hvdtl:e:",
                                       ["help", "verbose", "debug", "tee",
                                        "stdout-logfile=", "stderr-logfile=",
                                        "output-filter=", "error-filter="])
        for opt, val in opts:
            if opt in ("-h", "--help"):
                _usage()
                sys.exit()
            elif opt in ("-v", "--verbose"):
                options["log_level"] = logging.INFO
            elif opt in ("-d", "--debug"):
                options["log_level"] = logging.DEBUG
            elif opt in ("-t", "--tee"):
                options["tee"] = True
            elif opt in ("-l", "--stdout-logfile"):
                options["stdout_logfile"] = val
            elif opt in ("-e", "--stderr-logfile"):
                options["stderr_logfile"] = val
            elif opt == "--output-filter":
                if "stdout_filters" in options:
                    options["stdout_filters"].append(val)
                else:
                    options["stdout_filters"] = [val]
            elif opt == "--error-filter":
                if "stderr_filters" in options:
                    options["stderr_filters"].append(val)
                else:
                    options["stderr_filters"] = [val]
            else:
                assert False, "unhandled option"

        if len(args) == 0:
            raise SystemExit("command to run is required.")

        command = args[0]
        return (command, options)
    except getopt.GetoptError as e:
        raise SystemExit("%s\n" % str(e))

if __name__ == "__main__":
    command, options = _parse_args()
    pty_wrapper = PtyWrapper(options)
    ret_code = pty_wrapper.run(command)
    sys.exit(ret_code)
