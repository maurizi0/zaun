#!/usr/bin/env python3
"""Render the shared Supervisor template for a native systemd installation."""
import configparser
import sys


def render(source, destination):
    config = configparser.ConfigParser(interpolation=None)
    config.read_file(source)
    config["supervisord"]["pidfile"] = "/run/agent-proxy/supervisord.pid"
    config["unix_http_server"]["file"] = "/run/agent-proxy/supervisor.sock"
    config["unix_http_server"]["chmod"] = "0700"
    config["supervisorctl"]["serverurl"] = "unix:///run/agent-proxy/supervisor.sock"
    for section in config.sections():
        if section.startswith("program:"):
            # journald supplies an AF_UNIX socket. Supervisor cannot reopen that
            # socket through /dev/stdout, so use bounded regular files instead.
            config[section]["stdout_logfile"] = "/var/log/agent-proxy/%(program_name)s.log"
            config[section]["stdout_logfile_maxbytes"] = "10MB"
            config[section]["stdout_logfile_backups"] = "3"
    config.write(destination)


if __name__ == "__main__":
    with open(sys.argv[1]) as source:
        render(source, sys.stdout)
