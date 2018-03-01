#!/usr/bin/env python
from __future__ import print_function
import sys
import re
import shlex
import subprocess
import six
from six.moves import input
from six.moves import shlex_quote

CTL_SOCK = "/var/run/connector.sock"
CONTROLLER = "/usr/src/app/controller.py"

try:
    from subprocess import DEVNULL  # py3k
except ImportError:
    import os

    DEVNULL = open(os.devnull, 'wb')


def message(msg):
    print("[rshell]", msg, file=sys.stderr)


def info(msg):
    message("info: {}".format(msg))


def error(msg):
    print("* [rshell] Error:", msg, file=sys.stderr)


def fatal(msg):
    error(msg)
    sys.exit(1)


def register(args):
    if len(args) > 0 and args[0] in ("--help", "-h"):
        print("""
register [--help | -h]                          print this
register PORT [ NAME [ TYPE [ DESCRIPTION ] ] ] register service running on port PORT with specified NAME, TYPE
                                                and DESCRIPTION. When no NAME is specified PORT is used as NAME.
""")
        return
    if len(args) == 0 or not args[0]:
        error("register: port number missing")
        return
    port = args[0]
    name = args[1] if len(args) > 1 else port
    type = args[2] if len(args) > 2 else ''
    descr = args[3] if len(args) > 3 else ''
    message("Register port={} name={} type={} description={}".format(port, name, type, descr))

    subprocess.call([CONTROLLER, '--control-unix-socket', CTL_SOCK, "register",
                     "--name", name, "--type", type, "--description", descr, port],
                    env=os.environ)


def unregister(args):
    if len(args) > 0 and args[0] in ("--help", "-h"):
        print("""
unregister [--help | -h]  print this
unregister PORT | NAME    unregister service bound to the port PORT or named NAME
""")
        return
    if len(args) == 0 or not args[0]:
        error("unregister: port number or service name missing")
        return
    port = args[0]
    message("Unregister port={}".format(port))

    subprocess.call([CONTROLLER, '--control-unix-socket', CTL_SOCK, "unregister", port],
                    env=os.environ)


def getfreeport(args):
    if len(args) > 0 and args[0] in ("--help", "-h"):
        print("""
getfreeport [--help | -h] print this
getfreeport [NUM_PORTS]   print NUM_PORTS free TCP/IP ports""")
        return
    num_sockets = 1
    if len(args) > 0:
        try:
            num_sockets = int(args[0])
        except ValueError:
            error("getfreeport: argument is not an integer > 0")
            return
    if num_sockets <= 0:
        error("getfreeport: argument is not an integer > 0")
        return

    import socket
    sockets = []
    try:
        for i in range(num_sockets):
            s = socket.socket()
            sockets.append(s)
            s.bind(("", 0))
            print(s.getsockname()[1])
    finally:
        for s in sockets:
            try:
                s.close()
            except:
                pass


COMMANDS = {"getfreeport": getfreeport, "register": register, "unregister": unregister}


def run_cmd(args):
    if not args:
        return
    global COMMANDS
    if args[0] in ("exit", "quit", "q"):
        sys.exit(0)
    elif args[0] == "help":
        print("""Type exit, quit, or q to quit.
Commands you can use:
  help
  exit
  quit
  q""")
        for cname in six.iterkeys(COMMANDS):
            print("  " + cname)
    else:
        func = COMMANDS.get(args[0])
        if not func:
            error("Unsupported command {!r}: {}".format(
                args[0], ' '.join([shlex_quote(i) for i in args])))
        else:
            func(args[1:])


def run_commands(str):
    for line in re.split(r"[\n\r]", str):
        lexer = shlex.shlex(line, posix=True)
        lexer.wordchars += '-'
        cmd = []
        for token in lexer:
            if token == ';':
                run_cmd(cmd)
                del cmd[:]
            else:
                cmd.append(token)
        if len(cmd) > 0:
            run_cmd(cmd)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "-c":
        if len(sys.argv) > 2:
            run_commands(sys.argv[2])
        else:
            fatal("Missing command argument in -c option", file=sys.stderr)
    else:
        while True:
            try:
                line = input("> ")
            except (EOFError, KeyboardInterrupt):
                break
            run_commands(line)
