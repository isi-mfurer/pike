#!/usr/bin/env python
"""
Used by CI to wait for the port to accept connections
"""

import argparse
import socket
import sys
import time


def ping_port(ip, port, timeout, step=1):
    """
    Attempt to open a TCP connection to (ip, port) and close it immediately.

    Determines if the port is accepting connections.

    :param ip: ip or hostname to connect to
    :param port: TCP port number
    :param timeout: maximum time to retry connections
    :param step: time to sleep before trying again
    :return: True if the connection was established. False if all retry attempts are
             exhausted without establishing connection
    """
    family = socket.AF_INET
    if ":" in ip:
        family = socket.AF_INET6

    def attempt():
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((str(ip), int(port)))
            s.close()
            print("Successfully connect to {}:{}".format(ip, port))
            return True
        except (socket.error, socket.gaierror):
            pass

    start = time.time()
    while time.time() - start < timeout:
        if attempt():
            return True
        time.sleep(step)
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost", help="the host to check")
    parser.add_argument("--port", default=445, help="the port to check")
    parser.add_argument(
        "--timeout", default=60, help="exit non-zero after the timeout expires"
    )
    args = parser.parse_args(sys.argv[1:])
    if ping_port(args.host, args.port, float(args.timeout)):
        sys.exit(0)
    sys.exit(1)
