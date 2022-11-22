import json
import logging
import sys
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException, NmapReport


def discover_hosts(target: str) -> list:
    scan_types = [
        {"name": "Ping", "args": ""},
        {"name": "UDP", "args": "-PU"},
        {"name": "ARP", "args": "-PR"},
        {"name": "TCP SYN", "args": "-PS22,135,80"},
    ]
    hosts = list()
    for scan_type in scan_types:
        logging.info("host discovery using {0} scan".format(scan_type["name"]))
        report = __discover_hosts(target, scan_type["args"], hosts)
        logging.info(
            "found {0} alive hosts of total {1}".format(
                report.hosts_up, report.hosts_total
            )
        )
        hosts.extend(
            host.address
            for host in report.hosts
            if host.address not in hosts and host.is_up()
        )

    return hosts


def __discover_hosts(target: str, options: str, exclude_hosts: list) -> NmapReport:
    parsed = None
    if len(exclude_hosts) > 0:
        nm = NmapProcess(
            target,
            options="-sn {0} --exclude {1}".format(options, ",".join(exclude_hosts)),
        )
    else:
        nm = NmapProcess(target, options="-sn {0}".format(options))

    rc = nm.sudo_run()
    if rc != 0:
        logging.error("something went wrong running host discovery: {0}".format(nm.stderr))
        sys.exit(2)
    try:
        parsed = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        logging.error("error while discovering hosts: {0}".format(e.msg))
    return parsed


def scan_target(target: str) -> NmapReport:
    parsed = None
    nm = NmapProcess(target, options="-sV -O -Pn -p- -T2")
    rc = nm.sudo_run()
    if rc != 0:
        logging.error("something went wrong running host scan: {0}".format(nm.stderr))
        sys.exit(2)
    try:
        parsed = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        logging.error("error while parsing scan: {0}".format(e.msg))
    return parsed
