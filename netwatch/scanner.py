import json
import sys
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException, NmapReport

def discover_hosts(target : str) -> list:
    scan_types = ["-PS22,135,80", "-PU", "-PR"]
    hosts = list()
    for scan_type in scan_types:
        report = __discover_hosts(target, scan_type)
        hosts.extend(host.address for host in report.hosts if host.address not in hosts and host.is_up())
    
    return hosts

def __discover_hosts(target: str, options:str) -> NmapReport:
    parsed = None
    nm = NmapProcess(target, options="-sn {0}".format(options))
    rc = nm.sudo_run()
    if rc != 0:
        print("Something went wrong running host discovery: {0}".format(nm.stderr))
        sys.exit(2)
    try:
        parsed = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        print("Error while discovering hosts: {0}".format(e.msg))
    return parsed


def scan_network(target: str) -> NmapReport:
    parsed = None
    nm = NmapProcess(target, options="-sV -O -Pn")
    rc = nm.sudo_run()
    if rc != 0:
        print("Something went wrong running host scan: {0}".format(nm.stderr))
        sys.exit(2)
    try:
        parsed = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        print("Error while parsing scan: {0}".format(e.msg))
    return parsed
