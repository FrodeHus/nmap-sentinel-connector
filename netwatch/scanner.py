import json
import sys
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException, NmapReport

def discover_hosts(target : str) -> list:
    scan_types = ["", "-PU", "-PR", "-PS22,135,80"]
    hosts = list()
    for scan_type in scan_types:
        report = __discover_hosts(target, scan_type, hosts)
        hosts.extend(host.address for host in report.hosts if host.address not in hosts and host.is_up())
    
    return hosts

def __discover_hosts(target: str, options:str, exclude_hosts : list) -> NmapReport:
    parsed = None
    if len(exclude_hosts)>0:
        nm = NmapProcess(target, options="-sn {0} --exclude {1}".format(options, ",".join(exclude_hosts)))
    else:
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
    nm = NmapProcess(target, options="-sV -O -Pn -p- -T2")
    rc = nm.sudo_run()
    if rc != 0:
        print("Something went wrong running host scan: {0}".format(nm.stderr))
        sys.exit(2)
    try:
        parsed = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        print("Error while parsing scan: {0}".format(e.msg))
    return parsed
