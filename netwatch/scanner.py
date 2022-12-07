import logging
import os
from time import sleep
import sys
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException, NmapReport
from rich.progress import Progress
from rich.console import Console

log = logging.getLogger("rich")


def discover_hosts(target: str) -> list:
    scan_types = [
        {"name": "ICMP Echo", "args": "-PE"},
        {"name": "UDP", "args": "-PU"},
        {"name": "ARP", "args": "-PR"},
        {"name": "TCP SYN", "args": "-PS22,135,80"},
    ]
    console = Console(force_terminal=True, force_interactive=True)
    hosts = list()
    with Progress(console=console) as progress:
        for scan_type in progress.track(scan_types, description="Host discovery..."):
            report = __discover_hosts(target, scan_type["args"], hosts)
            progress.print(
                "[yellow]{0:>10s}[/]: Found [cyan]{1}[/] alive hosts of total {2}".format(
                    scan_type["name"], report.hosts_up, report.hosts_total
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
        nm = NmapProcess(
            target,
            options="-sn {0} -T5 --max-parallelism 100 --max-hostgroup 100 --max-rtt-timeout 100ms".format(
                options
            ),
        )

    if os.geteuid() != 0:
        rc = nm.sudo_run()
    else:
        rc = nm.run()
    if rc != 0:
        log.error("something went wrong running host discovery: {0}".format(nm.stderr))
        sys.exit(2)
    try:
        parsed = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        log.error("error while discovering hosts: {0}".format(e.msg))
    return parsed


def scan_target(
    target: list, progress: Progress, quick_scan: bool = False
) -> NmapReport:
    task = progress.add_task(
        "[cyan]Scanning {0} hosts \[{1}]".format(
            len(target), "quick" if quick_scan else "normal"
        ),
        start=False,
        total=100,
    )
    scan_options = [
        "-sS",
        "-Pn",
        "-T5",
        "--max-rtt-timeout 100ms",
        "--max-parallelism 100",
        "--min-hostgroup 100",
        "-O",
        "--osscan-limit",
    ]
    if not quick_scan:
        scan_options.append("-p-")
        scan_options.append("-sV")

    parsed = None
    nm = NmapProcess(target, options=" ".join(scan_options))
    if os.geteuid() != 0:
        nm.sudo_run_background()
    else:
        nm.run_background()
    progress.start_task(task)
    while nm.is_running():
        progress.update(task, completed=float(nm.progress))
        sleep(5)

    progress.update(task, completed=100)

    try:
        parsed = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        log.error("error while parsing scan: {0}".format(e.msg))
    return parsed
