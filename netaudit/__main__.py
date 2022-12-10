import json
import sys, os, argparse
from time import sleep
from netaudit import scanner, sentinel
from rich.progress import Progress
from libnmap.objects import NmapHost
from rich import print
from rich.progress import track
from rich.console import Console
import logging
from rich.logging import RichHandler

from netaudit.types import ConfigFile, Target, LogAnalyticsConfig


FORMAT = "%(message)s"
logging.basicConfig(
    format=FORMAT, datefmt="[%X]", handlers=[RichHandler(rich_tracebacks=True)]
)


def main(argv):
    if os.geteuid() != 0:
        print(
            "Due to the nature of some of the scans used, this command needs to run as root"
        )
        sys.exit(1)

    boolAction = (
        argparse.BooleanOptionalAction
        if hasattr(argparse, "BooleanOptionalAction")
        else "store_true"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-file", type=str, help="Configuration file to be used")
    parser.add_argument("--target", type=str, help="Target host/network")
    parser.add_argument("--workspace", type=str, help="Workspace ID")
    parser.add_argument("--key", type=str, help="Workspace shared key")
    parser.add_argument(
        "--quick",
        action=boolAction,
        help="Enable quick scan",
        default=False,
    )
    parser.add_argument(
        "--log-name", type=str, help="Custom log name", default="NetworkAudit"
    )
    parser.add_argument("--output-file", type=str, help="Output file (JSON)")
    parser.add_argument("--schedule", help="Run scan every <num> minutes", type=int)

    args = parser.parse_args()
    if args.config_file:
        with open(args.config_file) as c:
            config_data = json.load(c)
            config = ConfigFile.from_dict(config_data)
    else:
        config = create_config_from_args(args)
    console = Console(force_terminal=True, force_interactive=True)
    console.rule(
        "{0}Easee Network Audit [yellow]\[{1} target(s)]".format(
            "Scheduled " if config.schedule else "", len(config.targets)
        ),
        align="left",
    )

    if config.schedule:
        while True:
            run_audit(config, console)
            for i in track(
                range(config.schedule),
                description="Waiting for next scan [{0} minutes]...".format(
                    config.schedule
                ),
            ):
                sleep(60)
    else:
        run_audit(config, console)


def create_config_from_args(args: argparse.Namespace) -> ConfigFile:
    target = Target(
        "Manual",
        args.target,
        args.quick,
        True if args.workspace else False,
        args.output_file,
    )
    targets = [target]
    if args.workspace:
        analytics_config = LogAnalyticsConfig(args.workspace, args.key, args.log_name)
    else:
        analytics_config = None
    schedule = args.schedule if args.schedule else None
    return ConfigFile(targets, analytics_config, schedule)


def run_audit(config: ConfigFile, console: Console):
    for target in config.targets:
        console.print("[cyan]\[{0}][/] {1}".format(target.name, target.target))
        hosts = scanner.discover_hosts(target.target)
        final_report = []
        with Progress(console=console) as progress:
            report = scanner.scan_target(hosts, progress, quick_scan=target.quick_scan)
            for host in [host for host in report.hosts if host.is_up()]:
                host_report = transform_scan(host)
                final_report.append(host_report)
                if target.send_to_analytics:
                    payload = json.dumps(host_report)
                    sentinel.post_data(
                        config.log_analytics_config.workspace_id,
                        config.log_analytics_config.shared_access_key,
                        payload,
                        config.log_analytics_config.log_name,
                    )

        if target.output_file:
            with open(target.output_file, "w") as f:
                f.write(json.dumps(final_report, indent=2))


def transform_scan(host: NmapHost):
    services = []
    os = "unknown"
    for serv in host.services:
        service = {
            "port": serv.port,
            "protocol": serv.protocol,
            "state": serv.state,
            "service": serv.service,
        }
        if len(serv.banner):
            service["banner"] = serv.banner
        services.append(service)
    host_os = get_os(host)

    report = {
        "id": host.id,
        "network_address_IPv4": host.address,
        "status": host.status,
        "services": services,
        "vendor": host_os["vendor"],
        "product": host_os["product"],
        "os_match": host_os["os_match"],
    }
    return report


def get_os(host: NmapHost):
    rval = {"vendor": "unknown", "product": "unknown", "os_match": "unknown"}
    if host.is_up() and host.os_fingerprinted:
        cpelist = host.os.os_cpelist()
        if len(host.os.osmatches) > 0:
            host.os.osmatches.sort(key=lambda m: m.accuracy, reverse=True)
            os_match = host.os.osmatches.pop()
        if len(cpelist):
            mcpe = cpelist.pop()
            rval.update(
                {
                    "vendor": mcpe.get_vendor(),
                    "product": mcpe.get_product(),
                    "os_match": os_match.name if os_match else "unknown",
                }
            )
    return rval


if __name__ == "__main__":
    main(sys.argv[1:])
