import json
import sys, os, argparse
from netwatch import scanner, sentinel
from rich.progress import Progress
from libnmap.objects import NmapHost
from rich import print
from rich.console import Console
import logging
from rich.logging import RichHandler


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

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=str, help="Target host/network", required=True)
    parser.add_argument("--workspace", type=str, help="Workspace ID")
    parser.add_argument("--key", type=str, help="Workspace shared key")
    parser.add_argument(
        "--quick",
        action=argparse.BooleanOptionalAction,
        help="Enable quick scan",
        default=False,
    )
    parser.add_argument(
        "--log-name", type=str, help="Custom log name", default="NetworkAudit"
    )
    parser.add_argument("--output-file", type=str, help="Output file (JSON)")

    args = parser.parse_args()

    console = Console(force_terminal=True, force_interactive=True)
    console.rule("Easee Network Audit", align="left")

    hosts = scanner.discover_hosts(args.target)
    final_report = []
    with Progress(console=console) as progress:
        report = scanner.scan_target(hosts, progress, quick_scan=args.quick)
        for host in [host for host in report.hosts if host.is_up()]:
            host_report = transform_scan(host)
            final_report.append(host_report)
            if args.workspace:
                payload = json.dumps(host_report)
                sentinel.post_data(args.workspace, args.key, payload, args.log_name)

    if args.output_file:
        with open(args.output_file, "w") as f:
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
