import json
import sys, getopt, os
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
    print("[bold green]Easee Network Audit[/]")
    target = ""
    workspace_id = ""
    shared_key = ""
    output_file = None
    quick_scan = False
    log_name = "NetworkAudit"
    if os.geteuid() != 0:
        print(
            "Due to the nature of some of the scans used, this command needs to run as root"
        )
        sys.exit(1)

    try:
        opts, args = getopt.getopt(
            argv,
            "qht:w:k:l:f:n:",
            ["target=", "workspace-id=", "shared-key=", "log-name=", "file=", "quick"],
        )
    except getopt.GetoptError as e:
        print("Didn't understand, try using '-h' for help.")
        print(e.msg)
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-t", "--target"):
            target = arg
        elif opt in ("-w", "--workspace-id"):
            workspace_id = arg
        elif opt in ("-k", "--shared-key"):
            shared_key = arg
        elif opt in ("-l", "--log-name"):
            log_name = arg
        elif opt in ("-f", "--file"):
            output_file = arg
        elif opt in ("-q", "--quick"):
            quick_scan = True
        elif opt == "-h":
            print(r"-t \[target host/network]")
            print(r"-w \[log analytics workspace id]")
            print(r"-l \[custom log name]")
            print(r"-k \[workspace shared key]")
            print(r"-f \[outputfile] <optional>")
            sys.exit(0)

    hosts = scanner.discover_hosts(target)
    final_report = []
    console = Console(force_terminal=True, force_interactive=True)
    with Progress(console=console) as progress:
        report = scanner.scan_target(hosts, progress, quick_scan)
        for host in [host for host in report.hosts if host.is_up()]:
            host_report = transform_scan(host)
            final_report.append(host_report)
            if workspace_id:
                payload = json.dumps(host_report)
                sentinel.post_data(workspace_id, shared_key, payload, log_name)

    if output_file:
        with open(output_file, "w") as f:
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
    }
    return report


def get_os(host: NmapHost):
    rval = {"vendor": "unknown", "product": "unknown"}
    if host.is_up() and host.os_fingerprinted:
        cpelist = host.os.os_cpelist()
        if len(cpelist):
            mcpe = cpelist.pop()
            rval.update({"vendor": mcpe.get_vendor(), "product": mcpe.get_product()})
    return rval


if __name__ == "__main__":
    main(sys.argv[1:])
