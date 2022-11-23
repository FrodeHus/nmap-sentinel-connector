import json
import concurrent.futures
from loguru import logger as logging
import sys, getopt, os
from netwatch import scanner, sentinel
from rich.progress import Progress
from libnmap.objects import NmapHost
from rich import print
from rich.console import Console


def main(argv):
    target = ""
    workspace_id = ""
    shared_key = ""
    output_file = None
    log_name = "NetworkAudit"
    if os.geteuid() != 0:
        print(
            "Due to the nature of some of the scans used, this command needs to run as root"
        )
        sys.exit(1)

    try:
        opts, args = getopt.getopt(
            argv,
            "vht:w:k:l:f:",
            [
                "target=",
                "workspace-id=",
                "shared-key=",
                "log-name=",
                "file=",
                "verbose",
            ],
        )
    except getopt.GetoptError:
        print("{0} -t <target host/network>".format(__name__))
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
        elif opt in ("-v", "--verbose"):
            logging.remove()
            logging.add(
                sys.stdout,
                level="INFO",
                format="[{time:HH:mm:ss}] {level} <yellow>{name}</yellow> <level>{message}</level>",
                colorize=True,
            )
        elif opt == "-h":
            print(r"-t \[target host/network]")
            print(r"-w \[log analytics workspace id]")
            print(r"-l \[custom log name]")
            print(r"-k \[workspace shared key]")
            print(r"-f \[outputfile] <optional>")
            sys.exit(0)

    hosts = scanner.discover_hosts(target)
    print("Detected [cyan]{0}[/] hosts".format(len(hosts)))
    final_report = []
    console = Console(force_terminal=True, force_interactive=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        with Progress(console=console) as progress:
            try:
                future_to_scan = {
                    executor.submit(scanner.scan_target, target, progress): target
                    for target in hosts
                }
                for future in concurrent.futures.as_completed(future_to_scan):
                    target = future_to_scan[future]
                    try:
                        report = future.result()
                    except Exception as e:
                        logging.error(
                            "{t} generated an exception: {msg}", t=target, msg=e.msg
                        )
                    else:
                        host = report.hosts.pop()
                        host_report = transform_scan(host)
                        final_report.append(host_report)
                        if workspace_id:
                            payload = json.dumps(host_report)
                            sentinel.post_data(
                                workspace_id, shared_key, payload, log_name
                            )

            except KeyboardInterrupt:
                executor.shutdown(wait=False)

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
    if host.os_fingerprinted and len(host.os_match_probabilities()) > 0:
        os_probabilities = host.os_match_probabilities()
        os = os_probabilities.pop().name

    report = {
        "id": host.id,
        "network_address_IPv4": host.address,
        "status": host.status,
        "services": services,
        "os": os,
    }
    return report


if __name__ == "__main__":
    main(sys.argv[1:])
