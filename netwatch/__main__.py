import json
import logging
import sys, getopt
from netwatch import scanner, sentinel


def main(argv):
    target = ""
    workspace_id = ""
    shared_key = ""
    output_file = None
    log_name = "NetworkAudit"
    try:
        opts, args = getopt.getopt(
            argv,
            "vht:w:k:l:f:",
            ["target=", "workspace-id=", "shared-key=", "log-name=", "file=", "verbose"],
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
            logging.basicConfig(format='%(levelname)s:%(message)s',level=logging.INFO)
        elif opt == "-h":
            print(
                "{0} -t <target host/network> -w <log analytics workspace id> -l <custom log name> -k <workspace shared key> [-f <outputfile>]".format(
                    __name__
                )
            )
            sys.exit(0)

    hosts = scanner.discover_hosts(target)
    logging.info("detected {0} hosts".format(len(hosts)))
    final_report = []
    for address in hosts:
        logging.info("scanning {0}".format(address))
        target_report = scanner.scan_target(address)
        detected_host = target_report.hosts.pop()
        services = []
        os = "unknown"
        for serv in detected_host.services:
            service = {
                "port": serv.port,
                "protocol": serv.protocol,
                "state": serv.state,
                "service": serv.service,
            }
            if len(serv.banner):
                service["banner"] = serv.banner
            services.append(service)
        if (
            detected_host.os_fingerprinted
            and len(detected_host.os_match_probabilities()) > 0
        ):
            os_probabilities = detected_host.os_match_probabilities()
            os = os_probabilities.pop().name

        report = {
            "id": detected_host.id,
            "network_address_IPv4": detected_host.address,
            "status": detected_host.status,
            "services": services,
            "os": os,
        }
        payload = json.dumps(report)
        final_report.append(report)
        if workspace_id:
            sentinel.post_data(workspace_id, shared_key, payload, log_name)

    if output_file:
        with open(output_file, "w") as f:
            f.write(json.dumps(final_report, indent=2))


if __name__ == "__main__":
    main(sys.argv[1:])
