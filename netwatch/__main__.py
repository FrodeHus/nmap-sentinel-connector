import json
import socket
import sys, getopt
from netwatch import scanner, sentinel


def main(argv):
    target = ""
    workspace_id = ""
    shared_key = ""
    log_name = "NetworkAudit"
    try:
        opts, args = getopt.getopt(
            argv, "ht:w:k:l:", ["target=", "workspace-id=", "shared-key=", "log-name="]
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
        elif opt == "-h":
            print("{0} -t <target host/network>".format(__name__))

    report = scanner.scan_network(target)
    hosts = []
    online_hosts = (host for host in report.hosts if host.is_up())
    for host in online_hosts:
        services = []
        os = 'unknown'        
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
        if len(host.hostnames):
            hostname = host.hostnames.pop()
        else:
            hostname = socket.gethostbyaddr(host.address)
        if host.os_fingerprinted:
            os_probabilities = host.os_match_probabilities()
            os = os_probabilities.pop().name
            
        report = {
            "id": host.id,
            "hostname": hostname,
            "network_address_IPv4": host.address,
            "status": host.status,
            "services": services,
            "os": os
        }
        hosts.append(report)

    payload = json.dumps(hosts)
    sentinel.post_data(workspace_id, shared_key, payload, log_name)


if __name__ == "__main__":
    main(sys.argv[1:])
