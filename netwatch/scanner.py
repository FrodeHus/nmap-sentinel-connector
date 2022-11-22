import time
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException, NmapReport

def scan_network(target : str) -> NmapReport:
    parsed = None
    nm = NmapProcess(target, options="-sV -sS -T4 -O")
    nm.sudo_run_background()
    while nm.is_running:
        print("Scan is running: ETC: {0} Done: {1}%".format(nm.etc,nm.progress))
        time.sleep(5)
    
    try:
        parsed = NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        print("Error while parsing scan: {0}".format(e.msg))
    return parsed