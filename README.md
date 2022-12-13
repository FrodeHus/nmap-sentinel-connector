# nmap-sentinel-connector

A little utility to scan specified networks for connected devices and report to Azure Log Analytics Workspace for analysis with Microsoft Sentinel

## Installation

Requires:

- [nmap](https://nmap.org)

Install pre-requisite modules `python3 -m pip install -r requirements.txt`

## Run it

`python3 -m netaudit --target 192.168.1.0/24 -output-file output.json`

or using a config file:

`python3 -m netaudit --config-file sample-config.json`

### Using Docker

`docker run -it --rm -v ~/sample-config.json:/config.json reothor/networkaudit:latest --config-file /config.json`
