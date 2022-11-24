# nmap-sentinel-connector

A little utility to scan specified networks for connected devices and report to Azure Log Analytics Workspace for analysis with Microsoft Sentinel

## Installation

Requires:
- [nmap](https://nmap.org)

Install pre-requisite modules `python3 -m pip install -r requirements.txt`

## Run it

`python3 -m netwatch -t 192.168.1.0/24 -f output.json`
