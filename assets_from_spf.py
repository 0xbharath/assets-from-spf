from __future__ import print_function
import sys
import re
import json
from socket import gethostbyname, gaierror
import click
from ipwhois.net import Net
from ipwhois.asn import IPASN

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
    )

try:
    import dns.resolver
except ImportError:
    logging.info("\033[1;31m[!] Failed to import dnspython module. Run 'pip install dnspython'\033[1;m")
    sys.exit()

__author__  = "Bharath(github.com/yamakira)"
__version__ = "0.0.1"
__purpose__ = '''Extract domains/netblocks for a SPF record'''

logger = logging.getLogger('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def get_spf_record(domain):
    try:
        answers = dns.resolver.query(domain, 'TXT', raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        logger.info("[+] Couldn't resolve the domain {}".format(domain))
        sys.exit(1)
    for rdata in answers:
        for record in rdata.strings:
            if 'spf1' in record:
                spf_record=record
    if 'spf_record' in locals():
        return spf_record
    else:
        logger.info("[+] {} doesn't support SPF record ".format(domain))
        sys.exit(1)

def get_assets(spf_record):
    assets = []
    spf_values = spf_record.split(" ")
    # List of all mechanisms as part of SPF standard
    mechanisms = ['ip4:','ip6:','ptr:','include:','a:','include:','mx:','exists:']
    for item in spf_values:
        # Check for SPF mechanisms in each part of SPF record
        if any(mechanism in item for mechanism in mechanisms):
            assets.append(item)
    return assets

def enumerate_asn(assets):
    assets_report = {}
    asn_details = []
    mechanisms = ['ip4:','ip6:','ptr:','include:','a:','include:','mx:','exists:']
    for asset in assets:
        if asset.startswith('ip4:') or asset.startswith('ip6:'):
            cidr_value = re.sub(r'|'.join(map(re.escape, mechanisms)), '', asset)
            ip_address = cidr_value.split("/")[0]
            asn_details = get_asn(ip_address)
            assets_report[ip_address] = asn_details
        elif asset.startswith('include:'):
            domain = re.sub(r'|'.join(map(re.escape, mechanisms)), '', asset)
            try:
                ip_address = gethostbyname(domain)
                asn_details = get_asn(ip_address)
                assets_report[domain] = asn_details
            except gaierror as e:
                assets_report[domain] = "No valid A record exists"

    return assets_report

def get_asn(ip_address):
    net = Net(ip_address)
    obj = IPASN(net)
    asn_details = obj.lookup()
    return asn_details

def print_assets(assets):
    mechanisms = ['ip4:','ip6:','ptr:','include:','a:','include:','mx:','exists:']
    for asset in assets:
        asset = re.sub(r'|'.join(map(re.escape, mechanisms)), '', asset)
        print(asset)

@click.command()
@click.argument('domain')
@click.option('--asn/--no-asn', '-a', default=False,
                help='Enable/Disable ASN enumeration')
def main(domain, asn):
    spf_record = get_spf_record(domain)
    assets = get_assets(spf_record)
    #for asset in set(assets):
    #    print(asset)
    #print(json.dumps(assets, default=str))
    if asn == True:
        assets_reports = enumerate_asn(assets)
        print(json.dumps(assets_reports, default=str))
    else:
        print_assets(assets)

if __name__ == '__main__':
    main()
