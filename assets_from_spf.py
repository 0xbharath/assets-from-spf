from __future__ import print_function
import sys
import re
import json

try:
    import dns.resolver
except ImportError:
    logging.info("\033[1;31m[!] Failed to import dnspython module. Run 'pip install dnspython'\033[1;m")
    sys.exit()

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
    )

__author__  = "Bharath(github.com/yamakira)"
__version__ = "0.0.1"
__purpose__ = '''Extract domains/netblocks for a SPF record'''

logger = logging.getLogger('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def get_spf_record(domain):
    try:
        answers = dns.resolver.query(domain, 'TXT')
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
            # Replace the mechanism's keyword to extract only the asset value
            asset = re.sub(r'|'.join(map(re.escape, mechanisms)), '', item)
            assets.append(asset)
    return assets

def get_domain():
    if len(sys.argv) <= 1:
        print("Usage: python domain_enum_csp.py <target_domain>\n")
        sys.exit(1)
    else:
        return sys.argv[1]

def main():
    domain = get_domain() 
    spf_record = get_spf_record(domain)
    assets = get_assets(spf_record)
    for asset in set(assets):
        print(asset)

if __name__ == '__main__':
    main()
