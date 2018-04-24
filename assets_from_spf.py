from __future__ import print_function
import sys
import dns.resolver

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
    )

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
    for item in spf_values:
        if 'ip4:' in item:
            assets.append(item.replace("ip4:",""))
        if 'ip6:' in item:
            assets.append(item.replace("ip6:",""))
        if 'include:' in item:
            assets.append(item.replace("include:",""))
        if 'ptr:' in item:
            assets.append(item.replace("ptr:",""))
        if 'a:' in item:
            assets.append(item.replace("a:",""))
        if 'mx:' in item:
            assets.append(item.replace("mx:",""))
        if 'exists:' in item:
            assets.append(item.replace("exists:",""))
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
