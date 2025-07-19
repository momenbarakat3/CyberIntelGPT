def main():   

    import requests
    import yaml
    import json

    # Load API credentials
    with open('config/config.yaml') as f:
        config = yaml.safe_load(f)

    auth = (config['xforce_api_key'], config['xforce_password'])

    # Enrichment Functions (Only IPs, Domains, Hashes, URLs are supported by X-Force)
    def enrich_ip(ip):
        r = requests.get(f"https://api.xforce.ibmcloud.com/ipr/{ip}", auth=auth)
        return r.json()

    def enrich_domain(domain):
        r = requests.get(f"https://api.xforce.ibmcloud.com/url/{domain}", auth=auth)
        return r.json()

    def enrich_hash(hash_value):
        r = requests.get(f"https://api.xforce.ibmcloud.com/malware/{hash_value}", auth=auth)
        return r.json()

    def enrich_url(url):
        r = requests.get(f"https://api.xforce.ibmcloud.com/url/{url}", auth=auth)
        return r.json()

    # Load extracted IOCs
    with open('output/iocs_output.json') as f:
        iocs = json.load(f)

    # Prepare enrichment structure
    enriched = {
        "ips": [],
        "domains": [],
        "hashes": [],
        "urls": [],
        "emails": iocs["emails"],
        "cves": iocs["cves"],
        "archive_files": iocs["archive_files"],
        "commands": iocs["commands"],
        "lolbins": iocs["lolbins"],
        "detection_rules": iocs["detection_rules"],
        "malware_names": iocs["malware_names"],
        "redirectors": iocs["redirectors"],
        "webmail_domains": iocs["webmail_domains"],
        "vpn_exit_ips": iocs["vpn_exit_ips"],
        "phishing_indicators": iocs["phishing_indicators"],
    }

    # Enrich IPs
    for ip in iocs['ips']:
        enriched["ips"].append({"ip": ip, "xforce": enrich_ip(ip)})

    # Enrich Domains
    for domain in iocs['domains']:
        enriched["domains"].append({"domain": domain, "xforce": enrich_domain(domain)})

    # Enrich Hashes
    for hash_value in iocs['hashes']:
        enriched["hashes"].append({"hash": hash_value, "xforce": enrich_hash(hash_value)})

    # Enrich URLs
    for url in iocs['urls']:
        enriched["urls"].append({"url": url, "xforce": enrich_url(url)})

    # Save enriched output
    with open('output/enriched_iocs_with_xforce.json', 'w') as f:
        json.dump(enriched, f, indent=4)

    print("[+] Enriched IOCs saved to output/enriched_iocs.json")


if __name__ == "__main__":
    main()