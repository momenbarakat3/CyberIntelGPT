import requests
import json
import yaml
import os

# Load config
with open('config/config.yaml') as f:
    config = yaml.safe_load(f)

VT_API_KEY = config['virustotal_api_key']
HEADERS = {
    "x-apikey": VT_API_KEY
}

def enrich_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)
    return response.json()

def enrich_domain(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    response = requests.get(url, headers=HEADERS)
    return response.json()

def enrich_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    return response.json()

def enrich_url(url_to_check):
    # VirusTotal requires URL encoding
    url_id = requests.utils.quote(url_to_check, safe='')
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    response = requests.get(url, headers=HEADERS)
    return response.json()

# Load IOCs from LLM output
with open('output/iocs_output.json') as f:
    iocs = json.load(f)

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
    enriched["ips"].append({"ip": ip, "virustotal": enrich_ip(ip)})

# Enrich Domains
for domain in iocs['domains']:
    enriched["domains"].append({"domain": domain, "virustotal": enrich_domain(domain)})

# Enrich Hashes
for hash_value in iocs['hashes']:
    enriched["hashes"].append({"hash": hash_value, "virustotal": enrich_hash(hash_value)})

# Enrich URLs
for url in iocs['urls']:
    url_value = url.get("url") if isinstance(url, dict) else url
    if url_value:
        enriched["urls"].append({"url": url_value, "virustotal": enrich_url(url_value)})

# Ensure output directory exists
os.makedirs("output", exist_ok=True)

# Save enriched output
with open('output/enriched_iocs_with_virustotal.json', 'w') as f:
    json.dump(enriched, f, indent=4)

print("[+] Enriched IOCs saved to output/enriched_iocs.json using VirusTotal API.")
