import json
import csv

# Load the enriched JSON from VirusTotal
with open('output/enriched_iocs_with_virustotal.json', 'r') as f:
    enriched_iocs = json.load(f)

# Prepare output CSV
output_file = 'output/flattened_iocs_for_splunk.csv'

fields = ['type', 'value', 'source', 'context', 'description']

rows = []

# Flatten IPs
for ip_entry in enriched_iocs.get('ips', []):
    ip = ip_entry.get('ip')
    vt_data = ip_entry.get('virustotal', {}).get('data', {})
    context = ''
    if vt_data.get('attributes') and vt_data['attributes'].get('crowdsourced_context'):
        context = '; '.join([item.get('details', '') for item in vt_data['attributes']['crowdsourced_context']])
    rows.append(['ipv4', ip, 'VirusTotal', context, 'From VirusTotal API'])

# Flatten Domains
for domain_entry in enriched_iocs.get('domains', []):
    domain = domain_entry.get('domain')
    vt_data = domain_entry.get('virustotal', {}).get('data', {})
    context = vt_data.get('attributes', {}).get('reputation', '')
    rows.append(['domain', domain, 'VirusTotal', f'Reputation: {context}', 'From VirusTotal API'])

# Flatten Hashes (if present)
for hash_entry in enriched_iocs.get('hashes', []):
    hash_val = hash_entry.get('hash')
    vt_data = hash_entry.get('virustotal', {}).get('data', {})
    context = vt_data.get('attributes', {}).get('last_analysis_stats', '')
    rows.append(['hash', hash_val, 'VirusTotal', str(context), 'From VirusTotal API'])

# Emails, CVEs, URLs, Archive Files (carry forward simply)
for email in enriched_iocs.get('emails', []):
    rows.append(['email', email, 'N/A', '', 'From CTI Report'])

for cve in enriched_iocs.get('cves', []):
    rows.append(['cve', cve, 'N/A', '', 'From CTI Report'])

for url in enriched_iocs.get('urls', []):
    rows.append(['url', url, 'N/A', '', 'From CTI Report'])

for archive in enriched_iocs.get('archive_files', []):
    rows.append(['archive', archive, 'N/A', '', 'From CTI Report'])

# Write CSV
with open(output_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(fields)
    writer.writerows(rows)

print(f"[+] Flattened IOCs saved to {output_file}")
