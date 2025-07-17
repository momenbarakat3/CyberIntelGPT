from stix2 import Indicator, Bundle
import json
from datetime import datetime, timezone
import os

# Load enriched IOCs
with open("output/enriched_iocs_with_xforce.json") as f:
    enriched_iocs = json.load(f)

indicators = []

def safe_stix_value(value):
    if isinstance(value, str):
        # Escape backslashes and double quotes for STIX compliance
        value = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{value}"'
    return value

def add_indicator(label, pattern, value):
    value = safe_stix_value(value)
    try:
        indicators.append(Indicator(
            name=f"{label} {value}",
            pattern=pattern.format(value),
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc)
        ))
    except Exception as e:
        print(f"[ERROR] Skipping indicator for value '{value}' due to STIX error: {e}")

# For free-text IOCs that break STIX grammar (commands, detection rules, etc.)
def add_freeform_indicator(label, value):
    try:
        indicators.append(Indicator(
            name=f"{label}",
            description=f"{value}",
            pattern="[x-def:custom = 'dummy']",
            pattern_type="stix",
            valid_from=datetime.now(timezone.utc)
        ))
    except Exception as e:
        print(f"[ERROR] Skipping freeform indicator '{value}': {e}")

# IPs
for ip_entry in enriched_iocs["ips"]:
    add_indicator("Malicious IP", "[ipv4-addr:value = {}]", ip_entry["ip"])

# Domains
for domain_entry in enriched_iocs["domains"]:
    add_indicator("Malicious Domain", "[domain-name:value = {}]", domain_entry["domain"])

# Emails
for email in enriched_iocs["emails"]:
    add_indicator("Suspicious Email", "[email-addr:value = {}]", email)

# URLs
for url_entry in enriched_iocs["urls"]:
    url_value = url_entry.get("url") if isinstance(url_entry, dict) else url_entry
    if url_value:
        add_indicator("Suspicious URL", "[url:value = {}]", url_value)

# Hashes
for hash_entry in enriched_iocs["hashes"]:
    add_indicator("Suspicious File Hash", "[file:hashes.'SHA-256' = {}]", hash_entry["hash"])

# CVEs
for cve in enriched_iocs["cves"]:
    add_indicator("CVE ID", "[vulnerability:external_references[*].external_id = {}]", cve)

# Archives
for item in enriched_iocs["archive_files"]:
    add_indicator("Suspicious Archive File", "[artifact:name = {}]", item)

# Commands (freeform with description)
for item in enriched_iocs["commands"]:
    add_freeform_indicator("Suspicious Command", item)

# LOLBins
for item in enriched_iocs["lolbins"]:
    add_indicator("LOLBIN Tool", "[software:name = {}]", item)

# Detection Rules (freeform with description)
for item in enriched_iocs["detection_rules"]:
    add_freeform_indicator("Detection Rule", item)

# Malware Names
for item in enriched_iocs["malware_names"]:
    add_indicator("Malware Name", "[malware:name = {}]", item)

# Redirectors
for item in enriched_iocs["redirectors"]:
    add_indicator("Redirector Service", "[x-def:infrastructure = {}]", item)

# Webmail Domains
for item in enriched_iocs["webmail_domains"]:
    add_indicator("Webmail Domain", "[domain-name:value = {}]", item)

# VPN Exit IPs
for item in enriched_iocs["vpn_exit_ips"]:
    add_indicator("VPN Exit IP", "[ipv4-addr:value = {}]", item)

# Phishing Indicators (freeform with description)
for item in enriched_iocs["phishing_indicators"]:
    add_freeform_indicator("Phishing Indicator", item)

# Debug: Confirm indicators generated
print(f"[DEBUG] Total Indicators Prepared: {len(indicators)}")

# Create STIX bundle
bundle = Bundle(objects=indicators)

# Ensure output directory exists
os.makedirs("output", exist_ok=True)

# Save to STIX JSON
with open('output/enriched_iocs_with_xforce_stix.json', 'w') as f:
    f.write(bundle.serialize(pretty=True))

print("[+] STIX JSON saved to output/enriched_iocs_stix.json")
