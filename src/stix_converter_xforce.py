from stix2 import Indicator, Bundle
import json
from datetime import datetime, timezone
import os


def sanitize(value):
    if isinstance(value, str):
        return value.strip().strip('"').strip("'")
    return value


def main():
    # Load enriched IOCs
    with open("output/enriched_iocs_with_xforce.json") as f:
        enriched_iocs = json.load(f)

    indicators = []

    def add_indicator(label, pattern, value):
        value = sanitize(value)
        try:
            indicators.append(Indicator(
                name=f"{label} {value}",
                pattern=pattern.format(value),
                pattern_type="stix",
                valid_from=datetime.now(timezone.utc)
            ))
        except Exception:
            pass  # Skip problematic indicators silently

    def add_freeform_indicator(label, value):
        try:
            indicators.append(Indicator(
                name=f"{label}",
                description=f"{value}",
                pattern="[x-def:custom = 'dummy']",
                pattern_type="stix",
                valid_from=datetime.now(timezone.utc)
            ))
        except Exception:
            pass  # Skip problematic indicators silently

    for ip_entry in enriched_iocs["ips"]:
        add_indicator("Malicious IP", "[ipv4-addr:value = '{}']", ip_entry["ip"])

    for domain_entry in enriched_iocs["domains"]:
        add_indicator("Malicious Domain", "[domain-name:value = '{}']", domain_entry["domain"])

    for email in enriched_iocs["emails"]:
        add_indicator("Suspicious Email", "[email-addr:value = '{}']", email)

    for url_entry in enriched_iocs["urls"]:
        url_value = url_entry.get("url") if isinstance(url_entry, dict) else url_entry
        if url_value:
            add_indicator("Suspicious URL", "[url:value = '{}']", url_value)

    for hash_entry in enriched_iocs["hashes"]:
        add_indicator("Suspicious File Hash", "[file:hashes.'SHA-256' = '{}']", hash_entry["hash"])

    for cve in enriched_iocs["cves"]:
        add_indicator("CVE ID", "[vulnerability:external_references[*].external_id = '{}']", cve)

    for item in enriched_iocs["archive_files"]:
        add_indicator("Suspicious Archive File", "[artifact:name = '{}']", item)

    for item in enriched_iocs["commands"]:
        add_freeform_indicator("Suspicious Command", item)

    for item in enriched_iocs["lolbins"]:
        add_indicator("LOLBIN Tool", "[software:name = '{}']", item)

    for item in enriched_iocs["detection_rules"]:
        add_freeform_indicator("Detection Rule", item)

    for item in enriched_iocs["malware_names"]:
        add_indicator("Malware Name", "[malware:name = '{}']", item)

    for item in enriched_iocs["redirectors"]:
        add_indicator("Redirector Service", "[x-def:infrastructure = '{}']", item)

    for item in enriched_iocs["webmail_domains"]:
        add_indicator("Webmail Domain", "[domain-name:value = '{}']", item)

    for item in enriched_iocs["vpn_exit_ips"]:
        add_indicator("VPN Exit IP", "[ipv4-addr:value = '{}']", item)

    for item in enriched_iocs["phishing_indicators"]:
        add_freeform_indicator("Phishing Indicator", item)

    bundle = Bundle(objects=indicators)

    os.makedirs("output", exist_ok=True)

    with open('output/enriched_iocs_xforce_stix.json', 'w') as f:
        f.write(bundle.serialize(pretty=True))

    print("[✓] IBM X-Force Enrichment STIX Export Completed.")


if __name__ == "__main__":
    main()
