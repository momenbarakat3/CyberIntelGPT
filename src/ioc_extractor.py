import yaml
from openai import OpenAI
import json
import re

# Load OpenAI API Key from config.yaml
with open('config/config.yaml') as f:
    config = yaml.safe_load(f)

client = OpenAI(api_key=config['openai_api_key'])


def escape_backslashes_in_dict(data):
    for key, items in data.items():
        if isinstance(items, list):
            data[key] = [item.replace("\\", "\\\\") if isinstance(item, str) else item for item in items]
    return data


def extract_iocs_with_llm(text):
    prompt = f"""
Extract all the following Indicators of Compromise (IOCs) from this text. Return JSON structured like this:
{{
    "ips": [],
    "domains": [],
    "emails": [],
    "urls": [],
    "hashes": [],
    "cves": [],
    "archive_files": [],
    "commands": [],
    "lolbins": [],
    "detection_rules": [],
    "malware_names": [],
    "redirectors": [],
    "webmail_domains": [],
    "vpn_exit_ips": [],
    "phishing_indicators": []
}}
Text:
{text}
"""

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}]
    )

    # Raw LLM response (likely with ```json markdown)
    ioc_json = response.choices[0].message.content.strip()

    # Remove markdown formatting if present
    if ioc_json.startswith("```json"):
        ioc_json = re.sub(r"```json\s*", "", ioc_json)
        ioc_json = re.sub(r"```", "", ioc_json).strip()

    # Convert cleaned string to JSON object
    iocs = json.loads(ioc_json)

    # Escape backslashes for JSON compliance
    iocs = escape_backslashes_in_dict(iocs)

    # Save to output file
    with open('../output/iocs_output.json', 'w') as f:
        json.dump(iocs, f, indent=4)

    return iocs
