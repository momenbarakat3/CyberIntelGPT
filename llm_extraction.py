import yaml
from openai import OpenAI
import json

# Load OpenAI API Key
with open('config/config.yaml') as f:
    config = yaml.safe_load(f)

client = OpenAI(api_key=config['openai_api_key'])

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
    ioc_json = response.choices[0].message.content
    return json.loads(ioc_json)
