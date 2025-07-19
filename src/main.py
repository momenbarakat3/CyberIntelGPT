import os
import json
from pdf_parser import extract_text_from_pdf
from ioc_extractor import extract_iocs_with_llm
import enrich_with_xforce
import enrich_with_virustotal
import flatten_iocs_virustotal
import stix_converter_xforce
import stix_converter_virustotal

# Ensure output directory exists
os.makedirs("../output", exist_ok=True)

# Step 1: Extract PDF text
pdf_path = os.path.join(os.path.dirname(__file__), '..', 'input', 'CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf')
pdf_text = extract_text_from_pdf(pdf_path)
print("[+] PDF Text Extraction Completed")

# Step 2: Extract IOCs with LLM
extracted_iocs = extract_iocs_with_llm(pdf_text)
with open('output/iocs_output.json', 'w') as f:
    json.dump(extracted_iocs, f, indent=4)
print("[+] LLM-based IOC Extraction Completed and Saved")

# Step 3: Enrich with IBM X-Force
enrich_with_xforce.main()
print("[+] Enrichment with IBM X-Force Completed")

# Step 4: Enrich with VirusTotal
enrich_with_virustotal.main()
print("[+] Enrichment with VirusTotal Completed")

# Step 5: Flatten VirusTotal IOC JSON for SIEM
flatten_iocs_virustotal.main()
print("[+] Flattened IOC CSV for SIEM Saved")

# Step 6: Convert X-Force to STIX
stix_converter_xforce.main()
print("[+] X-Force Enriched IOCs Converted to STIX")

# Step 7: Convert VirusTotal to STIX
stix_converter_virustotal.main()
print("[+] VirusTotal Enriched IOCs Converted to STIX")

print("\n[✓] All pipeline stages executed successfully.")
