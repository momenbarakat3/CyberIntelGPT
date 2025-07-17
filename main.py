from utils.pdf_parser import extract_text_from_pdf
from utils.ioc_extractor import extract_iocs_with_llm
import json
import os

input_file = "input/CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf"
output_file = "output/iocs_output.json"

# Extract text from the PDF
pdf_text = extract_text_from_pdf(input_file)

# Extract IOCs using OpenAI LLM
extracted_iocs = extract_iocs_with_llm(pdf_text)

# Ensure output directory exists
os.makedirs(os.path.dirname(output_file), exist_ok=True)

# Save the output to JSON
with open(output_file, "w") as f:
    json.dump(extracted_iocs, f, indent=4)

print(f"[+] Raw IOCs saved to {output_file}")
