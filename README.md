
# CyberIntelGPT: LLM-Driven IOC Extraction & Enrichment with SIEM & TIP-Ready Outputs

## 📌 Project Overview


**CyberIntelGPT** is a cybersecurity automation project designed to streamline the extraction and enrichment of **Indicators of Compromise (IOCs)** from unstructured **Cyber Threat Intelligence (CTI)** reports. Leveraging **Large Language Models (LLMs)**, the project automates the identification of relevant IOCs and enriches them through public intelligence services such as **VirusTotal** and **IBM X-Force Exchange**.

The extracted and enriched data is then formatted for seamless integration with industry-standard security tools, including **Security Information and Event Management (SIEM)** solutions and **Threat Intelligence Platforms (TIPs)**.

---

## Key Workflow

This project reflects a typical industry-standard threat intelligence pipeline used within SOC (Security Operations Center) environments and CTI teams:

1. **Extraction**  
   Using LLM-based models to extract IOCs from raw CTI reports (PDFs, unstructured text).

2. **Enrichment**  
   Supplementing extracted IOCs with additional context from public intelligence services like VirusTotal and IBM X-Force Exchange.

3. **Preparation for Ingestion**  
   Preparing the output in two formats:
   - **Flattened CSV**: Suitable for SIEM tools such as Splunk, QRadar, etc.
   - **STIX JSON**: Suitable for sharing through TIPs such as MISP, Anomali, IBM X-Force Threat Intelligence Platform, or even CERTs and ISACs.

---

## Why This Workflow?

This project demonstrates a realistic, industry-aligned workflow for operationalizing threat intelligence:

- **LLM-Based Automation** reduces manual analysis time when processing large CTI reports.
- **Public Enrichment Services** provide lightweight but valuable context without requiring costly enterprise licenses.
- **Output Standardization** aligns the data with existing security tooling and workflows for correlation, detection, and threat hunting activities.


---

## 📝 Input CTI Report

The provided CTI report used for this demo:
- **CSA_RUSSIAN_GRU_TARGET_LOGISTICS.pdf**
- Focus: Russian GRU targeting Western logistics & tech entities.
- [Official Report Reference (U.S. DoD & CISA)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141a)

---

---

## 📊 Pipeline Visualization

![Pipeline Diagram](assets/pipeline_diagram.png)

---

## 💡 How It Works

### 1️⃣ Extraction
- Extracts IOCs from PDF CTI reports using OpenAI GPT API (LLM-based extraction).

### 2️⃣ Enrichment
- Enriches IOCs using:
  - **VirusTotal API** (Free version provides meaningful enrichment)
  - **IBM X-Force Exchange API** (Free version provides limited/no enrichment)

### 3️⃣ Outputs
- **Flattened CSV** for SIEM tools (Splunk, QRadar, etc.)
- **STIX JSON** for Threat Intelligence Platforms (MISP, etc.)

---

##  Key Output Examples (Demo Screenshots)

### 📄 CSV Output Example for SIEM:
![CSV Output](assets/output_csv_example.PNG)

### 📑 JSON Enriched Output (VirusTotal):
![JSON Output](assets/output_json_example.PNG)

### 🗂️ STIX JSON Enriched Output (VirusTotal):
![STIX JSON Output](assets/output_stix_json_example.PNG)

### 🖥️ Terminal Execution Example:
![Terminal Success](assets/terminal_success_example.PNG)

---

## 💬 Important Notes
- **X-Force outputs are placeholders for demo only**. Limited enrichment due to freemium API.
- **VirusTotal outputs are meaningful and demonstrate the enrichment phase.**
- All API keys used are **free tier** except OpenAI, which requires **$1-2 credit**.

---

## ⚙️ Running the Project

### Prerequisites:
- Python 3.x environment
-  Create and activate a virtual environment:

### Activate your virtual environment:
```bash
# Windows
.\venv\Scripts\activate

# Linux/MacOS
source venv/bin/activate


### Running the Full Pipeline:
```bash
python src/main.py
```
### Installing Requirements
```bash
pip install -r requirements.txt
```

### Contents of requirements.txt
```ngnix
PyPDF2
stix2
pyyaml
requests
openai
```

---

## 🔄 Running Stages Separately (Optional)
For clarity on each stage's output:
```bash
python src/pdf_parser.py
python src/ioc_extractor.py
python src/enrich_with_virustotal.py
python src/enrich_with_xforce.py
python src/flatten_iocs_virustotal.py
python src/stix_converter_virustotal.py
python src/stix_converter_xforce.py
```

---

## 🛠️ What to Modify for Your Project

| File               | What to Change                 |
|--------------------|--------------------------------|
| `config/config.yaml` | API keys (keep secret, not committed) |
| `input/`           | Place your own CTI reports      |
| `output/`          | Output paths as per your needs  |

---

## 🔍 Project Gap Addressed

**Gap:** Unstructured CTI reports → SIEM/TIP-ready structured outputs.  
**Problem:** Manual parsing of CTI reports is inefficient, error-prone, and lacks scalability. SIEM and TIPs require structured inputs.

**How This Project Bridges It:**
- Automates extraction from CTI reports using LLMs.
- Provides machine-ingestible, enriched outputs ready for operational use (CSV for SIEM / STIX for TIP).
- Bridges the gap between CTI analysts and operational security tooling with clarity, speed, and accuracy.

---

## 📥 License & Contribution

This project is open-source and freely available for educational, research, and non-commercial cybersecurity use cases.  
Anyone is welcome to fork, reuse, or extend it for their own CTI pipelines or related projects.

**Pull requests for improvements or suggestions are highly encouraged.**

---

## 📌 Disclaimer
The outputs are from real CTI data but were **not tested on live SIEM or TIP tools**.

---
