<div align="center">

# 🛡️ Agentic SOC Investigation Engine  

## 🧠 SOC Systems • Detection Engineering • Agentic Investigation

![Focus](https://img.shields.io/badge/Focus-SOC%20Analysis%20%7C%20ATT%26CK%20%7C%20Automation-blue?style=for-the-badge)
![Approach](https://img.shields.io/badge/Approach-Detection%20→%20Investigation%20→%20Decision-success?style=for-the-badge)
![Tech](https://img.shields.io/badge/Tech-Python%20%7C%20NLP%20%7C%20MITRE-black?style=for-the-badge)

</div>

<div align="center">
  <img src="images/demo.gif" width="900">
</div>

<p align="center"><em>End-to-end SOC investigation pipeline demonstrating ingestion → detection → analysis → response.</em></p>

---

## 🧠 Purpose

This project represents the **investigation and decision-support stage** of a progressively evolving SOC system.

| Stage | Description |
|------|------------|
| Alert Analysis | Understanding and triaging security events |
| Detection Engineering | Mapping behavior to MITRE ATT&CK |
| Investigation | Correlating and enriching alerts |
| Decision Support | Recommending response actions |

---

## 🎯 Objective

The goal of this phase is to demonstrate:

- how alerts are enriched with context  
- how related activity is correlated  
- how investigation workflows improve understanding  
- how reasoning leads to response decisions  
- how systems evolve toward AI-assisted SOC operations  

---

## 🤖 Phase 3 — Agentic SOC Investigation Engine

![Focus](https://img.shields.io/badge/Focus-Investigation%20%7C%20Automation-red)

| Category | Details |
|---------|--------|
| Focus | Investigation and decision support |
| Role | SOC analyst + automation system |
| Output | Investigation + response recommendation |

---

## 🧩 Key Capabilities

- alert correlation  
- IOC enrichment  
- vulnerability context  
- asset context  
- SOAR playbooks  
- investigation loop  
- response recommendation   

---

## 🧠 SOC Investigation Workflow

| Stage | Description |
|------|------------|
| 🟦 Raw Security Alert | Alert ingestion from SIEM |
| 🟨 Triage + ATT&CK Mapping | Behavioral classification |
| 🟪 SOAR Playbook Selection | Response logic selection |
| 🧠 AI-Assisted Analysis | Explanation generation |
| 🧬 Context Enrichment | IOC, vulnerability, asset context |
| 🔁 Investigation Loop | Iterative reasoning |
| 🚨 Response Recommendation | Final decision |

---

## ⚡ Quick Start (Run the Project)

Run the full investigation pipeline locally.

### 1. Clone the repository

```bash
git clone https://github.com/shannonasmith/Agentic-SOC-Investigation-Engine.git
cd Agentic-SOC-Investigation-Engine
```

---

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Download MITRE ATT&CK dataset

```bash
mkdir -p data/raw
curl -L "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" -o data/raw/enterprise-attack.json
```

---

### 5. Run the demo pipeline

```bash
chmod +x run_demo.sh
./run_demo.sh
```

---

### 📁 Expected Output

```text
output/
├── mapped_alerts.json
├── normalized_zeek_alerts.json
├── threat_hunt_findings.json
├── coverage_summary.json
```

---

## 👀 What This Looks Like in Practice

The following steps show how a single alert moves through the system — from ingestion to final response recommendation.

---

### ⚙️ Step 1 — Log Ingestion

<div align="center">
  <img src="images/01-ingestion-pipeline.png" width="700">
</div>

### 🔍 Processing

- alerts are ingested and normalized into structured inputs  

---

### 🔍 Step 2 — ATT&CK Mapping Output

<div align="center">
  <img src="images/02-attack-mapping-output.png" width="700">
</div>

### 🧠 Observations

- detections provide initial behavioral context  
- mapping alone is insufficient for full investigation

---

### ⚙️ Step 3 — SOAR + AI Analyst Layer

<div align="center">
  <img src="images/03-soar-ai-analyst-output.png" width="700">
</div>

### 📊 Output Includes

- playbook-driven investigation steps  
- structured analyst-style explanations 
  
---

### 🧬 Step 4 — Vulnerability + Asset Context

<div align="center">
  <img src="images/04-asset-vuln-context.png" width="700">
</div>

### 🔎 Findings

- enriched data increases confidence in prioritization  
- additional context reveals deeper attack patterns 
  
---

### 🤖 Step 5 — Investigation Agent

<div align="center">
  <img src="images/05-investigation-agent-output.png" width="700">
</div>

### 🧠 Insight

- decisions are driven by accumulated evidence  
- automation reduces manual analysis effort  

---

### 🔎 Step 6 — Threat Hunting Findings

<div align="center">
  <img src="images/06-threat-hunting-findings.png" width="700">
</div>

### 🌐 Expansion

- investigation expands beyond the initial alert  
- identifies related activity across the environment  

---

## ⚙️ Technical Pipeline (Under the Hood)

```text
Detection
    ↓
Triage Scoring
    ↓
ATT&CK Retrieval (TF-IDF)
    ↓
Semantic Reranking (Embeddings)
    ↓
Hybrid ATT&CK Scoring
    ↓
SOAR Playbook Selection
    ↓
AI Analyst Explanation
    ↓
IOC Enrichment
    ↓
Vulnerability Context
    ↓
Asset Context
    ↓
Stateful Investigation Loop
    ↓
Response Recommendation
```

---

## 💡 What This Project Demonstrates

- SOC investigation workflows  
- ATT&CK-based detection engineering  
- correlation + enrichment  
- agentic reasoning systems  
- decision-support automation  

---

## 💼 SOC Relevance

Simulates:

- Tier 1 / Tier 2 analyst workflows  
- incident investigation  
- threat prioritization  
- response decision-making  

---

## 🧬 Project Progression

This project is part of a **multi-phase SOC system**:

[SOC Alert Analyzer](https://github.com/shannonasmith/AI-Assisted-SOC-Alert-Analyzer) → [ATT&CK Mapping Engine](https://github.com/shannonasmith/AI-Assisted-SOC-MITRE-ATTACK-Mapping-Engine) → **Agentic SOC Investigation Engine (current)**

---

## 🚧 Future Improvements

- real-time ingestion  
- SIEM/XDR integration  
- threat intelligence feeds  
- autonomous response actions  

---

<div align="center">

## 👤 Shannon Smith  

Cybersecurity | SOC Operations • Detection Engineering • Incident Response • AI-Assisted Security  

</div>
