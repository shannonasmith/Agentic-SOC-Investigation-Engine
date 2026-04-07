<div align="center">

## 🛡️ Agentic SOC Investigation Engine  
### ATT&CK Mapping, AI-Assisted Analysis, SOAR Playbooks & Stateful Investigation

![Category](https://img.shields.io/badge/Category-SOC%20Engineering-red?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Agentic%20IR%20%2B%20ATT%26CK%20Mapping-blue?style=for-the-badge)
![Tech](https://img.shields.io/badge/Tech-AI%20%2B%20SOAR%20%2B%20Detection%20Pipeline-black?style=for-the-badge)

</div>

<div align="center">
  <img src="images/05-investigation-agent-output.png" width="700">
</div>

<p align="center"><em>Figure 1. Investigation agent output showing response recommendation after ATT&CK mapping, enrichment, and confidence-based decisioning.</em></p>

---

## 🧠 Scenario

This project simulates how a **modern Security Operations Center (SOC)** can process alerts from detection through response using a combination of:

- MITRE ATT&CK mapping  
- SOAR playbooks  
- AI-assisted analyst output  
- context enrichment  
- vulnerability-aware prioritization  
- asset criticality awareness  
- a stateful investigation agent  

Rather than stopping at classification, the system continues through investigation and decision support to recommend response actions.

---

## 🎯 Objective

The goal of this project was to build a **production-style SOC investigation pipeline** that moves from:

Raw Security Alert  
↓  
Triage + ATT&CK Mapping  
↓  
SOAR Playbook Selection  
↓  
AI-Assisted Analyst Explanation  
↓  
IOC / Vulnerability / Asset Enrichment  
↓  
Stateful Investigation Agent  
↓  
Response Recommendation  

This project demonstrates how raw telemetry can be transformed into actionable, explainable security decisions.

---

## 🧠 Platform Workflow

Detection  
↓  
Triage Scoring  
↓  
TF-IDF Candidate Retrieval  
↓  
Embedding-Based Reranking  
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
Asset Criticality Context  
↓  
Stateful Investigation Agent  
↓  
Response Recommendation  

---

## 🔍 ATT&CK Mapping Engine

This project uses a **hybrid ATT&CK mapping approach** rather than simple keyword matching.

### Mapping pipeline:
- TF-IDF retrieval generates initial ATT&CK candidates  
- sentence-transformer embeddings improve semantic similarity ranking  
- rule-based scoring reinforces behavior-specific detections  
- field-aware scoring incorporates alert structure  
- tactic-aware scoring improves contextual alignment  
- confidence scoring ranks likely ATT&CK techniques  

This approach improves accuracy, explainability, and consistency of mappings.

---

## ⚙️ Core Capabilities

### 1. MITRE ATT&CK Mapping
- hybrid retrieval and scoring engine  
- ranked ATT&CK technique candidates  
- confidence-based mapping output  
- ATT&CK Navigator export  

### 2. SOAR Playbooks
Implemented response logic for:
- credential access  
- lateral movement  
- defense evasion  
- reconnaissance  
- collection  
- persistence  

### 3. AI-Assisted Analyst Output
- contextual explanation of alerts  
- risk summary  
- investigation guidance  
- analyst-friendly output  

### 4. IOC Enrichment
- internal vs external classification  
- threat indicator tagging  
- decision influence based on context  

### 5. Vulnerability-Aware Decisioning
- CVE-based enrichment  
- risk prioritization  
- vulnerability context integrated into decisions  

### 6. Asset Criticality Awareness
- differentiates high-value systems from standard endpoints  
- influences prioritization and response decisions  
- supports business-impact-driven workflows  

### 7. Threat Hunting Layer
- identifies high-confidence detections  
- surfaces high-risk techniques  
- detects critical vulnerability exposure across alerts  

### 8. Stateful Investigation Agent
- initializes case state per alert  
- selects enrichment actions dynamically  
- updates confidence after each step  
- maintains investigation context  
- recommends response actions  
- logs investigation reasoning  

---

## 🤖 Why It’s Agentic

The system behaves as an agent because it:

- maintains state  
- selects actions dynamically  
- executes enrichment steps  
- updates confidence based on evidence  
- decides when to stop  
- recommends response actions  

This enables structured, explainable investigation workflows rather than static pipelines.

---

## 🖥️ Environment

| Tool | Purpose |
|---|---|
| Python | Core platform |
| Splunk-style alerts | Detection input |
| scikit-learn | TF-IDF retrieval |
| sentence-transformers | Embedding similarity |
| MITRE ATT&CK | Technique mapping |
| JSON datasets | Alerts, vulnerabilities, assets |
| Custom SOAR logic | Response simulation |

---

## ⚙️ Step 1 — Project Structure

<div align="center">
  <img src="images/01-project-structure.png" width="600">
</div>

<p align="center"><em>Figure 2. Project structure showing separation between mapping, SOAR, enrichment, and agent logic.</em></p>

---

## 🔍 Step 2 — ATT&CK Mapping Output

<div align="center">
  <img src="images/02-attack-mapping-output.png" width="700">
</div>

<p align="center"><em>Figure 3. Hybrid ATT&CK mapping output with ranked techniques and confidence scores.</em></p>

---

## ⚙️ Step 3 — SOAR + AI Analyst Layer

<div align="center">
  <img src="images/03-soar-ai-analyst-output.png" width="700">
</div>

<p align="center"><em>Figure 4. SOAR playbook output and AI-assisted analyst explanation.</em></p>

---

## 🧬 Step 4 — Vulnerability + Asset Context

<div align="center">
  <img src="images/04-asset-vuln-context.png" width="700">
</div>

<p align="center"><em>Figure 5. Vulnerability and asset context influencing prioritization.</em></p>

---

## 🤖 Step 5 — Investigation Agent

<div align="center">
  <img src="images/05-investigation-agent-output.png" width="700">
</div>

<p align="center"><em>Figure 6. Investigation agent recommending response actions based on confidence.</em></p>

---

## 🔎 Step 6 — Threat Hunting Findings

<div align="center">
  <img src="images/06-threat-hunting-findings.png" width="700">
</div>

<p align="center"><em>Figure 7. Threat hunting layer identifying high-risk patterns across alerts.</em></p>

---

## 🧪 Example Investigation Output

INVESTIGATION AGENT OUTPUT:  
Final Severity: high  
Final Confidence: 1.00  
Stop Reason: confidence_threshold_met  

Decisions:  
- response_recommended  

Recommended Next Steps:  
- usermod -L admin  
- iptables -A INPUT -s 192.168.1.50 -j DROP  
- volatility -f memory.dump --profile=Win10x64 pslist  
- prioritize_patch_and_isolation  

---

## 💡 What This Project Demonstrates

- SOC alert triage workflows  
- MITRE ATT&CK mapping logic  
- hybrid detection scoring  
- SOAR automation design  
- AI-assisted analysis  
- enrichment-driven investigation  
- vulnerability-aware prioritization  
- asset-aware decision support  
- agentic investigation workflows  

---

## 💼 SOC Relevance

This system simulates:

- SIEM-style alert analysis  
- ATT&CK classification  
- contextual enrichment  
- investigation workflows  
- response decision support  

It demonstrates how alerts can move from detection to actionable decisions.

---

## 🧠 Key Engineering Insights

If the correct ATT&CK technique is not retrieved, no amount of scoring can fix it.  

Detection accuracy alone is not enough — context determines operational value.  

---

## ⚙️ How to Run

Clone the repository:

git clone https://github.com/YOUR_USERNAME/Agentic-SOC-Investigation-Engine.git  
cd Agentic-SOC-Investigation-Engine  

Create a virtual environment:

python3 -m venv .venv  
source .venv/bin/activate  

Install dependencies:

pip install -r requirements.txt  

Run the platform:

python run.py  

---

## 📁 Suggested Repo Contents

- app/  
- modules/  
- pipeline/  
- playbooks/  
- data/alerts.json  
- data/assets.json  
- data/vulnerabilities.json  
- run.py  
- requirements.txt  

---

## 🚧 Future Improvements

- SIEM API integration  
- EDR/XDR ingestion  
- streaming pipeline  
- threat intelligence APIs  
- analyst feedback loop  
- multi-agent collaboration  

---

<div align="center">

## 👤 Shannon Smith  

Cybersecurity | SOC Operations • Detection Engineering • Incident Response • AI-Assisted Security  

</div>
