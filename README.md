<div align="center">

# 🛡️ Agentic SOC Investigation Engine  
### ATT&CK Mapping • AI-Assisted Analysis • SOAR • Stateful Investigation

![Category](https://img.shields.io/badge/Category-SOC%20Engineering-red?style=for-the-badge)
![Focus](https://img.shields.io/badge/Focus-Incident%20Response%20%7C%20ATT%26CK%20Mapping-blue?style=for-the-badge)
![Tech](https://img.shields.io/badge/Tech-Automation%20%2B%20Detection%20Engineering-black?style=for-the-badge)

</div>

<div align="center">
  <img src="images/05-investigation-agent-output.png" width="700">
</div>

<p align="center"><em>Figure 1. Investigation output showing response recommendations after contextual analysis and iterative investigation.</em></p>

---

## 🧠 Scenario

Modern Security Operations Centers (SOCs) face a fundamental problem:

- alerts are noisy and fragmented  
- context is spread across multiple systems  
- prioritization is inconsistent  
- analysts must manually correlate signals  

Detection alone is not enough.

This project simulates how a SOC can move beyond alert triage into **structured investigation and decision-making**, combining:

- MITRE ATT&CK mapping  
- contextual enrichment  
- automated playbooks  
- iterative investigation  

---

## 🎯 Objective

The goal of this project was to design a **production-style SOC investigation pipeline** that transforms raw alerts into actionable, context-aware response decisions.

Instead of treating alerts as isolated events, the system demonstrates how SOC workflows:

- align detections to ATT&CK techniques  
- enrich alerts with environmental context  
- iteratively build understanding  
- generate response recommendations  

---

## 🧠 SOC Investigation Workflow

| Stage | Description |
|------|------------|
| 🟦 Raw Security Alert | Alert ingestion from SIEM (Splunk-style input) |
| 🟨 Triage + ATT&CK Mapping | Classification and behavioral alignment |
| 🟪 SOAR Playbook Selection | Response logic selected based on behavior |
| 🧠 AI-Assisted Analysis | Explanation of what is happening and why |
| 🧬 Context Enrichment | IOC, vulnerability, and asset data added |
| 🔁 Investigation | Iterative analysis and correlation |
| 🚨 Response Recommendation | Final actions based on confidence and risk |

<div align="center">

🔍 **From Detection → Context → Decision**

</div>

---

## ⚙️ 🔬 Inside the System (Technical Pipeline)

<div align="center">

### 🧩 From Detection to Decision — Step by Step

</div>

```text
🟦 Detection
   ↓
🟨 Triage Scoring
   ↓
🧠 ATT&CK Candidate Retrieval (TF-IDF)
   ↓
🔎 Semantic Reranking (Embeddings)
   ↓
⚖️ Hybrid ATT&CK Scoring
   ↓
🟪 SOAR Playbook Selection
   ↓
🤖 AI Analyst Explanation
   ↓
🧬 IOC Enrichment
   ↓
⚠️ Vulnerability Context
   ↓
🏢 Asset Criticality Context
   ↓
🔁 Stateful Investigation Loop
   ↓
🚨 Response Recommendation
```

---

### 🧠 Key Idea

This is a **layered decision pipeline**:

> Each stage reduces uncertainty and increases confidence until a response can be recommended.

---

## 🔍 ATT&CK Mapping Engine

This system uses a **hybrid ATT&CK mapping approach** rather than simple keyword matching.

- TF-IDF retrieves candidate techniques  
- embeddings improve semantic understanding  
- rule-based scoring reinforces known behaviors  
- contextual scoring refines results  
- confidence ranking determines final output  

---

## 🧠 Why This Mapping Works

Mapping alerts to ATT&CK is difficult because:

- alerts are incomplete  
- behaviors overlap  
- keyword matching is unreliable  

### Design Approach

1. Retrieval ensures correct candidates  
2. Semantic matching captures meaning  
3. Behavioral rules improve precision  
4. Context refines results  
5. Confidence ranks outcomes  

---

### 🎯 Key Insight

> Retrieval determines what is possible — scoring determines what is likely.

---

### 🧪 Validation

- brute force → T1110  
- web shell → T1505.003  
- payload transfer → T1105  

Results:
- Top-1 accuracy ≈ 0.80  
- Top-3 accuracy ≈ 0.90  

---

## 🧠 Why This Matters in a SOC

### 🔍 Alerts Are Not Isolated
The system correlates:
- IOCs  
- vulnerabilities  
- assets  

---

### 🔄 Investigation Is Iterative
Each step:
- gathers new data  
- updates confidence  
- refines decisions  

---

### ⚖️ Context Drives Priority
The system considers:
- asset value  
- exploitability  
- behavioral risk  

---

### 🧠 Decisions Are Explainable
- investigation steps are logged  
- reasoning is visible  
- actions are justified  

---

### 🚀 From Detection → Decision

This system moves beyond detection into:

- investigation  
- correlation  
- response recommendation  

---

## ⚙️ Core Capabilities

- ATT&CK mapping (hybrid scoring)  
- SOAR playbooks  
- AI-assisted analysis  
- IOC enrichment  
- vulnerability-aware prioritization  
- asset-aware decisioning  
- threat hunting insights  
- stateful investigation workflow  

---

## ⚙️ Step 1 — Project Structure

<div align="center">
  <img src="images/01-project-structure.png" width="600">
</div>

<p align="center"><em>Figure 2. Modular structure separating mapping, enrichment, and agent logic.</em></p>

---

## 🔍 Step 2 — ATT&CK Mapping Output

<div align="center">
  <img src="images/02-attack-mapping-output.png" width="700">
</div>

<p align="center"><em>Figure 3. Ranked ATT&CK techniques with confidence scoring.</em></p>

---

## ⚙️ Step 3 — SOAR + AI Analyst Layer

<div align="center">
  <img src="images/03-soar-ai-analyst-output.png" width="700">
</div>

<p align="center"><em>Figure 4. Playbook execution and analyst explanation.</em></p>

---

## 🧬 Step 4 — Vulnerability + Asset Context

<div align="center">
  <img src="images/04-asset-vuln-context.png" width="700">
</div>

<p align="center"><em>Figure 5. Context enrichment influencing prioritization.</em></p>

---

## 🤖 Step 5 — Investigation Agent

<div align="center">
  <img src="images/05-investigation-agent-output.png" width="700">
</div>

<p align="center"><em>Figure 6. Agent recommending response actions after confidence threshold is reached.</em></p>

---

## 🔎 Step 6 — Threat Hunting Findings

<div align="center">
  <img src="images/06-threat-hunting-findings.png" width="700">
</div>

<p align="center"><em>Figure 7. Threat hunting layer identifying broader attack patterns.</em></p>

---

## 🧪 Example Output

```text
INVESTIGATION AGENT OUTPUT:
Final Severity: high
Final Confidence: 1.00

Decisions:
- response_recommended

Recommended Next Steps:
- usermod -L admin
- iptables -A INPUT ...
- volatility analysis
```

---

## 💡 What This Project Demonstrates

- SOC alert triage  
- ATT&CK-based detection engineering  
- contextual investigation workflows  
- automation and decision support  
- real-world SOC reasoning patterns  

---

## ⚙️ How to Run

git clone https://github.com/YOUR_USERNAME/Agentic-SOC-Investigation-Engine.git  
cd Agentic-SOC-Investigation-Engine  

python3 -m venv .venv  
source .venv/bin/activate  

pip install -r requirements.txt  

python run.py  

---

## 🚧 Future Improvements

- SIEM API integration  
- EDR/XDR telemetry  
- streaming pipelines  
- threat intelligence feeds  

---

<div align="center">

## 👤 Shannon Smith  

Cybersecurity | SOC Operations • Detection Engineering • Incident Response  

U.S. Navy Veteran | Virginia Tech — M.S. Information Technology  

🛡️ Investigating and correlating security events across systems  
🔎 Designing ATT&CK-aligned detection workflows  
⚙️ Building automation to improve SOC efficiency  

</div>
