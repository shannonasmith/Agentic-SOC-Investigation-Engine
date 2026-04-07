<div align="center">

# 🛡️ Agentic SOC Investigation Engine  
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

This project simulates how a **modern Security Operations Center (SOC)** processes alerts from detection through response using:

- MITRE ATT&CK mapping  
- SOAR playbooks  
- AI-assisted analyst reasoning  
- contextual enrichment  
- vulnerability-aware prioritization  
- asset criticality awareness  
- a stateful investigation agent  

Rather than stopping at classification, the system continues through investigation and decision-making to produce actionable response recommendations.

---

## 🎯 Objective

The goal of this project was to design a **production-style SOC investigation pipeline** that transforms:

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

This reflects how real-world SOC workflows move from raw telemetry to operational decisions.

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

This system uses a **hybrid ATT&CK mapping approach** rather than simple keyword matching.

### Mapping pipeline:
- TF-IDF retrieval generates initial technique candidates  
- embedding similarity improves semantic understanding  
- rule-based scoring reinforces known behavioral patterns  
- field-aware scoring incorporates structured alert data  
- tactic-aware scoring improves contextual alignment  
- confidence scoring ranks likely techniques  

This allows the system to produce mappings that are both accurate and explainable.

---

## 🧠 How ATT&CK Mapping Works (and Why It’s Correct)

Mapping alerts to MITRE ATT&CK techniques is not a simple classification problem.

In real SOC environments:

- alerts are noisy and incomplete  
- multiple techniques share similar characteristics  
- keyword matching often leads to incorrect classifications  

### 🔍 Design Approach

The system uses a **multi-stage hybrid pipeline**:

1. **TF-IDF Retrieval (Recall Layer)**  
   Retrieves a broad set of candidate techniques to ensure the correct technique is included  

2. **Embedding-Based Reranking (Semantic Layer)**  
   Uses sentence-transformers to match meaning, not just keywords  

3. **Rule-Based Scoring (Behavior Layer)**  
   Applies domain logic for known attack patterns  
   - brute force → T1110  
   - encoded PowerShell → T1059.001  

4. **Field-Aware + Tactic-Aware Scoring (Context Layer)**  
   Uses alert structure and tactic alignment to refine results  

5. **Confidence-Based Ranking**  
   Combines all signals into a final ranking of techniques  

---

### ✅ Why This Works

> Retrieval determines what is possible — scoring determines what is likely.

If the correct technique is not retrieved early, no amount of scoring can fix it.

This system prioritizes **recall first**, then precision.

---

### 🧪 Validation Approach

The system was validated using known attack scenarios:

- web shell → T1505.003  
- brute force → T1110  
- payload transfer → T1105  

Evaluation included:

- Top-1 accuracy ≈ 0.80  
- Top-3 accuracy ≈ 0.90  
- false positive reduction testing  
- ensuring benign traffic was not misclassified  

---

### ⚖️ Tradeoffs

- TF-IDF alone lacks semantic understanding  
- embeddings alone can over-generalize  
- rule-based logic improves precision but must be scoped carefully  

The hybrid approach balances:

- recall  
- semantic understanding  
- behavioral accuracy  

---

### 🎯 Key Takeaway

The system combines:

- retrieval  
- semantic similarity  
- domain knowledge  

to produce ATT&CK mappings that are:

- more accurate  
- more explainable  
- more aligned with real SOC workflows  

---

## ⚙️ Core Capabilities

### 1. MITRE ATT&CK Mapping
- hybrid retrieval + scoring engine  
- ranked techniques with confidence scores  
- ATT&CK Navigator export  

### 2. SOAR Playbooks
Supports response workflows for:
- credential access  
- lateral movement  
- defense evasion  
- reconnaissance  
- collection  
- persistence  

### 3. AI-Assisted Analyst Output
- explains why alerts matter  
- summarizes risk  
- provides investigation guidance  

### 4. IOC Enrichment
- internal vs external classification  
- threat indicator tagging  
- influence on decision-making  

### 5. Vulnerability-Aware Decisioning
- CVE-based context  
- risk-aware prioritization  
- integrates vulnerability exposure into investigation  

### 6. Asset Criticality Awareness
- identifies high-value systems  
- adjusts prioritization based on impact  
- supports business-aware decision logic  

### 7. Threat Hunting Layer
- identifies high-confidence detections  
- surfaces high-risk techniques  
- detects vulnerability exposure across alerts  

### 8. Stateful Investigation Agent
- maintains case state  
- selects enrichment actions dynamically  
- updates confidence after each step  
- determines when to stop  
- recommends response actions  
- logs reasoning for explainability  

---

## 🤖 Why It’s Agentic

The system behaves as an agent because it:

- maintains state  
- selects actions  
- executes enrichment steps  
- updates confidence based on evidence  
- determines when to stop  
- produces response recommendations  

This creates a structured, explainable investigation workflow rather than a static pipeline.

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

- SOC alert triage and analysis  
- ATT&CK mapping methodology  
- hybrid detection scoring  
- SOAR automation design  
- AI-assisted investigation  
- enrichment-driven workflows  
- vulnerability-aware prioritization  
- asset-aware decision support  
- agentic investigation architecture  

---

## 💼 SOC Relevance

This system simulates:

- SIEM-style alert analysis  
- ATT&CK classification  
- contextual investigation workflows  
- response decision support  

It demonstrates how alerts move from detection to actionable security decisions.

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

Cybersecurity | SOC Operations • Detection Engineering • Incident Response  

U.S. Navy Veteran | Virginia Tech — M.S. Information Technology  

🛡️ Investigating and correlating security events across systems and environments  
🔎 Designing explainable detection and ATT&CK-aligned analysis workflows  
⚙️ Building automation and agent-driven approaches to improve SOC efficiency  

</div>
