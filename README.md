# Docker Security Scanner 🔒

An enterprise-grade Docker vulnerability scanner with **automatic remediation**, **validation**, **multi-container support**, and **CI/CD automation**.

---

## 🎯 Key Features

✅ **Scan Docker Images & Running Containers**  
✅ **Multi-Container Support (`--scan-running`)**  
✅ **Per-Container Drill-Down HTML Report**  
✅ **Auto-Generated Secure Dockerfile**  
✅ **Before vs After Validation (Proof of Fix)**  
✅ **CSV Export (Per Container / Severity)**  
✅ **CI/CD Automation via GitHub Actions**  
✅ **Auto Pull Request Creation with Fixes**  

---

## 🚀 Quick Start

### Prerequisites
- Python **3.8+**
- Docker **running**
- Trivy installed

### Installation
```bash
git clone https://github.com/sourav8908/docker-security-scanner.git
cd docker-security-scanner
pip install -r requirements.txt
Install Trivy
Mac

bash
Copy code
brew install trivy
Ubuntu

bash
Copy code
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy
📊 Usage
1️⃣ Scan a Docker Image
bash
Copy code
python main.py nginx:1.18
✔ Generates:

security_report.html

Dockerfile.fixed

2️⃣ Scan + Validate Fixes
bash
Copy code
python main.py nginx:1.18 --validate
✔ Builds fixed image
✔ Re-scans
✔ Shows Before vs After reduction

3️⃣ Scan ALL Running Containers (🔥 Feature)
bash
Copy code
python main.py --scan-running
✔ Scans every running container
✔ Generates one report
✔ UI lets you:

Select container

View vulnerabilities

Export CSV per container

🖥️ HTML Report Features
🔹 Overview Mode
Combined vulnerability counts

Severity charts

🔹 Per-Container Drill-Down
Dropdown to select container

Summary updates instantly

Table + pagination update

🔹 Export
📄 CSV export

Respects:

Selected container

Selected severity

🧪 Validation Example
markdown
Copy code
📊 BEFORE vs AFTER COMPARISON
=========================================
CRITICAL   42 → 14   (66% ↓)
HIGH       149 → 51  (65% ↓)
MEDIUM     193 → 105 (45% ↓)
LOW        31 → 121  (increase due to OS upgrade)
✔ Shows real-world tradeoffs
✔ Honest security reporting (interview-ready)

🤖 CI/CD Integration — GitHub Actions
The project ships with a ready-to-use workflow.

What It Does
Scans Dockerfiles on push / PR

Runs daily scheduled scans

Generates fixes

Uploads reports

Creates Pull Requests automatically

📁 Project Structure
arduino
Copy code
docker-security-scanner/
├── scanner/
│   ├── image_scanner.py
│   ├── vulnerability_analyzer.py
│   ├── dockerfile_fixer.py
│   ├── image_builder.py
│   └── report_generator.py
├── .github/workflows/
│   └── docker-security-scan.yml
├── config/config.yaml
├── main.py
├── requirements.txt
└── README.md
🎯 Real-World Use Cases
DevSecOps pipelines

Production container audits

Security compliance reporting

Vulnerability remediation proof

Interview / portfolio showcase

👤 Author
Sourav Mohanty
GitHub: https://github.com/sourav8908