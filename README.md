<div align="center">

# 🛡️ CVEDB  

**Comprehensive CVE Analysis & Visualization Platform**  

[![Build](https://img.shields.io/github/actions/workflow/status/cvedb/cvedb.github.io/deploy.yml?label=Build%20%26%20Deploy&logo=github)](https://github.com/cvedb/cvedb.github.io/actions/workflows/deploy.yml)
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Updates](https://img.shields.io/badge/Data%20Refresh-6h-brightgreen)

---

### 🔗 Explore
[🌍 Website](https://cvedb.github.io) • [📌 Issues](https://github.com/cvedb/cvedb.github.io/issues) • [💬 Discussions](https://github.com/cvedb/cvedb.github.io/discussions)

---

**Making vulnerability data accessible, understandable & actionable.**

</div>

---

## 🌟 Features

<div align="center">

| 📊 CVE Analysis | 📈 Visualizations | ⚡ Automation |
|-----------------|------------------|--------------|
| Multi-year data (1999 → now)<br/>CVSS v2/v3 scoring<br/>CWE/CPE/CNA breakdowns | Yearly trends<br/>Heatmaps<br/>Severity distributions<br/>Vendor insights | 6-hour CI/CD builds<br/>Always fresh NVD sync<br/>GitHub Pages auto-deploy<br/>Quiet Mode logging |

</div>

---

## 🏗️ Architecture Overview  

<div align="center">

```mermaid
flowchart LR
    A[📥 Fetch Data<br/>NVD + CVE v5] --> B[🔧 Process Formats]
    B --> C[📊 Run Analysis<br/>CVSS • CWE • CPE • CNA]
    C --> D[🎨 Generate Visualizations]
    D --> E[🌐 Build Static Website]
    E --> F[🚀 Deploy via GitHub Actions]
